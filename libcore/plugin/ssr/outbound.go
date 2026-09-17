package ssr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/core"
	EN "github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/net"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/obfs"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/protocol"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/shadowstream"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/socks5"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.SSROutboundOptions](registry, pluginoption.TypeSSR, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	cipher     core.Cipher
	obfs       obfs.Obfs
	protocol   protocol.Protocol
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options pluginoption.SSROutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	h := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(pluginoption.TypeSSR, tag, options.Network, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
	}
	// SSR protocol compatibility: strip "_compatible" suffix and normalize defaults
	cipherName := strings.TrimSuffix(options.Method, "_compatible")
	if cipherName == "none" || cipherName == "plain" || cipherName == "" {
		cipherName = "dummy"
	}
	coreCipher, err := core.PickCipher(cipherName, nil, options.Password)
	if err != nil {
		return nil, fmt.Errorf("ssr cipher initialize error: %w", err)
	}
	h.cipher = coreCipher
	var (
		ivSize int
		key    []byte
	)
	if cipherName == "dummy" {
		ivSize = 0
		key = core.Kdf(options.Password, 16)
	} else {
		streamCipher, ok := h.cipher.(*core.StreamCipher)
		if !ok {
			return nil, fmt.Errorf("%s is not none or a supported stream cipher in ssr", cipherName)
		}
		ivSize = streamCipher.IVSize()
		key = streamCipher.Key
	}

	obfsName := strings.TrimSuffix(options.Obfs, "_compatible")
	if obfsName == "" {
		obfsName = "plain"
	}
	ssrObfs, obfsOverhead, err := obfs.PickObfs(obfsName, &obfs.Base{
		Host:   options.Server,
		Port:   int(options.ServerPort),
		Key:    key,
		IVSize: ivSize,
		Param:  options.ObfsParam,
	})
	if err != nil {
		return nil, E.Cause(err, "initialize obfs")
	}

	protocolName := strings.TrimSuffix(options.Protocol, "_compatible")
	if protocolName == "" {
		protocolName = "origin"
	}
	ssrProtocol, err := protocol.PickProtocol(protocolName, &protocol.Base{
		Key:      key,
		Overhead: obfsOverhead,
		Param:    options.ProtocolParam,
	})
	if err != nil {
		return nil, E.Cause(err, "initialize protocol")
	}
	h.obfs = ssrObfs
	h.protocol = ssrProtocol
	return h, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := h.dialer.DialContext(ctx, network, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn = h.cipher.StreamConn(h.obfs.StreamConn(conn))
		var writeIv []byte
		switch c := conn.(type) {
		case *shadowstream.Conn:
			writeIv, err = c.ObtainWriteIV()
			if err != nil {
				conn.Close()
				return nil, err
			}
		}
		conn = h.protocol.StreamConn(conn, writeIv)
		err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
		if err != nil {
			conn.Close()
			return nil, E.Cause(err, "write request")
		}
		return conn, nil
	case N.NetworkUDP:
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	outConn, err := h.dialer.DialContext(ctx, N.NetworkUDP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	packetConn := h.cipher.PacketConn(EN.NewEnhancePacketConn(bufio.NewUnbindPacketConn(outConn)))
	packetConn = h.protocol.PacketConn(packetConn)
	return &ssPacketConn{packetConn, outConn.RemoteAddr()}, nil
}

type ssPacketConn struct {
	EN.EnhancePacketConn
	rAddr net.Addr
}

func (spc *ssPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return 0, err
	}
	_, err = spc.EnhancePacketConn.WriteTo(packet[3:], spc.rAddr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (spc *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := spc.EnhancePacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}

	addr := socks5.SplitAddr(b[:n])
	if addr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	copy(b, b[len(addr):])
	return n - len(addr), udpAddr, e
}

func (spc *ssPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, _, err = spc.EnhancePacketConn.WaitReadFrom()
	if err != nil {
		return nil, nil, nil, err
	}

	_addr := socks5.SplitAddr(data)
	if _addr == nil {
		if put != nil {
			put()
		}
		return nil, nil, nil, errors.New("parse addr error")
	}

	udpAddr := _addr.UDPAddr()
	if udpAddr == nil {
		if put != nil {
			put()
		}
		return nil, nil, nil, errors.New("parse addr error")
	}
	addr = udpAddr

	data = data[len(_addr):]
	return
}

package ssr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"libcore/plugin/pluginoption"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	EN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowstream"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/ssr/obfs"
	"github.com/metacubex/mihomo/transport/ssr/protocol"
)

var bufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 2048)
	},
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.SSROutboundOptions](registry, pluginoption.TypeSSR, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	udpOverTCP bool
	options    pluginoption.SSROutboundOptions
	cipher     core.Cipher
	key        []byte
	ivSize     int
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options pluginoption.SSROutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, M.IsDomainName(options.Server))
	if err != nil {
		return nil, err
	}

	cipherName := options.Method
	if cipherName == "none" {
		cipherName = "dummy"
	}
	coreCipher, err := core.PickCipher(cipherName, nil, options.Password)
	if err != nil {
		return nil, fmt.Errorf("ssr cipher initialize error: %w", err)
	}

	h := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(pluginoption.TypeSSR, tag, options.Network, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		udpOverTCP: options.UDPOverTCP,
		options:    options,
		cipher:     coreCipher,
	}

	if cipherName == "dummy" {
		h.ivSize = 0
		h.key = core.Kdf(options.Password, 16)
	} else {
		streamCipher, ok := coreCipher.(*core.StreamCipher)
		if !ok {
			return nil, fmt.Errorf("%s is not supported in ssr", cipherName)
		}
		h.ivSize = streamCipher.IVSize()
		h.key = streamCipher.Key
	}

	return h, nil
}

func (h *Outbound) createObfsAndProtocol() (obfs.Obfs, protocol.Protocol, error) {
	ssrObfs, obfsOverhead, err := obfs.PickObfs(h.options.Obfs, &obfs.Base{
		Host:   h.options.Server,
		Port:   int(h.options.ServerPort),
		Key:    h.key,
		IVSize: h.ivSize,
		Param:  h.options.ObfsParam,
	})
	if err != nil {
		return nil, nil, E.Cause(err, "initialize obfs")
	}
	ssrProtocol, err := protocol.PickProtocol(h.options.Protocol, &protocol.Base{
		Key:      h.key,
		Overhead: obfsOverhead,
		Param:    h.options.ProtocolParam,
	})
	if err != nil {
		return nil, nil, E.Cause(err, "initialize protocol")
	}
	return ssrObfs, ssrProtocol, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	if network == N.NetworkUDP {
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	}

	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	conn, err := h.dialer.DialContext(ctx, network, h.serverAddr)
	if err != nil {
		return nil, err
	}

	ssrObfs, ssrProtocol, err := h.createObfsAndProtocol()
	if err != nil {
		conn.Close()
		return nil, err
	}

	conn = h.cipher.StreamConn(ssrObfs.StreamConn(conn))
	var writeIv []byte
	if sc, ok := conn.(*shadowstream.Conn); ok {
		if writeIv, err = sc.ObtainWriteIV(); err != nil {
			conn.Close()
			return nil, err
		}
	}
	conn = ssrProtocol.StreamConn(conn, writeIv)

	if err = M.SocksaddrSerializer.WriteAddrPort(conn, destination); err != nil {
		conn.Close()
		return nil, E.Cause(err, "write request")
	}
	return conn, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)

	ssrObfs, ssrProtocol, err := h.createObfsAndProtocol()
	if err != nil {
		return nil, err
	}

	if h.udpOverTCP {
		conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn = h.cipher.StreamConn(ssrObfs.StreamConn(conn))
		var writeIv []byte
		if sc, ok := conn.(*shadowstream.Conn); ok {
			writeIv, _ = sc.ObtainWriteIV()
		}
		conn = ssrProtocol.StreamConn(conn, writeIv)
		return &ssPacketConn{EN.NewEnhancePacketConn(bufio.NewUnbindPacketConn(conn)), h.serverAddr.UDPAddr()}, nil
	}

	outConn, err := h.dialer.DialContext(ctx, N.NetworkUDP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	packetConn := h.cipher.PacketConn(EN.NewEnhancePacketConn(bufio.NewUnbindPacketConn(outConn)))
	packetConn = ssrProtocol.PacketConn(packetConn)
	return &ssPacketConn{packetConn, outConn.RemoteAddr()}, nil
}

type ssPacketConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (spc *ssPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	socksAddr := socks5.ParseAddrToSocksAddr(addr)
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	headerLen := 3 + len(socksAddr)
	if headerLen+len(b) > len(buf) {
		packet, err := socks5.EncodeUDPPacket(socksAddr, b)
		if err != nil {
			return 0, err
		}
		return spc.PacketConn.WriteTo(packet[3:], spc.rAddr)
	}
	buf[0], buf[1], buf[2] = 0, 0, 0
	copy(buf[3:], socksAddr)
	copy(buf[headerLen:], b)
	n, err = spc.PacketConn.WriteTo(buf[3:headerLen+len(b)], spc.rAddr)
	if err == nil {
		n = len(b)
	}
	return
}

func (spc *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := spc.PacketConn.ReadFrom(b)
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

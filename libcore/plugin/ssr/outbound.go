package ssr

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"net"

	"libcore/plugin/pluginoption"
	"libcore/plugin/ssr/internal/obfs"
	"libcore/plugin/ssr/internal/protocol"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.SSROutboundOptions](registry, pluginoption.TypeSSR, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	options    pluginoption.SSROutboundOptions
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options pluginoption.SSROutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(pluginoption.TypeSSR, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		options:    options,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.logger.InfoContext(ctx, "outbound connection to ", destination)
	conn, err := o.dialer.DialContext(ctx, N.NetworkTCP, o.serverAddr)
	if err != nil {
		return nil, err
	}

	var key []byte
	var ivSize int
	method := o.options.Method
	password := o.options.Password

	switch method {
	case "aes-128-cfb", "aes-128-ctr":
		key = kdf(password, 16)
		ivSize = 16
	case "aes-192-cfb", "aes-192-ctr":
		key = kdf(password, 24)
		ivSize = 16
	case "aes-256-cfb", "aes-256-ctr":
		key = kdf(password, 32)
		ivSize = 16
	case "rc4-md5":
		key = kdf(password, 16)
		ivSize = 16
	case "none", "":
		key = kdf(password, 16)
		ivSize = 0
	default:
		key = kdf(password, 16)
		ivSize = 16
	}

	// 1. Obfs
	obfsName := o.options.Obfs
	if obfsName == "" {
		obfsName = "plain"
	}
	obfsImpl, obfsOverhead, err := obfs.PickObfs(obfsName, &obfs.Base{
		Host:   o.serverAddr.Addr.String(),
		Port:   int(o.serverAddr.Port),
		Key:    key,
		IVSize: ivSize,
		Param:  o.options.ObfsParam,
	})
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	conn = obfsImpl.StreamConn(conn)

	// 2. Shadowsocks Cipher layer (Using standard Go crypto since we don't want external libs)
	var iv []byte
	if method != "none" && method != "" {
		iv = make([]byte, ivSize)
		if _, err := rand.Read(iv); err != nil {
			common.Close(conn)
			return nil, err
		}
		if _, err := conn.Write(iv); err != nil {
			common.Close(conn)
			return nil, err
		}

		var streamBlock cipher.Block
		streamBlock, err = aes.NewCipher(key)
		if err != nil {
			common.Close(conn)
			return nil, err
		}

		var encrypter, decrypter cipher.Stream
		switch {
		case method == "rc4-md5":
			h := md5.New()
			h.Write(key)
			h.Write(iv)
			rc4Key := h.Sum(nil)
			encrypter, _ = rc4.NewCipher(rc4Key)
			decrypter, _ = rc4.NewCipher(rc4Key)
		case method[len(method)-3:] == "cfb":
			encrypter = cipher.NewCFBEncrypter(streamBlock, iv)
			decrypter = cipher.NewCFBDecrypter(streamBlock, iv)
		case method[len(method)-3:] == "ctr":
			encrypter = cipher.NewCTR(streamBlock, iv)
			decrypter = cipher.NewCTR(streamBlock, iv)
		}

		if encrypter != nil {
			conn = &shadowConn{Conn: conn, enc: encrypter, dec: decrypter}
		}
	}

	// 3. Protocol
	protocolName := o.options.Protocol
	if protocolName == "" {
		protocolName = "origin"
	}
	protoImpl, err := protocol.PickProtocol(protocolName, &protocol.Base{
		Key:      key,
		Overhead: obfsOverhead,
		Param:    o.options.ProtocolParam,
	})
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	conn = protoImpl.StreamConn(conn, iv)

	// 4. Handshake (Send destination)
	if err := M.SocksaddrSerializer.WriteAddrPort(conn, destination); err != nil {
		common.Close(conn)
		return nil, err
	}

	return conn, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	packetConn, err := o.dialer.ListenPacket(ctx, o.serverAddr)
	if err != nil {
		return nil, err
	}

	// SSR UDP implementation usually skips shadowsocks stream cipher
	// and uses protocol-specific packet encapsulation.
	key := kdf(o.options.Password, 16)

	protocolName := o.options.Protocol
	if protocolName == "" {
		protocolName = "origin"
	}
	protoImpl, err := protocol.PickProtocol(protocolName, &protocol.Base{
		Key:   key,
		Param: o.options.ProtocolParam,
	})
	if err != nil {
		common.Close(packetConn)
		return nil, err
	}

	return bufio.NewBindPacketConn(protoImpl.PacketConn(packetConn), destination), nil
}

func (o *Outbound) InterfaceUpdated() {
}

func (o *Outbound) Close() error {
	return nil
}

func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

type shadowConn struct {
	net.Conn
	enc cipher.Stream
	dec cipher.Stream
}

func (c *shadowConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.dec.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (c *shadowConn) Write(b []byte) (int, error) {
	c.enc.XORKeyStream(b, b)
	return c.Conn.Write(b)
}

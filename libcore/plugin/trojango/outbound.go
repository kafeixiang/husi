package trojango

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.TrojanGoOutboundOptions](registry, pluginoption.TypeTrojanGo, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	key        [trojan.KeyLength]byte
	tlsConfig  tls.Config
	tlsDialer  tls.Dialer
	transport  adapter.V2RayClientTransport
	ssCipher   *SSCipher
	muxPool    *SessionPool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options pluginoption.TrojanGoOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	h := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(pluginoption.TypeTrojanGo, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		key:        trojan.Key(options.Password),
	}

	// Always ensure TLS is enabled for Trojan-Go unless explicitly overridden
	tlsOptions := options.TLS
	if tlsOptions == nil {
		tlsOptions = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: options.Server,
		}
	} else if !tlsOptions.Enabled && tlsOptions.ServerName == "" {
		tlsOptions.Enabled = true
		tlsOptions.ServerName = options.Server
	}

	h.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
		Context:       ctx,
		Logger:        logger,
		ServerAddress: options.Server,
		Options:       common.PtrValueOrDefault(tlsOptions),
	})
	if err != nil {
		return nil, err
	}
	h.tlsDialer = tls.NewDialer(outboundDialer, h.tlsConfig)

	// Transport layer (e.g. WebSocket)
	if options.Transport != nil && options.Transport.Type != "" {
		h.transport, err = v2ray.NewClientTransport(ctx, outboundDialer, h.serverAddr, common.PtrValueOrDefault(options.Transport), h.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}

	// Shadowsocks secondary encryption layer
	if options.Shadowsocks != nil && options.Shadowsocks.Enabled && options.Shadowsocks.Method != "" {
		h.ssCipher, err = NewSSCipher(options.Shadowsocks.Method, options.Shadowsocks.Password)
		if err != nil {
			return nil, E.Cause(err, "initialize shadowsocks cipher")
		}
	}

	// Trojan-Go smux multiplexing
	if options.Mux != nil && options.Mux.Enabled {
		h.muxPool = NewSessionPool(h, options.Mux.Concurrency, options.Mux.IdleTimeout)
	}

	return h, nil
}

func (h *Outbound) dialUnderlay(ctx context.Context) (net.Conn, error) {
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		return nil, err
	}
	if h.ssCipher != nil {
		conn = h.ssCipher.StreamConn(conn)
	}
	return conn, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	if h.muxPool != nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
			return h.muxPool.DialContext(ctx, destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
			return h.muxPool.ListenPacket(ctx, destination)
		default:
			return nil, E.Extend(N.ErrUnknownNetwork, network)
		}
	}

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		conn, err := h.dialUnderlay(ctx)
		if err != nil {
			return nil, err
		}
		return trojan.NewClientConn(conn, h.key, destination), nil
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		conn, err := h.dialUnderlay(ctx)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(trojan.NewClientPacketConn(conn, h.key), destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)

	if h.muxPool != nil {
		return h.muxPool.ListenPacket(ctx, destination)
	}

	conn, err := h.dialUnderlay(ctx)
	if err != nil {
		return nil, err
	}
	return bufio.NewBindPacketConn(trojan.NewClientPacketConn(conn, h.key), destination), nil
}

func (h *Outbound) MultiplexEnabled() bool {
	return h.muxPool != nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.muxPool != nil {
		h.muxPool.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	if transportKeeper, ok := h.transport.(adapter.IdleConnectionKeeper); ok {
		transportKeeper.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	if transportKeeper, ok := h.transport.(adapter.IdleConnectionKeeper); ok {
		transportKeeper.CloseIdleConnections()
	}
	if h.muxPool != nil {
		h.muxPool.Reset()
	}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if h.transport != nil {
		scope.Add(h.transport.Close)
	}
	if h.muxPool != nil {
		scope.Add(h.muxPool.Close)
	}
	return nil
}

package snell

import (
	"context"
	"net"

	"libcore/plugin/pluginoption"

	snellcore "github.com/reF1nd/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.SnellOutboundOptions](registry, pluginoption.TypeSnell, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	serverAddr      M.Socksaddr
	psk             []byte
	version         int
	reuse           bool
	pool            *snellcore.Pool
	client          *snellcore.Client
	obfs            *pluginoption.SnellObfsOptions
	multiplexDialer *mux.Client
	tlsDialer       tls.Dialer
	uotClient       *uot.Client
}


func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options pluginoption.SnellOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}

	var tlsDialer tls.Dialer
	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewClientWithOptions(tls.ClientOptions{
			Context:       ctx,
			Logger:        logger,
			ServerAddress: options.Server,
			Options:       common.PtrValueOrDefault(options.TLS),
		})
		if err != nil {
			return nil, err
		}
		tlsDialer = tls.NewDialer(outboundDialer, tlsConfig)
	}

	h := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(pluginoption.TypeSnell, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		psk:        []byte(options.PSK),
		version:    options.Version,
		reuse:      options.Reuse,
		tlsDialer:  tlsDialer,
		obfs:       options.Obfs,
	}

	h.client, err = snellcore.NewClient(h.psk, h.version)
	if err != nil {
		return nil, err
	}

	if h.reuse && h.version >= 4 {
		h.pool = snellcore.NewPool(func(ctx context.Context) (net.Conn, error) {
			conn, err := h.dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			return h.client.WrapStream(conn), nil
		})
	}


	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		h.uotClient = &uot.Client{
			Dialer:  h,
			Version: uotOptions.Version,
		}
	}

	if options.Multiplex != nil && options.Multiplex.Enabled {
		h.multiplexDialer, err = mux.NewClientWithOptions((*snellDialer)(h), logger, common.PtrValueOrDefault(options.Multiplex))
		if err != nil {
			return nil, err
		}
	}

	return h, nil
}

func (o *Outbound) Close() error {
	return common.Close(common.PtrOrNil(o.multiplexDialer), o.tlsDialer, o.pool)
}


func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.uotClient != nil && network == N.NetworkUDP {
		o.logger.InfoContext(ctx, "outbound UoT connection to ", destination)
		return o.uotClient.DialContext(ctx, network, destination)
	}
	if o.multiplexDialer != nil && network == N.NetworkTCP {
		return o.multiplexDialer.DialContext(ctx, network, destination)
	}
	return o.dialInternal(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if o.uotClient != nil {
		o.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return o.uotClient.ListenPacket(ctx, destination)
	}

	if o.multiplexDialer != nil {
		return o.multiplexDialer.ListenPacket(ctx, destination)
	}

	if o.version == 5 {
		conn, err := o.dialer.DialContext(ctx, N.NetworkUDP, o.serverAddr)
		if err != nil {
			return nil, err
		}
		// Snell v5 QUIC proxy establish
		return snellcore.NewQUICProxyPacketConn(conn, o.psk, destination, nil)
	}

	conn, err := o.dialInternal(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}
	return bufio.NewBindPacketConn(snellcore.NewClientPacketConn(conn), destination), nil
}

func (o *Outbound) InterfaceUpdated() {
	if o.multiplexDialer != nil {
		o.multiplexDialer.Reset()
	}
	common.Close(o.pool)
}

func (o *Outbound) dialInternal(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination
	o.logger.InfoContext(ctx, "outbound connection to ", destination)

	if network == N.NetworkUDP && o.version == 5 {
		conn, err := o.dialer.DialContext(ctx, N.NetworkUDP, o.serverAddr)
		if err != nil {
			return nil, err
		}
		packetConn, err := snellcore.NewQUICProxyPacketConn(conn, o.psk, destination, nil)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	}

	if network == N.NetworkTCP && o.pool != nil {
		return o.client.DialContextWithPool(ctx, o.pool, destination)
	}

	conn, err := o.dialRaw(ctx)
	if err != nil {
		return nil, err
	}

	if network == N.NetworkUDP {
		return o.client.DialUDP(ctx, conn)
	}

	return o.client.DialContext(ctx, conn, destination)
}


func (o *Outbound) dialRaw(ctx context.Context) (net.Conn, error) {
	if o.version == 5 {
		return o.dialer.DialContext(ctx, N.NetworkUDP, o.serverAddr)
	}
	var conn net.Conn
	var err error
	if o.tlsDialer != nil {
		conn, err = o.tlsDialer.DialTLSContext(ctx, o.serverAddr)
	} else {
		conn, err = o.dialer.DialContext(ctx, N.NetworkTCP, o.serverAddr)
	}
	if err != nil {
		return nil, err
	}

	if o.obfs != nil {
		conn, err = NewObfsConn(conn, o.obfs.Type, o.obfs.Host)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

type snellDialer Outbound

func (d *snellDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (*Outbound)(d).dialInternal(ctx, network, destination)
}

func (d *snellDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (*Outbound)(d).ListenPacket(ctx, destination)
}

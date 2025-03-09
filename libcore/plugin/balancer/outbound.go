package balancer

import (
	"context"
	"math/rand/v2"
	"net"
	"slices"

	"libcore/plugin/pluginoption"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.BalancerOutboundOptions](registry, pluginoption.TypeBalancer, NewBalancer)
}

var (
	_ adapter.OutboundGroup             = (*Balancer)(nil)
	_ adapter.ConnectionHandlerEx       = (*Balancer)(nil)
	_ adapter.PacketConnectionHandlerEx = (*Balancer)(nil)
)

type Balancer struct {
	outbound.Adapter
	ctx        context.Context
	connection adapter.ConnectionManager
	outbounds  []adapter.Outbound
	tags       []string
	outbound   adapter.OutboundManager
}

func NewBalancer(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options pluginoption.BalancerOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds) == 0 {
		return nil, E.New("missing tags")
	}
	return &Balancer{
		Adapter:    outbound.NewAdapter(pluginoption.TypeBalancer, tag, nil, options.Outbounds),
		ctx:        ctx,
		connection: service.FromContext[adapter.ConnectionManager](ctx),
		outbounds:  make([]adapter.Outbound, len(options.Outbounds)),
		tags:       options.Outbounds,
		outbound:   service.FromContext[adapter.OutboundManager](ctx),
	}, nil
}

func (b *Balancer) Start() error {
	for i, tag := range b.tags {
		detour, loaded := b.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound, ", i, " not found: ", tag)
		}
		b.outbounds[i] = detour
	}

	return nil
}

func (b *Balancer) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (b *Balancer) Now() string {
	// Random
	return b.Tag()
}

func (b *Balancer) All() []string {
	return slices.Clone(b.tags)
}

func (b *Balancer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return b.detour().DialContext(ctx, network, destination)
}

func (b *Balancer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return b.detour().ListenPacket(ctx, destination)
}

func (b *Balancer) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	detour := b.detour()
	if outboundHandler, isHandler := detour.(adapter.ConnectionHandlerEx); isHandler {
		outboundHandler.NewConnectionEx(ctx, conn, metadata, onClose)
	} else {
		b.connection.NewConnection(ctx, detour, conn, metadata, onClose)
	}
}

func (b *Balancer) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	detour := b.detour()
	if outboundHandler, isHandler := detour.(adapter.PacketConnectionHandlerEx); isHandler {
		outboundHandler.NewPacketConnectionEx(ctx, conn, metadata, onClose)
	} else {
		b.connection.NewPacketConnection(ctx, detour, conn, metadata, onClose)
	}
}

func (b *Balancer) detour() adapter.Outbound {
	return b.outbounds[rand.IntN(len(b.outbounds))]
}

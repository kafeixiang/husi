package mieru

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/mieruproto"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
	"google.golang.org/protobuf/proto"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.MieruOutboundOptions](registry, pluginoption.TypeMieru, NewOutbound)
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	dialer N.Dialer
	logger log.ContextLogger
	client mieruclient.Client
	mu     sync.Mutex
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options pluginoption.MieruOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}

	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	config, err := buildMieruClientConfig(options, mieruDialer{dialer: outboundDialer}, dnsRouter)
	if err != nil {
		return nil, fmt.Errorf("failed to build mieru client config: %w", err)
	}
	c := mieruclient.NewClient()
	if err := c.Store(config); err != nil {
		return nil, fmt.Errorf("failed to store mieru client config: %w", err)
	}

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(pluginoption.TypeMieru, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		dialer:  outboundDialer,
		logger:  logger,
		client:  c,
	}, nil
}

func (o *Outbound) ensureClientIsRunning() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.client.IsRunning() {
		return nil
	}

	if err := o.client.Start(); err != nil {
		return fmt.Errorf("failed to start mieru client: %w", err)
	}
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination

	if err := o.ensureClientIsRunning(); err != nil {
		return nil, err
	}

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		d, err := socksAddrToNetAddrSpec(destination, "tcp")
		if err != nil {
			return nil, E.Cause(err, "failed to convert destination address")
		}
		return o.client.DialContext(ctx, d)
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		d, err := socksAddrToNetAddrSpec(destination, "udp")
		if err != nil {
			return nil, E.Cause(err, "failed to convert destination address")
		}
		streamConn, err := o.client.DialContext(ctx, d)
		if err != nil {
			return nil, err
		}
		udpWrapper := &threadSafePacketConn{
			PacketConn: mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(streamConn)),
		}
		return bufio.NewBindPacketConn(udpWrapper, destination), nil
	default:
		return nil, os.ErrInvalid
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination

	if err := o.ensureClientIsRunning(); err != nil {
		return nil, err
	}

	o.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	d, err := socksAddrToNetAddrSpec(destination, "udp")
	if err != nil {
		return nil, E.Cause(err, "failed to convert destination address")
	}
	streamConn, err := o.client.DialContext(ctx, d)
	if err != nil {
		return nil, err
	}
	return &threadSafePacketConn{
		PacketConn: mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(streamConn)),
	}, nil
}

func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client != nil && o.client.IsRunning() {
		_ = o.client.Stop()
	}
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client != nil && o.client.IsRunning() {
		return o.client.Stop()
	}
	return nil
}

// mieruDialer is an adapter to mieru dialer interface.
type mieruDialer struct {
	dialer N.Dialer
}

func (md mieruDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	addr := M.ParseSocksaddr(address)
	return md.dialer.DialContext(ctx, network, addr)
}

func (md mieruDialer) ListenPacket(ctx context.Context, network, laddr, raddr string) (net.PacketConn, error) {
	addr := M.ParseSocksaddr(raddr)
	return md.dialer.ListenPacket(ctx, addr)
}

var (
	_ mierucommon.Dialer       = (*mieruDialer)(nil)
	_ mierucommon.PacketDialer = (*mieruDialer)(nil)
)

type mieruResolver struct {
	dnsRouter adapter.DNSRouter
}

var _ mierucommon.DNSResolver = (*mieruResolver)(nil)

func (r mieruResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if r.dnsRouter != nil {
		addrs, err := r.dnsRouter.Lookup(ctx, host, adapter.DNSQueryOptions{})
		if err == nil && len(addrs) > 0 {
			netIPs := make([]net.IP, len(addrs))
			for i, addr := range addrs {
				netIPs[i] = addr.AsSlice()
			}
			return netIPs, nil
		}
	}
	if dnsRouter := service.FromContext[adapter.DNSRouter](ctx); dnsRouter != nil {
		addrs, err := dnsRouter.Lookup(ctx, host, adapter.DNSQueryOptions{})
		if err == nil && len(addrs) > 0 {
			netIPs := make([]net.IP, len(addrs))
			for i, addr := range addrs {
				netIPs[i] = addr.AsSlice()
			}
			return netIPs, nil
		}
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

type threadSafePacketConn struct {
	net.PacketConn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func (c *threadSafePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.PacketConn.ReadFrom(p)
}

func (c *threadSafePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

// socksAddrToNetAddrSpec converts a Socksaddr object to NetAddrSpec, and overrides the network.
func socksAddrToNetAddrSpec(sa M.Socksaddr, network string) (mierumodel.NetAddrSpec, error) {
	var nas mierumodel.NetAddrSpec
	if err := nas.From(sa); err != nil {
		return nas, err
	}
	nas.Net = network
	return nas, nil
}

func parseTrafficPattern(s string) (*mierupb.TrafficPattern, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		encoded, err := mieruproto.EncodeJSONBase64(s)
		if err != nil {
			return nil, fmt.Errorf("encode json traffic pattern: %w", err)
		}
		s = encoded
	}
	return mierutp.Decode(s)
}

func buildMieruClientConfig(options pluginoption.MieruOutboundOptions, dialer mieruDialer, dnsRouter adapter.DNSRouter) (*mieruclient.ClientConfig, error) {
	if err := validateMieruOptions(options); err != nil {
		return nil, fmt.Errorf("failed to validate mieru options: %w", err)
	}

	transport := strings.ToUpper(options.Transport)
	if transport == "" {
		transport = "TCP"
	}

	var transportProtocol *mierupb.TransportProtocol
	switch transport {
	case "TCP":
		transportProtocol = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		transportProtocol = mierupb.TransportProtocol_UDP.Enum()
	}
	server := &mierupb.ServerEndpoint{}
	boundPorts := make(map[int32]bool)
	if options.ServerPort != 0 {
		port := int32(options.ServerPort)
		server.PortBindings = append(server.PortBindings, &mierupb.PortBinding{
			Port:     proto.Int32(port),
			Protocol: transportProtocol,
		})
		boundPorts[port] = true
	}
	for _, pr := range options.ServerPortRanges {
		if portNum, err := strconv.Atoi(pr); err == nil {
			port := int32(portNum)
			if !boundPorts[port] {
				server.PortBindings = append(server.PortBindings, &mierupb.PortBinding{
					Port:     proto.Int32(port),
					Protocol: transportProtocol,
				})
				boundPorts[port] = true
			}
		} else {
			server.PortBindings = append(server.PortBindings, &mierupb.PortBinding{
				PortRange: proto.String(pr),
				Protocol:  transportProtocol,
			})
		}
	}
	if M.IsDomainName(options.Server) {
		server.DomainName = proto.String(options.Server)
	} else {
		server.IpAddress = proto.String(options.Server)
	}
	config := &mieruclient.ClientConfig{
		Profile: &mierupb.ClientProfile{
			ProfileName: proto.String("sing-box"),
			User: &mierupb.User{
				Name:     proto.String(options.UserName),
				Password: proto.String(options.Password),
			},
			Servers: []*mierupb.ServerEndpoint{server},
		},
		Dialer:       dialer,
		PacketDialer: dialer,
		Resolver:     mieruResolver{dnsRouter: dnsRouter},
		DNSConfig: &mierucommon.ClientDNSConfig{
			BypassDialerDNS: true,
		},
	}
	if options.MTU > 0 {
		config.Profile.Mtu = proto.Int32(int32(options.MTU))
	}
	if multiplexing, ok := mieruMuxValue(options.Multiplexing); ok {
		config.Profile.Multiplexing = &mierupb.MultiplexingConfig{
			Level: multiplexing.Enum(),
		}
	}
	if handshakeMode, ok := mieruHandshakeValue(options.HandshakeMode); ok {
		config.Profile.HandshakeMode = (&handshakeMode).Enum()
	}
	if options.TrafficPattern != "" {
		trafficPattern, err := parseTrafficPattern(options.TrafficPattern)
		if err != nil {
			return nil, fmt.Errorf("failed to parse traffic pattern: %w", err)
		}
		config.Profile.TrafficPattern = trafficPattern
	}
	return config, nil
}

func validateMieruOptions(options pluginoption.MieruOutboundOptions) error {
	if options.Server == "" {
		return fmt.Errorf("server is empty")
	}
	if options.ServerPort == 0 && len(options.ServerPortRanges) == 0 {
		return fmt.Errorf("either server_port or server_ports must be set")
	}
	for _, pr := range options.ServerPortRanges {
		begin, end, err := parsePortOrRange(pr)
		if err != nil {
			return fmt.Errorf("invalid server_ports format %q: %w", pr, err)
		}
		if begin < 1 || begin > 65535 {
			return fmt.Errorf("begin port must be between 1 and 65535")
		}
		if end < 1 || end > 65535 {
			return fmt.Errorf("end port must be between 1 and 65535")
		}
		if begin > end {
			return fmt.Errorf("begin port must be less than or equal to end port")
		}
	}
	transport := strings.ToUpper(options.Transport)
	if transport != "" && transport != "TCP" && transport != "UDP" {
		return fmt.Errorf("transport must be TCP or UDP")
	}
	if options.UserName == "" {
		return fmt.Errorf("username is empty")
	}
	if options.Password == "" {
		return fmt.Errorf("password is empty")
	}
	if options.Multiplexing != "" {
		if _, ok := mieruMuxValue(options.Multiplexing); !ok {
			return fmt.Errorf("invalid multiplexing level: %s", options.Multiplexing)
		}
	}
	if options.HandshakeMode != "" {
		if _, ok := mieruHandshakeValue(options.HandshakeMode); !ok {
			return fmt.Errorf("invalid handshake mode: %s", options.HandshakeMode)
		}
	}
	if options.TrafficPattern != "" {
		trafficPattern, err := parseTrafficPattern(options.TrafficPattern)
		if err != nil {
			return fmt.Errorf("failed to decode traffic pattern %q: %w", options.TrafficPattern, err)
		}
		if err := mierutp.Validate(trafficPattern); err != nil {
			return fmt.Errorf("invalid traffic pattern %q: %w", options.TrafficPattern, err)
		}
	}
	return nil
}

func mieruMuxValue(s string) (mierupb.MultiplexingLevel, bool) {
	if v, ok := mierupb.MultiplexingLevel_value[s]; ok {
		return mierupb.MultiplexingLevel(v), true
	}
	if v, ok := mierupb.MultiplexingLevel_value[strings.ToUpper(s)]; ok {
		return mierupb.MultiplexingLevel(v), true
	}
	if num, err := strconv.Atoi(s); err == nil {
		if _, ok := mierupb.MultiplexingLevel_name[int32(num)]; ok {
			return mierupb.MultiplexingLevel(num), true
		}
	}
	switch strings.ToUpper(s) {
	case "MIDDLE", "MEDIUM", "MULTIPLEXING_MEDIUM", "MULTIPLEXING_MIDDLE":
		return mierupb.MultiplexingLevel_MULTIPLEXING_MIDDLE, true
	case "LOW", "MULTIPLEXING_LOW":
		return mierupb.MultiplexingLevel_MULTIPLEXING_LOW, true
	case "HIGH", "MULTIPLEXING_HIGH":
		return mierupb.MultiplexingLevel_MULTIPLEXING_HIGH, true
	case "OFF", "MULTIPLEXING_OFF":
		return mierupb.MultiplexingLevel_MULTIPLEXING_OFF, true
	}
	return 0, false
}

func mieruHandshakeValue(s string) (mierupb.HandshakeMode, bool) {
	if v, ok := mierupb.HandshakeMode_value[s]; ok {
		return mierupb.HandshakeMode(v), true
	}
	if v, ok := mierupb.HandshakeMode_value[strings.ToUpper(s)]; ok {
		return mierupb.HandshakeMode(v), true
	}
	if num, err := strconv.Atoi(s); err == nil {
		if _, ok := mierupb.HandshakeMode_name[int32(num)]; ok {
			return mierupb.HandshakeMode(num), true
		}
	}
	switch strings.ToUpper(s) {
	case "DEFAULT", "HANDSHAKE_DEFAULT":
		return mierupb.HandshakeMode_HANDSHAKE_DEFAULT, true
	case "STANDARD", "HANDSHAKE_STANDARD", "1-RTT":
		return mierupb.HandshakeMode_HANDSHAKE_STANDARD, true
	case "NO_WAIT", "HANDSHAKE_NO_WAIT", "0-RTT":
		return mierupb.HandshakeMode_HANDSHAKE_NO_WAIT, true
	}
	return 0, false
}

func parsePortOrRange(s string) (int, int, error) {
	if p, err := strconv.Atoi(s); err == nil {
		return p, p, nil
	}
	var begin, end int
	_, err := fmt.Sscanf(s, "%d-%d", &begin, &end)
	return begin, end, err
}

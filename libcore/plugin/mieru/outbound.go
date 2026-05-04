package mieru

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"libcore/plugin/pluginoption"

	"github.com/enfein/mieru/v3/apis/constant"
	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[pluginoption.MieruOutboundOptions](registry, pluginoption.TypeMieru, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dialer  N.Dialer
	logger  log.ContextLogger
	mux     *protocol.Mux
	profile *mierupb.ClientProfile
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

	config, err := buildMieruClientConfig(tag, options, mieruDialer{dialer: outboundDialer})
	if err != nil {
		return nil, fmt.Errorf("failed to build mieru client config: %w", err)
	}

	mux, err := appctlcommon.NewClientMuxFromProfile(config.Profile, config.Dialer, config.PacketDialer, config.Resolver, config.DNSConfig)
	if err != nil {
		return nil, err
	}

	if !options.UserHint {
		user := config.Profile.GetUser()
		var hashedPassword []byte
		if user.GetHashedPassword() != "" {
			hashedPassword, err = hex.DecodeString(user.GetHashedPassword())
			if err != nil {
				return nil, fmt.Errorf("failed to decode hashed password: %w", err)
			}
		} else {
			hashedPassword = cipher.HashPassword([]byte(user.GetPassword()), []byte(user.GetName()))
		}
		mux.SetClientUserNamePassword("", hashedPassword)
	}

	logger.InfoContext(ctx, "mieru client is started")

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(pluginoption.TypeMieru, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		dialer:  outboundDialer,
		logger:  logger,
		mux:     mux,
		profile: config.Profile,
	}, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination

	var netAddrSpec mierumodel.NetAddrSpec
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound connection to ", destination)
		d, err := socksAddrToNetAddrSpec(destination, "tcp")
		if err != nil {
			return nil, E.Cause(err, "failed to convert destination address")
		}
		netAddrSpec = d
	case N.NetworkUDP:
		o.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		d, err := socksAddrToNetAddrSpec(destination, "udp")
		if err != nil {
			return nil, E.Cause(err, "failed to convert destination address")
		}
		netAddrSpec = d
	default:
		return nil, os.ErrInvalid
	}

	conn, err := o.mux.DialContext(ctx)
	if err != nil {
		return nil, err
	}

	var dialConn net.Conn
	if o.profile.GetHandshakeMode() == mierupb.HandshakeMode_HANDSHAKE_NO_WAIT {
		req := &mierumodel.Request{}
		if N.NetworkName(network) == N.NetworkTCP {
			req.Command = constant.Socks5ConnectCmd
		} else {
			req.Command = constant.Socks5UDPAssociateCmd
		}
		req.DstAddr = netAddrSpec.AddrSpec
		earlyConn := NewEarlyConn(conn)
		earlyConn.SetRequest(req)
		dialConn = earlyConn
	} else {
		_, err = PostDialHandshake(conn, netAddrSpec)
		if err != nil {
			conn.Close()
			return nil, err
		}
		dialConn = conn
	}

	if N.NetworkName(network) == N.NetworkUDP {
		return &streamer{
			PacketConn: mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(dialConn)),
			Remote:     destination,
		}, nil
	}
	return dialConn, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := o.DialContext(ctx, "udp", destination)
	if err != nil {
		return nil, err
	}
	return conn.(*streamer).PacketConn, nil
}

func (o *Outbound) Close() error {
	return common.Close(o.mux)
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

// streamer converts a net.PacketConn to a net.Conn.
type streamer struct {
	net.PacketConn
	Remote net.Addr
}

var _ net.Conn = (*streamer)(nil)

func (s *streamer) Read(b []byte) (n int, err error) {
	n, _, err = s.PacketConn.ReadFrom(b)
	return
}

func (s *streamer) Write(b []byte) (n int, err error) {
	return s.WriteTo(b, s.Remote)
}

func (s *streamer) RemoteAddr() net.Addr {
	return s.Remote
}

func (s *streamer) LocalAddr() net.Addr {
	return s.PacketConn.LocalAddr()
}

func (s *streamer) SetDeadline(t time.Time) error {
	return s.PacketConn.SetDeadline(t)
}

func (s *streamer) SetReadDeadline(t time.Time) error {
	return s.PacketConn.SetReadDeadline(t)
}

func (s *streamer) SetWriteDeadline(t time.Time) error {
	return s.PacketConn.SetWriteDeadline(t)
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

func buildMieruClientConfig(tag string, options pluginoption.MieruOutboundOptions, dialer mieruDialer) (*mieruclient.ClientConfig, error) {
	if err := validateMieruOptions(options); err != nil {
		return nil, fmt.Errorf("failed to validate mieru options: %w", err)
	}

	var transportProtocol *mierupb.TransportProtocol
	switch options.Transport {
	case "TCP":
		transportProtocol = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		transportProtocol = mierupb.TransportProtocol_UDP.Enum()
	}
	server := &mierupb.ServerEndpoint{}
	if options.ServerPort != 0 {
		server.PortBindings = append(server.PortBindings, &mierupb.PortBinding{
			Port:     proto.Int32(int32(options.ServerPort)),
			Protocol: transportProtocol,
		})
	}
	for _, pr := range options.ServerPortRanges {
		if strings.Contains(pr, "-") {
			server.PortBindings = append(server.PortBindings, &mierupb.PortBinding{
				PortRange: proto.String(pr),
				Protocol:  transportProtocol,
			})
		} else {
			port, err := strconv.Atoi(pr)
			if err == nil {
				server.PortBindings = append(server.PortBindings, &mierupb.PortBinding{
					Port:     proto.Int32(int32(port)),
					Protocol: transportProtocol,
				})
			}
		}
	}
	if M.IsDomainName(options.Server) {
		server.DomainName = proto.String(options.Server)
	} else {
		server.IpAddress = proto.String(options.Server)
	}
	config := &mieruclient.ClientConfig{
		Profile: &mierupb.ClientProfile{
			ProfileName: proto.String(tag),
			User: &mierupb.User{
				Name:     proto.String(options.UserName),
				Password: proto.String(options.Password),
			},
			Servers: []*mierupb.ServerEndpoint{server},
		},
		Dialer:       dialer,
		PacketDialer: dialer,
		DNSConfig: &mierucommon.ClientDNSConfig{
			BypassDialerDNS: true,
		},
	}
	if multiplexing, ok := mierupb.MultiplexingLevel_value[options.Multiplexing]; ok {
		config.Profile.Multiplexing = &mierupb.MultiplexingConfig{
			Level: mierupb.MultiplexingLevel(multiplexing).Enum(),
		}
	}
	if handshakeMode, ok := mierupb.HandshakeMode_value[options.HandshakeMode]; ok {
		config.Profile.HandshakeMode = mierupb.HandshakeMode(handshakeMode).Enum()
	}
	config.Profile.UserHint = proto.Bool(options.UserHint)
	if options.MTU > 0 {
		config.Profile.Mtu = proto.Int32(int32(options.MTU))
	}
	if options.TrafficPattern != "" {
		trafficPattern, err := mierutp.Decode(options.TrafficPattern)
		if err != nil {
			// Try decode as JSON
			trafficPattern, err = decodeTrafficPatternJSON(options.TrafficPattern)
		}
		if err == nil {
			config.Profile.TrafficPattern = trafficPattern
		}
	}
	return config, nil
}

func decodeTrafficPatternJSON(jsonText string) (*mierupb.TrafficPattern, error) {
	var root map[string]json.RawMessage
	err := json.Unmarshal([]byte(jsonText), &root)
	if err != nil {
		return nil, err
	}

	payload := []byte(jsonText)
	if nested, loaded := root["trafficPattern"]; loaded {
		payload = nested
	}

	pattern := &mierupb.TrafficPattern{}
	err = protojson.Unmarshal(payload, pattern)
	if err != nil {
		return nil, err
	}
	return pattern, nil
}

func validateMieruOptions(options pluginoption.MieruOutboundOptions) error {
	if options.Server == "" {
		return fmt.Errorf("server is empty")
	}
	if options.ServerPort == 0 && len(options.ServerPortRanges) == 0 {
		return fmt.Errorf("either server_port or server_ports must be set")
	}
	for _, pr := range options.ServerPortRanges {
		begin, end, err := beginAndEndPortFromPortRange(pr)
		if err != nil {
			return fmt.Errorf("invalid server_ports format")
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
	if options.Transport != "TCP" && options.Transport != "UDP" {
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
		if _, ok := mierupb.HandshakeMode_value[options.HandshakeMode]; !ok {
			return fmt.Errorf("invalid handshake mode: %s", options.HandshakeMode)
		}
	}
	if options.TrafficPattern != "" {
		trafficPattern, err := mierutp.Decode(options.TrafficPattern)
		if err != nil {
			return fmt.Errorf("failed to decode traffic pattern %q: %w", options.TrafficPattern, err)
		}
		if err := mierutp.Validate(trafficPattern); err != nil {
			return fmt.Errorf("invalid traffic pattern %q: %w", options.TrafficPattern, err)
		}
	}
	return nil
}

func mieruMuxValue(s string) (int32, bool) {
	if v, ok := mierupb.MultiplexingLevel_value[s]; ok {
		return v, true
	}
	switch s {
	case "MEDIUM":
		return mierupb.MultiplexingLevel_value["MULTIPLEXING_MIDDLE"], true
	}
	return 0, false
}

func beginAndEndPortFromPortRange(portRange string) (int, int, error) {
	var begin, end int
	_, err := fmt.Sscanf(portRange, "%d-%d", &begin, &end)
	return begin, end, err
}

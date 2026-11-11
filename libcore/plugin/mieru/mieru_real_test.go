package mieru

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	singcommon "github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/server"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/socks5"
	"github.com/stretchr/testify/require"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
)

type realMieruServer struct {
	server server.Server
	port   int
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (s *realMieruServer) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.server != nil && s.server.IsRunning() {
		_ = s.server.Stop()
	}
	s.wg.Wait()
}

type mieruServerOptions struct {
	protocol  string
	port      int
	portRange string
	username  string
	password  string
}

func startRealMieruServerCustom(t *testing.T, opts mieruServerOptions) *realMieruServer {
	var transportProto *appctlpb.TransportProtocol
	switch opts.protocol {
	case "UDP":
		transportProto = appctlpb.TransportProtocol_UDP.Enum()
	default:
		transportProto = appctlpb.TransportProtocol_TCP.Enum()
	}

	var portBinding *appctlpb.PortBinding
	if opts.portRange != "" {
		portBinding = &appctlpb.PortBinding{
			PortRange: new(opts.portRange),
			Protocol:  transportProto,
		}
	} else {
		if opts.port == 0 {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			opts.port = ln.Addr().(*net.TCPAddr).Port
			_ = ln.Close()
		}
		portBinding = &appctlpb.PortBinding{
			Port:     new(int32(opts.port)),
			Protocol: transportProto,
		}
	}

	listenIP := "127.0.0.1"
	s := server.NewServer()
	cfg := &server.ServerConfig{
		Config: &appctlpb.ServerConfig{
			ListenIPAddress: &listenIP,
			PortBindings:    []*appctlpb.PortBinding{portBinding},
			Users: []*appctlpb.User{
				{
					Name:            &opts.username,
					Password:        &opts.password,
					AllowPrivateIP:  new(true),
					AllowLoopbackIP: new(true),
				},
			},
		},
	}

	err := s.Store(cfg)
	require.NoError(t, err)
	err = s.Start()
	require.NoError(t, err)
	require.True(t, s.IsRunning())

	ctx, cancel := context.WithCancel(context.Background())
	rms := &realMieruServer{
		server: s,
		port:   opts.port,
		cancel: cancel,
	}

	rms.wg.Go(func() {
		for {
			proxyConn, req, err := s.Accept()
			if err != nil {
				return
			}
			go handleMieruProxyConn(ctx, proxyConn, req)
		}
	})

	return rms
}

func startRealMieruServer(t *testing.T, protocol string, username, password string) *realMieruServer {
	return startRealMieruServerCustom(t, mieruServerOptions{
		protocol: protocol,
		username: username,
		password: password,
	})
}

func handleMieruProxyConn(ctx context.Context, proxyConn net.Conn, req *model.Request) {
	defer proxyConn.Close()

	switch req.Command {
	case constant.Socks5ConnectCmd:
		target, err := net.DialTimeout("tcp", req.DstAddr.String(), 3*time.Second)
		if err != nil {
			resp := &model.Response{Reply: constant.Socks5ReplyHostUnreachable}
			_ = resp.WriteToSocks5(proxyConn)
			return
		}
		defer target.Close()

		local := target.LocalAddr().(*net.TCPAddr)
		resp := &model.Response{
			Reply:    constant.Socks5ReplySuccess,
			BindAddr: model.AddrSpec{IP: local.IP, Port: local.Port},
		}
		if err := resp.WriteToSocks5(proxyConn); err != nil {
			return
		}

		common.BidiCopy(proxyConn, target)

	case constant.Socks5UDPAssociateCmd:
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			resp := &model.Response{Reply: constant.Socks5ReplyServerFailure}
			_ = resp.WriteToSocks5(proxyConn)
			return
		}
		defer udpConn.Close()

		_, udpPortStr, _ := net.SplitHostPort(udpConn.LocalAddr().String())
		udpPort, _ := strconv.Atoi(udpPortStr)
		resp := &model.Response{
			Reply:    constant.Socks5ReplySuccess,
			BindAddr: model.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: udpPort},
		}
		if err := resp.WriteToSocks5(proxyConn); err != nil {
			return
		}

		tunnel := apicommon.NewPacketOverStreamTunnel(proxyConn)
		socks5.RunUDPAssociateLoop(udpConn, tunnel, &net.Resolver{})
	}
}

func startEchoServers(t *testing.T) (tcpPort, udpPort int, closeFn func()) {
	// TCP echo
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpPort = tcpLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil && err != io.EOF {
					return
				}
				resp := append([]byte("ECHO:"), buf[:n]...)
				_, _ = c.Write(resp)
			}(conn)
		}
	}()

	// UDP echo
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	udpPort = udpConn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := append([]byte("ECHO_UDP:"), buf[:n]...)
			_, _ = udpConn.WriteToUDP(resp, raddr)
		}
	}()

	closeFn = func() {
		_ = tcpLn.Close()
		_ = udpConn.Close()
	}
	return tcpPort, udpPort, closeFn
}

func TestMieru_Basic_TCP(t *testing.T) {
	username := "testuser"
	password := "testpass123"

	tcpEchoPort, _, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "TCP", username, password)
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(srv.port),
		UserName:   username,
		Password:   password,
		Transport:  "TCP",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-test", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
	conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
	require.NoError(t, err)
	defer conn.Close()

	sendMsg := []byte("hello mieru tcp")
	_, err = conn.Write(sendMsg)
	require.NoError(t, err)

	respBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(respBuf)
	require.NoError(t, err)

	expected := append([]byte("ECHO:"), sendMsg...)
	require.Equal(t, string(expected), string(respBuf[:n]))
}

func TestMieru_Basic_UDP_DialContext(t *testing.T) {
	username := "testuser"
	password := "testpass123"

	_, udpEchoPort, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "TCP", username, password)
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(srv.port),
		UserName:   username,
		Password:   password,
		Transport:  "TCP",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-test", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	targetUDP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", udpEchoPort))
	conn, err := outbound.DialContext(ctx, "udp", targetUDP)
	require.NoError(t, err)
	defer conn.Close()

	sendMsg := []byte("hello mieru udp dial")
	_, err = conn.Write(sendMsg)
	require.NoError(t, err)

	respBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(respBuf)
	require.NoError(t, err)

	expected := append([]byte("ECHO_UDP:"), sendMsg...)
	require.Equal(t, string(expected), string(respBuf[:n]))
}

func TestMieru_Basic_UDP_ListenPacket(t *testing.T) {
	username := "testuser"
	password := "testpass123"

	_, udpEchoPort, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "TCP", username, password)
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(srv.port),
		UserName:   username,
		Password:   password,
		Transport:  "TCP",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-test", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	targetUDP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", udpEchoPort))
	packetConn, err := outbound.ListenPacket(ctx, M.Socksaddr{})
	require.NoError(t, err)
	defer packetConn.Close()

	sendMsg := []byte("hello mieru udp listen")
	_, err = packetConn.WriteTo(sendMsg, targetUDP.UDPAddr())
	require.NoError(t, err)

	respBuf := make([]byte, 1024)
	packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, fromAddr, err := packetConn.ReadFrom(respBuf)
	require.NoError(t, err)

	expected := append([]byte("ECHO_UDP:"), sendMsg...)
	require.Equal(t, string(expected), string(respBuf[:n]))
	t.Logf("UDP packet received from %v", fromAddr)
}

func TestMieru_Transport_UDP(t *testing.T) {
	username := "testuser"
	password := "testpass123"

	tcpEchoPort, udpEchoPort, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "UDP", username, password)
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(srv.port),
		UserName:   username,
		Password:   password,
		Transport:  "UDP",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-test-udp-transport", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	// 1. TCP over Mieru UDP transport
	targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
	conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
	require.NoError(t, err)
	defer conn.Close()

	sendMsg := []byte("hello mieru over udp transport")
	_, err = conn.Write(sendMsg)
	require.NoError(t, err)

	respBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(respBuf)
	require.NoError(t, err)

	expected := append([]byte("ECHO:"), sendMsg...)
	require.Equal(t, string(expected), string(respBuf[:n]))

	// 2. UDP over Mieru UDP transport
	targetUDP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", udpEchoPort))
	packetConn, err := outbound.ListenPacket(ctx, M.Socksaddr{})
	require.NoError(t, err)
	defer packetConn.Close()

	udpSendMsg := []byte("hello mieru udp over udp transport")
	_, err = packetConn.WriteTo(udpSendMsg, targetUDP.UDPAddr())
	require.NoError(t, err)

	udpRespBuf := make([]byte, 1024)
	packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	un, _, err := packetConn.ReadFrom(udpRespBuf)
	require.NoError(t, err)

	expectedUDP := append([]byte("ECHO_UDP:"), udpSendMsg...)
	require.Equal(t, string(expectedUDP), string(udpRespBuf[:un]))
}

func TestMieru_Multiplexing_Levels(t *testing.T) {
	muxLevels := []string{"OFF", "LOW", "MIDDLE", "HIGH"}
	username := "muxuser"
	password := "muxpass123"

	tcpEchoPort, _, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "TCP", username, password)
	defer srv.Close()

	for _, level := range muxLevels {
		t.Run("Mux_"+level, func(t *testing.T) {
			opts := pluginoption.MieruOutboundOptions{
				Server:       "127.0.0.1",
				ServerPort:   uint16(srv.port),
				UserName:     username,
				Password:     password,
				Transport:    "TCP",
				Multiplexing: level,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			outbound, err := NewOutbound(ctx, nil, nil, "mieru-mux-"+level, opts)
			require.NoError(t, err)
			defer singcommon.Close(outbound)

			targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
			conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
			require.NoError(t, err)
			defer conn.Close()

			msg := fmt.Sprintf("test mux %s", level)
			_, err = conn.Write([]byte(msg))
			require.NoError(t, err)

			respBuf := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(respBuf)
			require.NoError(t, err)

			expected := "ECHO:" + msg
			require.Equal(t, expected, string(respBuf[:n]))
		})
	}
}

func TestMieru_Handshake_Modes(t *testing.T) {
	modes := []string{"HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT", "HANDSHAKE_DEFAULT"}
	username := "hsuser"
	password := "hspass123"

	tcpEchoPort, _, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "TCP", username, password)
	defer srv.Close()

	for _, mode := range modes {
		t.Run("Handshake_"+mode, func(t *testing.T) {
			opts := pluginoption.MieruOutboundOptions{
				Server:        "127.0.0.1",
				ServerPort:    uint16(srv.port),
				UserName:      username,
				Password:      password,
				Transport:     "TCP",
				HandshakeMode: mode,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			outbound, err := NewOutbound(ctx, nil, nil, "mieru-hs-"+mode, opts)
			require.NoError(t, err)
			defer singcommon.Close(outbound)

			targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
			conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
			require.NoError(t, err)
			defer conn.Close()

			msg := fmt.Sprintf("test handshake mode %s", mode)
			_, err = conn.Write([]byte(msg))
			require.NoError(t, err)

			respBuf := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(respBuf)
			require.NoError(t, err)

			expected := "ECHO:" + msg
			require.Equal(t, expected, string(respBuf[:n]))
		})
	}
}

func TestMieru_Port_Range(t *testing.T) {
	username := "rangeuser"
	password := "rangepass123"

	tcpEchoPort, _, closeEchos := startEchoServers(t)
	defer closeEchos()

	// Pick two free contiguous ports for testing port-range
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p1 := ln1.Addr().(*net.TCPAddr).Port
	_ = ln1.Close()

	portRangeStr := fmt.Sprintf("%d-%d", p1, p1+1)

	srv := startRealMieruServerCustom(t, mieruServerOptions{
		protocol:  "TCP",
		portRange: portRangeStr,
		username:  username,
		password:  password,
	})
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:           "127.0.0.1",
		ServerPortRanges: []string{portRangeStr},
		UserName:         username,
		Password:         password,
		Transport:        "TCP",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-range-test", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
	conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
	require.NoError(t, err)
	defer conn.Close()

	msg := "test port range"
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	respBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(respBuf)
	require.NoError(t, err)

	expected := "ECHO:" + msg
	require.Equal(t, expected, string(respBuf[:n]))
}

func TestMieru_MTU(t *testing.T) {
	username := "mtuuser"
	password := "mtupass123"

	tcpEchoPort, _, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "TCP", username, password)
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(srv.port),
		UserName:   username,
		Password:   password,
		Transport:  "TCP",
		MTU:        1400,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-mtu-test", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
	conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
	require.NoError(t, err)
	defer conn.Close()

	msg := "test mtu setting"
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)

	respBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(respBuf)
	require.NoError(t, err)

	expected := "ECHO:" + msg
	require.Equal(t, expected, string(respBuf[:n]))
}

func TestMieru_Auth_Failure(t *testing.T) {
	srv := startRealMieruServer(t, "TCP", "validuser", "correctpassword")
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(srv.port),
		UserName:   "validuser",
		Password:   "WRONG_PASSWORD_XYZ",
		Transport:  "TCP",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-auth-fail", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	targetTCP := M.ParseSocksaddr("127.0.0.1:8080")
	conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
	if err == nil {
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		_, writeErr := conn.Write([]byte("ping"))
		buf := make([]byte, 100)
		_, readErr := conn.Read(buf)
		conn.Close()
		require.True(t, writeErr != nil || readErr != nil, "Connection should fail due to invalid credentials")
	} else {
		require.Error(t, err)
	}
}

func TestMieru_Concurrency(t *testing.T) {
	username := "concurrentuser"
	password := "concurrentpass123"

	tcpEchoPort, _, closeEchos := startEchoServers(t)
	defer closeEchos()

	srv := startRealMieruServer(t, "TCP", username, password)
	defer srv.Close()

	opts := pluginoption.MieruOutboundOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(srv.port),
		UserName:     username,
		Password:     password,
		Transport:    "TCP",
		Multiplexing: "HIGH",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	outbound, err := NewOutbound(ctx, nil, nil, "mieru-concurrent-test", opts)
	require.NoError(t, err)
	defer singcommon.Close(outbound)

	numWorkers := 10
	var wg sync.WaitGroup
	errChan := make(chan error, numWorkers)

	for i := range numWorkers {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			workerCtx, workerCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer workerCancel()

			targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
			conn, err := outbound.DialContext(workerCtx, "tcp", targetTCP)
			if err != nil {
				errChan <- fmt.Errorf("worker %d DialContext failed: %w", workerID, err)
				return
			}
			defer conn.Close()

			sendMsg := fmt.Sprintf("concurrent worker payload #%d", workerID)
			if _, err := conn.Write([]byte(sendMsg)); err != nil {
				errChan <- fmt.Errorf("worker %d Write failed: %w", workerID, err)
				return
			}

			respBuf := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(respBuf)
			if err != nil {
				errChan <- fmt.Errorf("worker %d Read failed: %w", workerID, err)
				return
			}

			expected := "ECHO:" + sendMsg
			if string(respBuf[:n]) != expected {
				errChan <- fmt.Errorf("worker %d mismatch: got %q, want %q", workerID, string(respBuf[:n]), expected)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		require.NoError(t, err)
	}
}

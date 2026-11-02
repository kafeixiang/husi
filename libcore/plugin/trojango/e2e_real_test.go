package trojango

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
)

const (
	testCert = `-----BEGIN CERTIFICATE-----
MIIDZTCCAk2gAwIBAgIQBIBNupbq+KyHd0S1pzXEQDANBgkqhkiG9w0BAQsFADAR
MQ8wDQYDVQQDDAZmcmVnaWUwIBcNMjExMDE1MDI0NjU5WhgPMjEyMTA5MjEwMjQ2
NTlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAK274VfScpxWVf1Ulqpn8kY00cnB21fDjSr+t5SHEC8kzii7s0Wv
goGRLKGN0e7ok5Ufvc6vdgl0LCMYHii0a0xiRRKFmy5eTpcFaIa+RqRUt696afMh
q4qalB9pIx8PRfME8VhVwF9p9hRpcQOiXT1vV4JJqNZH5QIVC6n1pxDToTEKojYl
dBAYixniZFSGqmu6tki3s5dUnTyyIkdeoIUw+GFZfBY531Yh4dLge/OLIsf8ei2L
dV17Yp+8xgEzs6AAX2BSoj7C+G9cOAJOabcKPs7e+BQmqg8JWlQL+5wt0Nuu049O
uB/f9aJNZEvkuEyM3ZX1LLyLqwvLXuzABS8CAwEAAaOBszCBsDAJBgNVHRMEAjAA
MB0GA1UdDgQWBBQrj8OKLxmucf8DDW5bpCRV1dop3TBMBgNVHSMERTBDgBTJJdOJ
89Rd2u+plS2ikWTd1JAcu6EVpBMwETEPMA0GA1UEAwwGZnJlZ2llghREgytcTE5Q
JCUuH9oYchyboT+kXDATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAw
FAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBsGS0N1yCc
kBUaFMJ8CgiNQgLFoVJkawcT38//R+ii8/6Azt0JcTRzkcsm8Fut0ZrgilnlIGBI
3Y8dVNKDnDwlsANe/YFtIVJ7S/inK3SdZYyLec0VosTWT+T+NZLlI2ESLcSooVL6
+8cQAOcd6MArGHzOVam/pLTyatbOHv8ZFoNBT7zAEvUZJ7ZxwANLyW2XkiqC0Dlr
X/N2PHKY9Az94T4EhWJopiZA09HNAcQckAnAbHRoMulT94hxqyzV8RYDzHA9Z2TN
IfgNuFIhVyQqBp8Hc0/c8T0rBTYlbSPvggywQ9w5xQaoUePm31J/4jPSiFCci681
KnkNNFtbgo96
-----END CERTIFICATE-----`

	testKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtu+FX0nKcVlX9
VJaqZ/JGNNHJwdtXw40q/reUhxAvJM4ou7NFr4KBkSyhjdHu6JOVH73Or3YJdCwj
GB4otGtMYkUShZsuXk6XBWiGvkakVLevemnzIauKmpQfaSMfD0XzBPFYVcBfafYU
aXEDol09b1eCSajWR+UCFQup9acQ06ExCqI2JXQQGIsZ4mRUhqprurZIt7OXVJ08
siJHXqCFMPhhWXwWOd9WIeHS4HvziyLH/Hoti3Vde2KfvMYBM7OgAF9gUqI+wvhv
XDgCTmm3Cj7O3vgUJqoPCVpUC/ucLdDbrtOPTrgf3/WiTWRL5LhMjN2V9Sy8i6sL
y17swAUvAgMBAAECggEAQtfZoI+AtzPki76C5Xdu2KIz4RtsB/1eEB/GhCffCzRu
+W8WT4ZygOVZNaM6FWB4f9Shk6cglAyVer8pw2F/MvlQOAsdpJ52QFa9W7JTvaA2
uBYyM3BN7tsAiIFMGQQoVpMdRG5hwJQlML9M0ygiFaQEGEW85wzsSHvObArux2Lz
A9+YSOLdGWjW8UPGoIaWvPYp0/apwB9WQAfrxeHktbrAAv3293z1qq4BfP/t5mEm
vzOZiLRNlyjo6wj2kdB2UyF9SIUGWu2cMSTl8AiW+idLpursF1cSPaPtJAQyV10P
W1Y4ZESOGgXexbVNQJ6U8YTWCXiXkaDdGI3B9eyPcQKBgQDVR+bm6EeOks+91lfL
L94T3M6hCc9Cvz1Bxif1Ahl1rp0FN2102P/Ovf3ArpYMFNl0liwB2QehBGvgmNw4
IowxqNJKYUwqr+CMZVB0DHpc1p9avI7ISEt8hI6wiQjvvhLhtqqwKw9zxCgLaVD4
JaNN/a5BPyT0CfwqVKGZc5jaGQKBgQDQiC901vJlFekMWgCDOwsEB3S1t8K0xyVA
pWSFw25MzYHE3sBxdk5T+KAcxBHL0dSAvMfiMGnlguo/LAbs2bMR9xnFvoWpQYqp
NjBddZ1l9XtKGpeMwwWMn6+5MfoeVv068MZU2bwMyWiIfKm/4SNBjd6GGgM/m/do
f0D5prFShwKBgENAVd2vloitYFYS1UIbiOIoePssda8tUCqCSi0miVKjSZ3QeXIj
zp2pKO9t3aBXnq31gFDg11f9Zeq/KImG00ABZLXRckvvg1WhyLmfCaJmhn78/+TF
bxAHWFrwCuJVw+xqRe4g1dGCI8JdZgupCpJYEG9Acu2EjH/oicAyRBtZAoGAF+l1
36UCOJsxlQwBAQtVMQoV1PyUZBxt5iLRCxGk5UOvfL66PIh/ZNueqI3HKKMQBg8f
sI0yp3HCoKnQxXoVMZsvJmC5fPYaC1s+YokpGlby40V3WVnHmh95i/fyIWaCNS8E
3xf0m1bBGN2KrYkIfOzitmfnNXUSAraM4dO+g6MCgYEAgk5D3ulLR7scj4MK0jLs
hnUxHrgchGCAsREHDBo+GH6yBmyxyO35Zb4fDJEX4Yc8Enu8UHGhG7++lwGMZqY9
clPb/1SkuEWD+nCLUnkA5KyqPskF2GFjT8be4TBDFtQHBydxZFDZHxMhn4JShCTT
xiGQ1YfbqPMbovNUt1m0Es8=
-----END PRIVATE KEY-----`
)

// pickFreePort finds an available TCP port on 127.0.0.1
func pickFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startTargetHTTPServer(t *testing.T, port int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PONG_FROM_LOCAL_TARGET_HTTP_SERVER"))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}

	listener, err := net.Listen("tcp", server.Addr)
	require.NoError(t, err)

	go func() {
		_ = server.Serve(listener)
	}()

	return server
}

func startTargetUDPEchoServer(t *testing.T) (*net.UDPConn, int) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	port := conn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte("PONG_UDP:"), buf[:n]...)
			_, _ = conn.WriteTo(resp, addr)
		}
	}()

	return conn, port
}

func findTrojanGoBinary() string {
	candidates := []string{
		"/tmp/trojan-test/trojan-go",
		"trojan-go",
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

func TestE2ERealTrojanGoServer(t *testing.T) {
	trojanGoBin := findTrojanGoBinary()
	if trojanGoBin == "" {
		t.Skip("trojan-go binary not found, skipping real binary e2e tests")
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	require.NoError(t, os.WriteFile(certPath, []byte(testCert), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte(testKey), 0o600))

	targetPort := pickFreePort(t)
	targetServer := startTargetHTTPServer(t, targetPort)
	defer targetServer.Close()

	targetUDPConn, udpTargetPort := startTargetUDPEchoServer(t)
	defer targetUDPConn.Close()

	testPassword := "trojan-go-secret-pass-2026"
	logger := log.NewNOPFactory().Logger()

	testCases := []struct {
		name       string
		wsEnabled  bool
		wsPath     string
		ssEnabled  bool
		ssMethod   string
		ssPassword string
		muxEnabled bool
		muxConcur  int
		utlsFp     string
	}{
		{
			name:      "Direct TCP with TLS and uTLS Chrome",
			wsEnabled: false,
			utlsFp:    "chrome",
		},
		{
			name:      "WebSocket with TLS",
			wsEnabled: true,
			wsPath:    "/ws-path-test",
		},
		{
			name:       "WebSocket + smux Mux + stickyConn",
			wsEnabled:  true,
			wsPath:     "/ws-mux-test",
			muxEnabled: true,
			muxConcur:  8,
		},
		{
			name:       "WebSocket + smux Mux + Shadowsocks Secondary AEAD (aes-128-gcm)",
			wsEnabled:  true,
			wsPath:     "/ws-ss-mux-test",
			muxEnabled: true,
			muxConcur:  8,
			ssEnabled:  true,
			ssMethod:   "aes-128-gcm",
			ssPassword: "my-secondary-ss-key",
		},
		{
			name:       "WebSocket + smux Mux + Shadowsocks Secondary AEAD (chacha20-ietf-poly1305)",
			wsEnabled:  true,
			wsPath:     "/ws-ss-chacha-test",
			muxEnabled: true,
			muxConcur:  8,
			ssEnabled:  true,
			ssMethod:   "chacha20-ietf-poly1305",
			ssPassword: "chacha-secondary-secret",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serverPort := pickFreePort(t)

			// Generate server JSON config
			serverConfig := map[string]any{
				"run_type":    "server",
				"local_addr":  "127.0.0.1",
				"local_port":  serverPort,
				"remote_addr": "127.0.0.1",
				"remote_port": targetPort,
				"password":    []string{testPassword},
				"ssl": map[string]any{
					"cert": certPath,
					"key":  keyPath,
					"sni":  "localhost",
				},
			}
			if tc.wsEnabled {
				serverConfig["websocket"] = map[string]any{
					"enabled": true,
					"path":    tc.wsPath,
					"host":    "localhost",
				}
			}
			if tc.muxEnabled {
				serverConfig["mux"] = map[string]any{
					"enabled":     true,
					"concurrency": tc.muxConcur,
				}
			}
			if tc.ssEnabled {
				serverConfig["shadowsocks"] = map[string]any{
					"enabled":  true,
					"method":   tc.ssMethod,
					"password": tc.ssPassword,
				}
			}

			serverConfigBytes, err := json.MarshalIndent(serverConfig, "", "  ")
			require.NoError(t, err)

			cfgFile := filepath.Join(tmpDir, fmt.Sprintf("server-%d.json", serverPort))
			require.NoError(t, os.WriteFile(cfgFile, serverConfigBytes, 0o600))

			// Start real trojan-go server process
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cmd := exec.CommandContext(ctx, trojanGoBin, "-config", cfgFile)
			cmd.Dir = tmpDir
			var serverLog bytes.Buffer
			cmd.Stdout = &serverLog
			cmd.Stderr = &serverLog
			require.NoError(t, cmd.Start())
			defer func() {
				cancel()
				_ = cmd.Wait()
			}()

			// Wait for server to listen on serverPort
			var connected bool
			for range 50 {
				time.Sleep(50 * time.Millisecond)
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 100*time.Millisecond)
				if err == nil {
					conn.Close()
					connected = true
					break
				}
			}
			if !connected {
				t.Logf("trojan-go server output:\n%s", serverLog.String())
			}
			require.True(t, connected, "trojan-go server failed to start and listen within 2.5s")

			// Build Husi client outbound
			clientOpts := pluginoption.TrojanGoOutboundOptions{
				Password: testPassword,

				Server:     "127.0.0.1",
				ServerPort: uint16(serverPort),
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "localhost",
					Insecure:   true,
				},
			}

			if tc.utlsFp != "" {
				clientOpts.TLS.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: tc.utlsFp,
				}
			}

			if tc.wsEnabled {
				clientOpts.Transport = &option.V2RayTransportOptions{
					Type: "ws",
					WebsocketOptions: option.V2RayWebsocketOptions{
						Path: tc.wsPath,
						Headers: badoption.HTTPHeader{
							"Host": badoption.Listable[string]{"localhost"},
						},
					},
				}
			}

			if tc.muxEnabled {
				clientOpts.Mux = &pluginoption.TrojanGoMuxOptions{
					Enabled:     true,
					Concurrency: tc.muxConcur,
				}
			}

			if tc.ssEnabled {
				clientOpts.Shadowsocks = &pluginoption.TrojanGoShadowsocksOptions{
					Enabled:  true,
					Method:   tc.ssMethod,
					Password: tc.ssPassword,
				}
			}

			outbound, err := NewOutbound(ctx, nil, logger, "test-out", clientOpts)
			require.NoError(t, err)

			// Helper: send HTTP GET request through outbound to local target server
			sendAndVerifyHTTP := func() {
				dest := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", targetPort))
				conn, dialErr := outbound.DialContext(ctx, "tcp", dest)
				require.NoError(t, dialErr)
				defer conn.Close()

				req := "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
				_, writeErr := conn.Write([]byte(req))
				require.NoError(t, writeErr)

				respBytes, readErr := io.ReadAll(conn)
				require.NoError(t, readErr)

				respStr := string(respBytes)
				require.Contains(t, respStr, "HTTP/1.1 200 OK")
				require.Contains(t, respStr, "PONG_FROM_LOCAL_TARGET_HTTP_SERVER")
			}

			// Single HTTP request check
			sendAndVerifyHTTP()

			// Single UDP packet relay check
			udpTargetAddr := fmt.Sprintf("127.0.0.1:%d", udpTargetPort)
			destUDP := M.ParseSocksaddr(udpTargetAddr)
			pktConn, pktErr := outbound.ListenPacket(ctx, destUDP)
			require.NoError(t, pktErr)
			defer pktConn.Close()

			pingPayload := []byte("hello-udp-test")
			_, writeErr := pktConn.WriteTo(pingPayload, destUDP.UDPAddr())
			require.NoError(t, writeErr)

			respBuf := make([]byte, 1024)
			_ = pktConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, readErr := pktConn.ReadFrom(respBuf)
			require.NoError(t, readErr)
			require.Equal(t, "PONG_UDP:hello-udp-test", string(respBuf[:n]))

			// If Mux is enabled, test 10 concurrent requests multiplexing through the same session!
			if tc.muxEnabled {
				var wg sync.WaitGroup
				errChan := make(chan error, 10)
				for range 10 {
					wg.Go(func() {
						dest := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", targetPort))
						conn, dialErr := outbound.DialContext(ctx, "tcp", dest)
						if dialErr != nil {
							errChan <- dialErr
							return
						}
						defer conn.Close()

						req := "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
						if _, err := conn.Write([]byte(req)); err != nil {
							errChan <- err
							return
						}
						respBytes, err := io.ReadAll(conn)
						if err != nil {
							errChan <- err
							return
						}
						if !bytes.Contains(respBytes, []byte("PONG_FROM_LOCAL_TARGET_HTTP_SERVER")) {
							errChan <- fmt.Errorf("unexpected response: %s", string(respBytes))
							return
						}
					})
				}
				wg.Wait()
				close(errChan)
				for err := range errChan {
					require.NoError(t, err)
				}
			}
		})
	}
}

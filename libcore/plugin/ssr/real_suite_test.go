package ssr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/server"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/socks5"
	"github.com/stretchr/testify/require"
)

const (
	trojanCert = `-----BEGIN CERTIFICATE-----
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

	trojanKey = `-----BEGIN PRIVATE KEY-----
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

func makeSSRLikeLink(ip string, port int, method, protocol, obfs, pass, remarks string) string {
	b64Pass := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(pass)), "=")
	b64Remarks := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(remarks)), "=")
	mainPart := fmt.Sprintf("%s:%d:%s:%s:%s:%s/?remarks=%s", ip, port, protocol, method, obfs, b64Pass, b64Remarks)
	return "ssr://" + strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(mainPart)), "=")
}

func TestRunRealDeviceServers(t *testing.T) {
	if os.Getenv("REAL_DEVICE_SERVER") == "" {
		t.Skip("skipping manual real device server runner; set REAL_DEVICE_SERVER=1 to run")
	}

	lanIP := "192.168.1.11"
	targetEchoPort := 19999

	var links []string

	// 1. Target HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("husi_real_test_ok\n"))
	})
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PONG\n"))
	})
	mux.HandleFunc("/sub.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(strings.Join(links, "\n") + "\n"))
	})
	mux.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n") + "\n"))
		_, _ = w.Write([]byte(body))
	})

	httpServer := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", targetEchoPort),
		Handler: mux,
	}
	ln, err := net.Listen("tcp", httpServer.Addr)
	require.NoError(t, err)
	go func() { _ = httpServer.Serve(ln) }()
	defer httpServer.Close()
	t.Logf("[HTTP] Target server running on 0.0.0.0:%d", targetEchoPort)

	// 2. SSR Servers: ALL 37 Supported Ciphers
	allCiphers := []string{
		"none",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
		"aes-128-cfb8", "aes-192-cfb8", "aes-256-cfb8",
		"aes-128-ofb", "aes-192-ofb", "aes-256-ofb",
		"camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
		"camellia-128-cfb8", "camellia-192-cfb8", "camellia-256-cfb8",
		"rc4-md5", "rc4-md5-6", "rc4",
		"bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
		"chacha20-ietf", "xchacha20", "chacha20",
		"xsalsa20", "salsa20",
		"table", "rabbit", "hc128", "zuc128",
	}

	protoPool := []string{
		"auth_chain_a",
		"auth_chain_b",
		"auth_aes128_sha1",
		"auth_aes128_md5",
		"auth_sha1_v4",
		"origin",
	}
	obfsPool := []string{
		"http_simple",
		"tls1.2_ticket_auth",
		"plain",
		"http_post",
		"random_head",
		"tls1.2_ticket_fastauth",
	}

	for i, c := range allCiphers {
		port := 20001 + i
		proto := protoPool[i%len(protoPool)]
		obfs := obfsPool[i%len(obfsPool)]
		pass := fmt.Sprintf("pass%d", port)
		cleanMethod := strings.ReplaceAll(c, "-", "")
		name := fmt.Sprintf("SSR_%02d_%s_%s", i+1, cleanMethod, proto)

		cfg := SSRServerConfig{
			Method:     c,
			Password:   pass,
			Protocol:   proto,
			Obfs:       obfs,
			ListenAddr: fmt.Sprintf("0.0.0.0:%d", port),
			TargetAddr: fmt.Sprintf("127.0.0.1:%d", targetEchoPort),
		}
		s, err := StartSSRMockServer(cfg)
		require.NoError(t, err, "Start SSR %s", name)
		defer s.Close()
		link := makeSSRLikeLink(lanIP, port, c, proto, obfs, pass, name)
		links = append(links, link)
		t.Logf("[SSR] Started %s on port %d: %s", name, port, link)
	}

	// 3. Mieru Servers
	mieruCases := []struct {
		port  int
		proto string
		user  string
		pass  string
		name  string
	}{
		{21001, "TCP", "mieru_tcp_user", "mieru_tcp_pass", "Mieru_01_TCP"},
		{21002, "UDP", "mieru_udp_user", "mieru_udp_pass", "Mieru_02_UDP"},
	}
	for _, mc := range mieruCases {
		listenIP := "0.0.0.0"
		var transProto *appctlpb.TransportProtocol
		if mc.proto == "UDP" {
			transProto = appctlpb.TransportProtocol_UDP.Enum()
		} else {
			transProto = appctlpb.TransportProtocol_TCP.Enum()
		}
		portVal := int32(mc.port)
		ms := server.NewServer()
		cfg := &server.ServerConfig{
			Config: &appctlpb.ServerConfig{
				ListenIPAddress: &listenIP,
				PortBindings: []*appctlpb.PortBinding{
					{
						Port:     &portVal,
						Protocol: transProto,
					},
				},
				Users: []*appctlpb.User{
					{
						Name:            &mc.user,
						Password:        &mc.pass,
						AllowPrivateIP:  new(true),
						AllowLoopbackIP: new(true),
					},
				},
			},
		}
		err := ms.Store(cfg)
		require.NoError(t, err)
		err = ms.Start()
		require.NoError(t, err)
		defer func(s server.Server) { _ = s.Stop() }(ms)

		// Run accept loop for Mieru server
		go func(s server.Server) {
			for {
				proxyConn, req, err := s.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn, r *model.Request) {
					defer conn.Close()
					switch r.Command {
					case constant.Socks5ConnectCmd:
						target, err := net.DialTimeout("tcp", r.DstAddr.String(), 5*time.Second)
						if err != nil {
							resp := &model.Response{Reply: constant.Socks5ReplyHostUnreachable}
							_ = resp.WriteToSocks5(conn)
							return
						}
						defer target.Close()
						local := target.LocalAddr().(*net.TCPAddr)
						resp := &model.Response{
							Reply:    constant.Socks5ReplySuccess,
							BindAddr: model.AddrSpec{IP: local.IP, Port: local.Port},
						}
						if err := resp.WriteToSocks5(conn); err != nil {
							return
						}
						common.BidiCopy(conn, target)

					case constant.Socks5UDPAssociateCmd:
						udpConn, err := net.ListenUDP("udp", nil)
						if err != nil {
							return
						}
						defer udpConn.Close()
						_, udpPortStr, err := net.SplitHostPort(udpConn.LocalAddr().String())
						if err != nil {
							return
						}
						udpPort, _ := strconv.Atoi(udpPortStr)
						resp := &model.Response{
							Reply:    constant.Socks5ReplySuccess,
							BindAddr: model.AddrSpec{IP: net.IP{0, 0, 0, 0}, Port: udpPort},
						}
						if err := resp.WriteToSocks5(conn); err != nil {
							return
						}
						tunnel := apicommon.NewPacketOverStreamTunnel(conn)
						socks5.RunUDPAssociateLoop(udpConn, tunnel, &net.Resolver{})
					}
				}(proxyConn, req)
			}
		}(ms)

		link := fmt.Sprintf("mierus://%s:%s@%s:%d?port=%d&protocol=%s&profile=%s#%s",
			mc.user, mc.pass, lanIP, mc.port, mc.port, mc.proto, mc.name, mc.name)
		links = append(links, link)
		t.Logf("[MIERU] Started %s on port %d: %s", mc.name, mc.port, link)
	}

	// 4. Trojan-Go Servers
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	require.NoError(t, os.WriteFile(certPath, []byte(trojanCert), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte(trojanKey), 0o600))

	trojanGoBin := "/opt/homebrew/bin/trojan-go"
	tgCases := []struct {
		port       int
		wsPath     string
		mux        bool
		ssMethod   string
		ssPassword string
		name       string
	}{
		{22001, "", false, "", "", "TrojanGo_01_Direct_TLS"},
		{22002, "/trojan-ws", false, "", "", "TrojanGo_02_WebSocket_TLS"},
		{22003, "/trojan-mux", true, "", "", "TrojanGo_03_WS_smux_Mux"},
		{22004, "/trojan-ss-mux", true, "aes-128-gcm", "secpass123", "TrojanGo_04_WS_Mux_SS_AES128GCM"},
		{22005, "/trojan-ss-chacha", true, "chacha20-ietf-poly1305", "secpass456", "TrojanGo_05_WS_Mux_SS_Chacha20"},
	}

	for _, tc := range tgCases {
		trojanPass := "trojanpass123"
		conf := map[string]any{
			"run_type":    "server",
			"local_addr":  "0.0.0.0",
			"local_port":  tc.port,
			"remote_addr": "127.0.0.1",
			"remote_port": targetEchoPort,
			"password":    []string{trojanPass},
			"ssl": map[string]any{
				"cert": certPath,
				"key":  keyPath,
				"sni":  "localhost",
			},
		}
		if tc.wsPath != "" {
			conf["websocket"] = map[string]any{
				"enabled": true,
				"path":    tc.wsPath,
				"host":    "localhost",
			}
		}
		if tc.mux {
			conf["mux"] = map[string]any{
				"enabled":     true,
				"concurrency": 8,
			}
		}
		if tc.ssMethod != "" {
			conf["shadowsocks"] = map[string]any{
				"enabled":  true,
				"method":   tc.ssMethod,
				"password": tc.ssPassword,
			}
		}

		confPath := filepath.Join(tmpDir, fmt.Sprintf("tg_%d.json", tc.port))
		confData, err := json.Marshal(conf)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(confPath, confData, 0o600))

		cmd := exec.Command(trojanGoBin, "-config", confPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		require.NoError(t, err, "Failed to start trojan-go %s", tc.name)
		defer func(c *exec.Cmd) {
			if c.Process != nil {
				_ = c.Process.Kill()
			}
		}(cmd)

		// Build URI
		var uriParts []string
		uriParts = append(uriParts, "sni=localhost", "allowInsecure=true")
		if tc.wsPath != "" {
			uriParts = append(uriParts, "type=ws", "host=localhost", "path="+tc.wsPath)
		}
		if tc.mux {
			uriParts = append(uriParts, "mux=true")
		}
		if tc.ssMethod != "" {
			uriParts = append(uriParts, fmt.Sprintf("encryption=ss;%s:%s", tc.ssMethod, tc.ssPassword))
		}
		link := fmt.Sprintf("trojan-go://%s@%s:%d/?%s#%s", trojanPass, lanIP, tc.port, strings.Join(uriParts, "&"), tc.name)
		links = append(links, link)
		t.Logf("[TROJAN-GO] Started %s on port %d: %s", tc.name, tc.port, link)
	}

	t.Logf("=== ALL 13 SERVERS READY ===")
	t.Logf("Sub URL: http://%s:%d/sub", lanIP, targetEchoPort)
	t.Logf("Sub txt URL: http://%s:%d/sub.txt", lanIP, targetEchoPort)

	// Keep running until test context is canceled or signal received
	for {
		time.Sleep(1 * time.Second)
	}
}

func TestAll37SSRCiphersEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 37-cipher test in short mode")
	}

	allCiphers := []string{
		"none",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
		"aes-128-cfb8", "aes-192-cfb8", "aes-256-cfb8",
		"aes-128-ofb", "aes-192-ofb", "aes-256-ofb",
		"camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
		"camellia-128-cfb8", "camellia-192-cfb8", "camellia-256-cfb8",
		"rc4-md5", "rc4-md5-6", "rc4",
		"bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
		"chacha20-ietf", "xchacha20", "chacha20",
		"xsalsa20", "salsa20",
		"table", "rabbit", "hc128", "zuc128",
	}

	for _, c := range allCiphers {
		t.Run(c, func(t *testing.T) {
			cfg := SSRServerConfig{
				Method:   c,
				Password: "test_e2e_pass",
				Obfs:     "plain",
				Protocol: "origin",
			}
			runRealTCPTest(t, cfg)
		})
	}
}

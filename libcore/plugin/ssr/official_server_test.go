package ssr

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
)

// runOfficialPythonSSRTest spawns the official Python ShadowsocksR server and runs
// an end-to-end TCP and UDP relay test against it.
func runOfficialPythonSSRTest(t *testing.T, method, protocol, obfs, protocolParam, obfsParam, password string) {
	if _, err := os.Stat("/tmp/ssr_official/shadowsocks/server.py"); err != nil {
		t.Skip("skipping official server test: /tmp/ssr_official/shadowsocks/server.py not found")
	}
	// 1. TCP echo server
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen TCP echo: %v", err)
	}
	defer tcpLn.Close()
	tcpEchoPort := tcpLn.Addr().(*net.TCPAddr).Port

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
				c.Write(resp)
			}(conn)
		}
	}()

	// 2. UDP echo server
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to listen UDP echo: %v", err)
	}
	defer udpConn.Close()
	udpEchoPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := append([]byte("ECHO_UDP:"), buf[:n]...)
			udpConn.WriteToUDP(resp, raddr)
		}
	}()

	// 3. Find a free port for Python SSR server
	findPortLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	ssrPort := findPortLn.Addr().(*net.TCPAddr).Port
	findPortLn.Close()

	// 4. Start Official Python ShadowsocksR server
	ssrPortStr := strconv.Itoa(ssrPort)
	args := []string{
		"/tmp/ssr_official/shadowsocks/server.py",
		"-s", "127.0.0.1",
		"-p", ssrPortStr,
		"-k", password,
		"-m", method,
		"-O", protocol,
		"-o", obfs,
		"--forbidden-ip", "",
	}
	if protocolParam != "" {
		args = append(args, "-G", protocolParam)
	}
	serverObfsParam := obfsParam
	if idx := strings.Index(serverObfsParam, "#"); idx != -1 {
		serverObfsParam = serverObfsParam[:idx]
	}
	if serverObfsParam != "" {
		args = append(args, "-g", serverObfsParam)
	}

	cmd := exec.Command("python3", args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start python ssr: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait for server to listen on TCP
	ready := false
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ssrPort), 100*time.Millisecond)
		if err == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("Python SSR server did not start in time. Stderr: %s, Stdout: %s", errBuf.String(), outBuf.String())
	}

	// 5. Test TCP through Husi SSR outbound
	opts := pluginoption.SSROutboundOptions{
		Server:        "127.0.0.1",
		ServerPort:    uint16(ssrPort),
		Method:        method,
		Password:      password,
		Obfs:          obfs,
		ObfsParam:     obfsParam,
		Protocol:      protocol,
		ProtocolParam: protocolParam,
	}

	outbound, err := NewOutbound(context.Background(), nil, nil, "official-ssr-test", opts)
	if err != nil {
		t.Fatalf("NewOutbound failed: %v", err)
	}

	targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientConn, err := outbound.DialContext(ctx, "tcp", targetTCP)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer clientConn.Close()

	sendMsg := []byte(fmt.Sprintf("Hello Python SSR [%s/%s/%s]", method, protocol, obfs))
	expected := append([]byte("ECHO:"), sendMsg...)

	// send a copy so sendMsg is not mutated in-place by stream XOR
	sendCopy := make([]byte, len(sendMsg))
	copy(sendCopy, sendMsg)

	if _, err := clientConn.Write(sendCopy); err != nil {
		t.Fatalf("clientConn.Write failed: %v", err)
	}

	respBuf := make([]byte, len(expected))
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(clientConn, respBuf)
	if err != nil {
		t.Fatalf("clientConn.Read failed: %v. Stderr: %s, Stdout: %s", err, errBuf.String(), outBuf.String())
	}
	if !bytes.Equal(respBuf, expected) {
		t.Fatalf("TCP mismatch: got %q, want %q", respBuf, expected)
	}

	// 6. Test UDP through Husi SSR outbound
	packetConn, err := outbound.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer packetConn.Close()

	targetUDP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", udpEchoPort))
	udpSendMsg := []byte(fmt.Sprintf("UDP ping [%s/%s/%s]", method, protocol, obfs))
	expectedUDP := append([]byte("ECHO_UDP:"), udpSendMsg...)

	udpSendCopy := make([]byte, len(udpSendMsg))
	copy(udpSendCopy, udpSendMsg)

	if _, err := packetConn.WriteTo(udpSendCopy, targetUDP); err != nil {
		t.Fatalf("packetConn.WriteTo failed: %v", err)
	}

	udpRespBuf := make([]byte, 1024)
	packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	un, fromAddr, err := packetConn.ReadFrom(udpRespBuf)
	if err != nil {
		t.Fatalf("packetConn.ReadFrom failed: %v. Stderr: %s, Stdout: %s", err, errBuf.String(), outBuf.String())
	}
	if !bytes.Equal(udpRespBuf[:un], expectedUDP) {
		t.Fatalf("UDP mismatch: got %q from %v, want %q", udpRespBuf[:un], fromAddr, expectedUDP)
	}
}

// TestOfficialPythonSSR_Protocols tests all 6 SSR protocols against the official Python server
func TestOfficialPythonSSR_Protocols(t *testing.T) {
	protocols := []string{
		"origin",
		"auth_sha1_v4",
		"auth_aes128_md5",
		"auth_aes128_sha1",
		"auth_chain_a",
		"auth_chain_b",
	}

	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			runOfficialPythonSSRTest(t, "rc4-md5", proto, "plain", "", "", "secret-pwd-456")
		})
	}
}

// TestOfficialPythonSSR_Obfs tests all 6 SSR obfuscations against the official Python server
func TestOfficialPythonSSR_Obfs(t *testing.T) {
	obfsList := []struct {
		obfs      string
		obfsParam string
	}{
		{"plain", ""},
		{"http_simple", "example.com#husi-test"},
		{"http_post", "bing.com#search"},
		{"random_head", ""},
		{"tls1.2_ticket_auth", "cloudflare.com"},
		{"tls1.2_ticket_fastauth", "apple.com"},
	}

	for _, tc := range obfsList {
		t.Run(tc.obfs, func(t *testing.T) {
			runOfficialPythonSSRTest(t, "rc4-md5", "auth_chain_a", tc.obfs, "", tc.obfsParam, "obfs-pwd-789")
		})
	}
}

// TestOfficialPythonSSR_Ciphers tests 15+ ciphers supported by OpenSSL in the official Python server
func TestOfficialPythonSSR_Ciphers(t *testing.T) {
	ciphers := []string{
		"aes-128-cfb",
		"aes-256-cfb",
		"aes-128-ctr",
		"aes-256-ctr",
		"rc4-md5",
		"rc4-md5-6",
		"rc4",
		"bf-cfb",
		"camellia-128-cfb",
		"camellia-256-cfb",
		"cast5-cfb",
		"des-cfb",
		"table",
		"none",
	}

	for _, cipher := range ciphers {
		t.Run(cipher, func(t *testing.T) {
			runOfficialPythonSSRTest(t, cipher, "origin", "plain", "", "", "cipher-test-pwd")
		})
	}
}

// TestOfficialPythonSSR_PopularSetups tests popular SSR setups used in production
func TestOfficialPythonSSR_PopularSetups(t *testing.T) {
	setups := []struct {
		name          string
		method        string
		protocol      string
		obfs          string
		protocolParam string
		obfsParam     string
	}{
		{"AuthChainA_TLS_RC4MD5", "rc4-md5", "auth_chain_a", "tls1.2_ticket_auth", "", "fastly.net"},
		{"AuthChainB_TLS_AES256", "aes-256-cfb", "auth_chain_b", "tls1.2_ticket_fastauth", "", "microsoft.com"},
		{"AuthAES128MD5_HttpSimple", "aes-128-cfb", "auth_aes128_md5", "http_simple", "", "gateway.icloud.com"},
		{"AuthAES128SHA1_HttpPost", "aes-256-ctr", "auth_aes128_sha1", "http_post", "", "api.github.com"},
		{"AuthSha1V4_RandomHead", "rc4-md5", "auth_sha1_v4", "random_head", "", ""},
		{"Origin_Plain_AES256", "aes-256-cfb", "origin", "plain", "", ""},
		{"Origin_Plain_None", "none", "origin", "plain", "", ""},
	}

	for _, s := range setups {
		t.Run(s.name, func(t *testing.T) {
			runOfficialPythonSSRTest(t, s.method, s.protocol, s.obfs, s.protocolParam, s.obfsParam, "prod-pwd-xyz")
		})
	}
}

// TestOfficialPythonSSR_Concurrency tests multiple concurrent connections to the official Python server
func TestOfficialPythonSSR_Concurrency(t *testing.T) {
	if _, err := os.Stat("/tmp/ssr_official/shadowsocks/server.py"); err != nil {
		t.Skip("skipping official server test: /tmp/ssr_official/shadowsocks/server.py not found")
	}
	// TCP echo server
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen TCP echo: %v", err)
	}
	defer tcpLn.Close()
	tcpEchoPort := tcpLn.Addr().(*net.TCPAddr).Port

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
				c.Write(resp)
			}(conn)
		}
	}()

	findPortLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	ssrPort := findPortLn.Addr().(*net.TCPAddr).Port
	findPortLn.Close()

	cmd := exec.Command("python3",
		"/tmp/ssr_official/shadowsocks/server.py",
		"-s", "127.0.0.1",
		"-p", strconv.Itoa(ssrPort),
		"-k", "concurrency-test-pwd",
		"-m", "rc4-md5",
		"-O", "auth_chain_a",
		"-o", "tls1.2_ticket_auth",
		"--forbidden-ip", "",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start python ssr: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ssrPort), 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	opts := pluginoption.SSROutboundOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(ssrPort),
		Method:     "rc4-md5",
		Password:   "concurrency-test-pwd",
		Obfs:       "tls1.2_ticket_auth",
		Protocol:   "auth_chain_a",
	}

	outbound, err := NewOutbound(context.Background(), nil, nil, "concurrency-test", opts)
	if err != nil {
		t.Fatalf("NewOutbound failed: %v", err)
	}

	var wg sync.WaitGroup
	concurrentClients := 10
	errChan := make(chan error, concurrentClients)

	for i := 0; i < concurrentClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			targetTCP := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", tcpEchoPort))
			conn, err := outbound.DialContext(ctx, "tcp", targetTCP)
			if err != nil {
				errChan <- fmt.Errorf("client %d DialContext failed: %w", id, err)
				return
			}
			defer conn.Close()

			sendMsg := []byte(fmt.Sprintf("hello concurrent worker %d", id))
			expected := append([]byte("ECHO:"), sendMsg...)

			sendCopy := make([]byte, len(sendMsg))
			copy(sendCopy, sendMsg)

			if _, err := conn.Write(sendCopy); err != nil {
				errChan <- fmt.Errorf("client %d Write failed: %w", id, err)
				return
			}

			resp := make([]byte, len(expected))
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn, resp); err != nil {
				errChan <- fmt.Errorf("client %d ReadFull failed: %w", id, err)
				return
			}

			if !bytes.Equal(resp, expected) {
				errChan <- fmt.Errorf("client %d response mismatch: got %q, want %q", id, resp, expected)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("Concurrent test failure: %v", err)
	}
}

package ssr

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/core"
)

func runRealTCPTest(t *testing.T, cfg SSRServerConfig) {
	server, err := StartSSRMockServer(cfg)
	if err != nil {
		t.Fatalf("StartSSRMockServer failed: %v", err)
	}
	defer server.Close()

	opts := pluginoption.SSROutboundOptions{
		Server:        "127.0.0.1",
		ServerPort:    uint16(server.Port()),
		Method:        cfg.Method,
		Password:      cfg.Password,
		Obfs:          cfg.Obfs,
		ObfsParam:     cfg.ObfsParam,
		Protocol:      cfg.Protocol,
		ProtocolParam: cfg.ProtocolParam,
	}

	outbound, err := NewOutbound(context.Background(), nil, nil, "ssr-test", opts)
	if err != nil {
		t.Fatalf("NewOutbound failed: %v", err)
	}

	target := M.ParseSocksaddr("echo.test.local:80")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := outbound.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext tcp failed: %v", err)
	}
	defer conn.Close()

	reqPayload := []byte("Hello Real SSR World! Data transmission test 1234567890.")
	expectedResp := append([]byte("ECHO:"), reqPayload...)

	_, err = conn.Write(append([]byte(nil), reqPayload...))
	if err != nil {
		t.Fatalf("conn.Write failed: %v", err)
	}
	recvBuf := make([]byte, len(expectedResp))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, recvBuf)
	if err != nil {
		t.Fatalf("conn.Read response failed: %v", err)
	}

	if !bytes.Equal(recvBuf, expectedResp) {
		t.Fatalf("Response mismatch: got %q, want %q", string(recvBuf), string(expectedResp))
	}
}

func runRealUDPTest(t *testing.T, cfg SSRServerConfig, targetAddrStr string) {
	server, err := StartSSRMockServer(cfg)
	if err != nil {
		t.Fatalf("StartSSRMockServer failed: %v", err)
	}
	defer server.Close()

	opts := pluginoption.SSROutboundOptions{
		Server:        "127.0.0.1",
		ServerPort:    uint16(server.Port()),
		Method:        cfg.Method,
		Password:      cfg.Password,
		Obfs:          cfg.Obfs,
		ObfsParam:     cfg.ObfsParam,
		Protocol:      cfg.Protocol,
		ProtocolParam: cfg.ProtocolParam,
	}

	outbound, err := NewOutbound(context.Background(), nil, nil, "ssr-udp-test", opts)
	if err != nil {
		t.Fatalf("NewOutbound failed: %v", err)
	}

	target := M.ParseSocksaddr(targetAddrStr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pc, err := outbound.ListenPacket(ctx, target)
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer pc.Close()

	// 1. Test WriteTo and ReadFrom
	reqPayload := []byte("Real SSR UDP packet payload #1")
	var destAddr net.Addr
	if target.IsIPv4() || target.IsIPv6() {
		destAddr = target.UDPAddr()
	} else {
		destAddr = target
	}

	_, err = pc.WriteTo(reqPayload, destAddr)
	if err != nil {
		t.Fatalf("pc.WriteTo failed: %v", err)
	}

	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, rAddr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc.ReadFrom failed: %v", err)
	}

	expectedEcho := append([]byte("UDP-ECHO:"), reqPayload...)
	if !bytes.Equal(buf[:n], expectedEcho) {
		t.Fatalf("UDP payload mismatch: got %q, want %q", string(buf[:n]), string(expectedEcho))
	}
	if rAddr.String() != targetAddrStr {
		t.Fatalf("UDP rAddr mismatch: got %q, want %q", rAddr.String(), targetAddrStr)
	}

	// 2. Test WaitReadFrom if EnhancePacketConn
	if waitPC, ok := pc.(interface {
		WaitReadFrom() ([]byte, func(), net.Addr, error)
	}); ok {
		reqPayload2 := []byte("Real SSR UDP packet payload #2 via WaitReadFrom")
		_, err = pc.WriteTo(reqPayload2, destAddr)
		if err != nil {
			t.Fatalf("pc.WriteTo #2 failed: %v", err)
		}

		data, put, rAddr2, err := waitPC.WaitReadFrom()
		if err != nil {
			t.Fatalf("waitPC.WaitReadFrom failed: %v", err)
		}
		if put != nil {
			defer put()
		}

		expectedEcho2 := append([]byte("UDP-ECHO:"), reqPayload2...)
		if !bytes.Equal(data, expectedEcho2) {
			t.Fatalf("WaitReadFrom payload mismatch: got %q, want %q", string(data), string(expectedEcho2))
		}
		if rAddr2.String() != targetAddrStr {
			t.Fatalf("WaitReadFrom rAddr mismatch: got %q, want %q", rAddr2.String(), targetAddrStr)
		}
	}
}

// Test 1: Real Local TCP for Every Single Protocol x Obfs
func TestSSRProtocolsAndObfsTCP(t *testing.T) {
	protocols := []string{
		"origin",
		"auth_sha1_v4",
		"auth_aes128_md5",
		"auth_aes128_sha1",
		"auth_chain_a",
		"auth_chain_b",
	}

	obfsList := []string{
		"plain",
		"http_simple",
		"http_post",
		"random_head",
		"tls1.2_ticket_auth",
		"tls1.2_ticket_fastauth",
	}

	for _, proto := range protocols {
		for _, obfs := range obfsList {
			name := fmt.Sprintf("%s_%s", proto, obfs)
			t.Run(name, func(t *testing.T) {
				cfg := SSRServerConfig{
					Method:        "aes-128-cfb",
					Password:      "test-protocol-obfs-pwd",
					Obfs:          obfs,
					ObfsParam:     "bing.com",
					Protocol:      proto,
					ProtocolParam: "1234:paramkey",
				}
				runRealTCPTest(t, cfg)
			})
		}
	}
}

// Test 2: Real Local TCP for Every Single Cipher (all 35+ stream ciphers + dummy/none/plain + aliases)
func TestSSRAllCiphersTCP(t *testing.T) {
	ciphers := core.ListCipher()
	ciphers = append(ciphers, "DUMMY", "NONE", "PLAIN", "BLOWFISH-CFB", "BLOWFISH", "AES-128", "AES-192", "AES-256")

	for _, ciph := range ciphers {
		t.Run(ciph, func(t *testing.T) {
			cfg := SSRServerConfig{
				Method:        ciph,
				Password:      "test-cipher-password-999",
				Obfs:          "plain",
				Protocol:      "origin",
				ProtocolParam: "",
			}
			runRealTCPTest(t, cfg)
		})
	}
}

// Test 3: Real Local UDP for All Protocols and Major Ciphers
func TestSSRAllProtocolsAndCiphersUDP(t *testing.T) {
	protocols := []string{
		"origin",
		"auth_sha1_v4",
		"auth_aes128_md5",
		"auth_aes128_sha1",
		"auth_chain_a",
		"auth_chain_b",
	}

	ciphers := []string{
		"none",
		"aes-256-cfb",
		"rc4-md5",
		"chacha20-ietf",
		"aes-128-ctr",
	}

	targetAddresses := []string{
		"127.0.0.1:53",
		"dns.google:53",
	}

	for _, proto := range protocols {
		for _, ciph := range ciphers {
			for _, target := range targetAddresses {
				testName := fmt.Sprintf("%s_%s_%s", proto, ciph, target)
				t.Run(testName, func(t *testing.T) {
					cfg := SSRServerConfig{
						Method:        ciph,
						Password:      "test-udp-pwd-888",
						Obfs:          "plain",
						Protocol:      proto,
						ProtocolParam: "5678:udpuserkey",
					}
					runRealUDPTest(t, cfg, target)
				})
			}
		}
	}
}

// Test 4: Real Local Exhaustive Popular Combinations with Both TCP and UDP
func TestSSRExhaustivePopularCombinations(t *testing.T) {
	combos := []struct {
		name          string
		method        string
		password      string
		obfs          string
		obfsParam     string
		protocol      string
		protocolParam string
	}{
		{
			name:          "Classic_RC4MD5_AuthChainA_TLS12",
			method:        "rc4-md5",
			password:      "password_classic",
			obfs:          "tls1.2_ticket_auth",
			obfsParam:     "cloudflare.com",
			protocol:      "auth_chain_a",
			protocolParam: "1001:classic_secret",
		},
		{
			name:          "Modern_ChaCha20_AuthChainB_TLS12FastAuth",
			method:        "chacha20-ietf",
			password:      "password_modern",
			obfs:          "tls1.2_ticket_fastauth",
			obfsParam:     "microsoft.com",
			protocol:      "auth_chain_b",
			protocolParam: "1002:modern_secret",
		},
		{
			name:          "Standard_AES256CFB_AuthAES128MD5_HTTPSimple",
			method:        "aes-256-cfb",
			password:      "password_http",
			obfs:          "http_simple",
			obfsParam:     "bing.com",
			protocol:      "auth_aes128_md5",
			protocolParam: "1003:http_secret",
		},
		{
			name:          "HighPerf_AES128CTR_AuthAES128SHA1_HTTPPost",
			method:        "aes-128-ctr",
			password:      "password_post",
			obfs:          "http_post",
			obfsParam:     "amazon.com",
			protocol:      "auth_aes128_sha1",
			protocolParam: "1004:post_secret",
		},
		{
			name:          "Camellia_AuthSHA1V4_RandomHead",
			method:        "camellia-256-cfb",
			password:      "password_camellia",
			obfs:          "random_head",
			obfsParam:     "",
			protocol:      "auth_sha1_v4",
			protocolParam: "",
		},
		{
			name:          "Plain_Origin_None",
			method:        "none",
			password:      "password_none",
			obfs:          "plain",
			obfsParam:     "",
			protocol:      "origin",
			protocolParam: "",
		},
	}

	for _, combo := range combos {
		t.Run("TCP_"+combo.name, func(t *testing.T) {
			cfg := SSRServerConfig{
				Method:        combo.method,
				Password:      combo.password,
				Obfs:          combo.obfs,
				ObfsParam:     combo.obfsParam,
				Protocol:      combo.protocol,
				ProtocolParam: combo.protocolParam,
			}
			runRealTCPTest(t, cfg)
		})

		t.Run("UDP_"+combo.name, func(t *testing.T) {
			cfg := SSRServerConfig{
				Method:        combo.method,
				Password:      combo.password,
				Obfs:          combo.obfs,
				ObfsParam:     combo.obfsParam,
				Protocol:      combo.protocol,
				ProtocolParam: combo.protocolParam,
			}
			runRealUDPTest(t, cfg, "8.8.8.8:53")
		})
	}
}

package ssr

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/socks5"
)

type mockEnhancePacketConn struct {
	data []byte
	addr net.Addr
}

func (m *mockEnhancePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	copy(b, m.data)
	return len(m.data), m.addr, nil
}

func (m *mockEnhancePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return len(b), nil
}

func (m *mockEnhancePacketConn) Close() error                       { return nil }
func (m *mockEnhancePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (m *mockEnhancePacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockEnhancePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockEnhancePacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockEnhancePacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	d := make([]byte, len(m.data))
	copy(d, m.data)
	return d, func() {}, m.addr, nil
}

func TestSSPacketConn(t *testing.T) {
	// 1. Test IPv4 UDP Packet ReadFrom and WaitReadFrom
	ipv4SocksAddr := socks5.ParseAddr("1.2.3.4:8388")
	payload := []byte("hello udp")
	ipv4Packet := append([]byte(nil), ipv4SocksAddr...)
	ipv4Packet = append(ipv4Packet, payload...)

	mockConn := &mockEnhancePacketConn{
		data: ipv4Packet,
		addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 8388},
	}
	spc := &ssPacketConn{
		EnhancePacketConn: mockConn,
		rAddr:             mockConn.addr,
	}

	buf := make([]byte, 1024)
	n, rAddr, err := spc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom ipv4 failed: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("ReadFrom ipv4 expected payload %s, got %s", payload, buf[:n])
	}
	if udpAddr, ok := rAddr.(*net.UDPAddr); !ok || udpAddr.String() != "1.2.3.4:8388" {
		t.Fatalf("ReadFrom ipv4 expected *net.UDPAddr 1.2.3.4:8388, got %v (%T)", rAddr, rAddr)
	}

	// WaitReadFrom IPv4
	data, put, rAddr, err := spc.WaitReadFrom()
	if err != nil {
		t.Fatalf("WaitReadFrom ipv4 failed: %v", err)
	}
	if put != nil {
		put()
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("WaitReadFrom ipv4 expected payload %s, got %s", payload, data)
	}
	if udpAddr, ok := rAddr.(*net.UDPAddr); !ok || udpAddr.String() != "1.2.3.4:8388" {
		t.Fatalf("WaitReadFrom ipv4 expected *net.UDPAddr 1.2.3.4:8388, got %v (%T)", rAddr, rAddr)
	}

	// 2. Test Domain UDP Packet ReadFrom and WaitReadFrom (the branch fixed for SA4023)
	domainSocksAddr := socks5.ParseAddr("domain.example.com:9999")
	domainPayload := []byte("domain udp data")
	domainPacket := append([]byte(nil), domainSocksAddr...)
	domainPacket = append(domainPacket, domainPayload...)

	mockConn.data = domainPacket
	n, rAddr, err = spc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom domain failed: %v", err)
	}
	if !bytes.Equal(buf[:n], domainPayload) {
		t.Fatalf("ReadFrom domain expected payload %s, got %s", domainPayload, buf[:n])
	}
	if rAddr.String() != "domain.example.com:9999" {
		t.Fatalf("ReadFrom domain expected address domain.example.com:9999, got %s", rAddr.String())
	}

	// WaitReadFrom Domain
	data, put, rAddr, err = spc.WaitReadFrom()
	if err != nil {
		t.Fatalf("WaitReadFrom domain failed: %v", err)
	}
	if put != nil {
		put()
	}
	if !bytes.Equal(data, domainPayload) {
		t.Fatalf("WaitReadFrom domain expected payload %s, got %s", domainPayload, data)
	}
	if rAddr.String() != "domain.example.com:9999" {
		t.Fatalf("WaitReadFrom domain expected address domain.example.com:9999, got %s", rAddr.String())
	}

	// 3. Test WriteTo
	wN, err := spc.WriteTo([]byte("test write"), &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 8388})
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if wN != len("test write") {
		t.Fatalf("WriteTo expected %d, got %d", len("test write"), wN)
	}
}

func TestNewOutbound(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		password      string
		obfs          string
		obfsParam     string
		protocol      string
		protocolParam string
	}{
		{
			name:     "plain_origin",
			method:   "aes-256-cfb",
			password: "password",
			obfs:     "plain",
			protocol: "origin",
		},
		{
			name:     "dummy_none",
			method:   "none",
			password: "password",
			obfs:     "plain",
			protocol: "origin",
		},
		{
			name:          "tls1.2_auth_chain_a",
			method:        "rc4-md5",
			password:      "pass123",
			obfs:          "tls1.2_ticket_auth",
			obfsParam:     "cloudflare.com",
			protocol:      "auth_chain_a",
			protocolParam: "12:secret",
		},
		{
			name:          "http_simple_auth_aes128_sha1",
			method:        "chacha20-ietf",
			password:      "pass456",
			obfs:          "http_simple",
			obfsParam:     "bing.com",
			protocol:      "auth_aes128_sha1",
			protocolParam: "34:secret2",
		},
		{
			name:     "auth_chain_b",
			method:   "aes-128-ctr",
			password: "pass789",
			obfs:     "plain",
			protocol: "auth_chain_b",
		},
		{
			name:     "compatible_suffixes",
			method:   "plain",
			password: "password",
			obfs:     "tls1.2_ticket_auth_compatible",
			protocol: "auth_sha1_v4_compatible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := pluginoption.SSROutboundOptions{
				Server:        "127.0.0.1",
				ServerPort:    8388,
				Method:        tt.method,
				Password:      tt.password,
				Obfs:          tt.obfs,
				ObfsParam:     tt.obfsParam,
				Protocol:      tt.protocol,
				ProtocolParam: tt.protocolParam,
			}
			out, err := NewOutbound(context.Background(), nil, nil, "ssr-tag", opts)
			if err != nil {
				t.Fatalf("NewOutbound failed: %v", err)
			}
			if out == nil {
				t.Fatalf("NewOutbound returned nil")
			}
		})
	}
}

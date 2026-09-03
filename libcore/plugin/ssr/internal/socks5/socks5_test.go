package socks5

import (
	"bytes"
	"net"
	"testing"
)

func TestSocks5Addr(t *testing.T) {
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 8080,
	}

	socksAddr := ParseAddrToSocksAddr(udpAddr)
	if socksAddr == nil {
		t.Fatalf("ParseAddrToSocksAddr returned nil")
	}

	parsedUDP := socksAddr.UDPAddr()
	if parsedUDP == nil {
		t.Fatalf("UDPAddr() returned nil")
	}

	if !parsedUDP.IP.Equal(udpAddr.IP) || parsedUDP.Port != udpAddr.Port {
		t.Fatalf("got %v, want %v", parsedUDP, udpAddr)
	}

	payload := []byte("hello udp")
	pkt, err := EncodeUDPPacket(socksAddr, payload)
	if err != nil {
		t.Fatalf("EncodeUDPPacket error: %v", err)
	}

	split := SplitAddr(pkt[3:])
	if !bytes.Equal(split, socksAddr) {
		t.Fatalf("SplitAddr mismatch")
	}
}

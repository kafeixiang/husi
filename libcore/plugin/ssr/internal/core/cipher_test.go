package core

import (
	"bytes"
	"net"
	"testing"
)

func TestPickCipher(t *testing.T) {
	ciphers := []string{
		"DUMMY",
		"AES-128-CTR",
		"AES-192-CTR",
		"AES-256-CTR",
		"AES-128-CFB",
		"AES-192-CFB",
		"AES-256-CFB",
		"AES-128-CFB8",
		"AES-192-CFB8",
		"AES-256-CFB8",
		"AES-128-OFB",
		"AES-192-OFB",
		"AES-256-OFB",
		"CAMELLIA-128-CFB",
		"CAMELLIA-192-CFB",
		"CAMELLIA-256-CFB",
		"CAMELLIA-128-CFB8",
		"CAMELLIA-192-CFB8",
		"CAMELLIA-256-CFB8",
		"RC4-MD5",
		"RC4-MD5-6",
		"RC4",
		"BF-CFB",
		"CAST5-CFB",
		"DES-CFB",
		"IDEA-CFB",
		"RC2-CFB",
		"SEED-CFB",
		"CHACHA20-IETF",
		"XCHACHA20",
		"CHACHA20",
		"XSALSA20",
		"SALSA20",
		"TABLE",
		"RABBIT",
		"HC128",
		"ZUC128",
	}

	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			c, err := PickCipher(name, nil, "password")
			if err != nil {
				t.Fatalf("PickCipher(%s) error: %v", name, err)
			}
			if c == nil {
				t.Fatalf("PickCipher(%s) returned nil cipher", name)
			}
		})
	}

	_, err := PickCipher("INVALID_CIPHER", nil, "password")
	if err == nil {
		t.Fatalf("expected error for invalid cipher")
	}
}

func TestStreamConnDummy(t *testing.T) {
	c, err := PickCipher("DUMMY", nil, "password")
	if err != nil {
		t.Fatalf("PickCipher error: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	wrapped := c.StreamConn(clientConn)

	msg := []byte("hello ssr dummy")
	go func() {
		wrapped.Write(msg)
	}()

	buf := make([]byte, 100)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("got %s, want %s", buf[:n], msg)
	}
}

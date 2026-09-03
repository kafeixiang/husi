package shadowstream

import (
	"bytes"
	"net"
	"testing"
)

func TestShadowstreamConn(t *testing.T) {
	ciphers := []struct {
		name string
		ctor func([]byte) (Cipher, error)
		size int
	}{
		{"AESCTR", AESCTR, 16},
		{"AESCFB", AESCFB, 16},
		{"RC4MD5", RC4MD5, 16},
		{"ChaCha20", ChaCha20, 32},
		{"Chacha20IETF", Chacha20IETF, 32},
		{"Xchacha20", Xchacha20, 32},
		{"Table", Table, 16},
	}

	key := bytes.Repeat([]byte("k"), 32)

	for _, tc := range ciphers {
		t.Run(tc.name, func(t *testing.T) {
			ciph, err := tc.ctor(key[:tc.size])
			if err != nil {
				t.Fatalf("ctor error: %v", err)
			}

			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			sConn := NewConn(serverConn, ciph)
			cConn := NewConn(clientConn, ciph)

			msg := []byte("hello shadowstream encryption test")

			errCh := make(chan error, 1)
			go func() {
				_, err := cConn.Write(msg)
				errCh <- err
			}()

			buf := make([]byte, 100)
			n, err := sConn.Read(buf)
			if err != nil {
				t.Fatalf("Read error: %v", err)
			}
			if writeErr := <-errCh; writeErr != nil {
				t.Fatalf("Write error: %v", writeErr)
			}

			if !bytes.Equal(buf[:n], msg) {
				t.Fatalf("got %s, want %s", buf[:n], msg)
			}
		})
	}
}

package core

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestAllCiphersStreamRoundTrip(t *testing.T) {
	ciphers := ListCipher()
	ciphers = append(ciphers, "DUMMY", "NONE", "PLAIN", "BLOWFISH-CFB", "BLOWFISH", "AES-128", "AES-192", "AES-256")

	password := "test-secret-password-123456"
	testPayload := []byte("Hello ShadowsocksR World! Testing full stream roundtrip for all ciphers. 1234567890!@#$%^&*()")

	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			clientCipher, err := PickCipher(name, nil, password)
			if err != nil {
				t.Fatalf("PickCipher client failed for %s: %v", name, err)
			}
			serverCipher, err := PickCipher(name, nil, password)
			if err != nil {
				t.Fatalf("PickCipher server failed for %s: %v", name, err)
			}

			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()

			clientConn := clientCipher.StreamConn(clientRaw)
			serverConn := serverCipher.StreamConn(serverRaw)

			// Client -> Server
			errCh := make(chan error, 1)
			go func() {
				_, writeErr := clientConn.Write(testPayload)
				errCh <- writeErr
			}()

			recvBuf := make([]byte, len(testPayload))
			_, readErr := io.ReadFull(serverConn, recvBuf)
			if readErr != nil {
				t.Fatalf("[%s] server read failed: %v", name, readErr)
			}
			if writeErr := <-errCh; writeErr != nil {
				t.Fatalf("[%s] client write failed: %v", name, writeErr)
			}
			if !bytes.Equal(recvBuf, testPayload) {
				t.Fatalf("[%s] payload mismatch: got %v, want %v", name, recvBuf, testPayload)
			}

			// Server -> Client
			serverPayload := []byte("Server response: stream roundtrip acknowledged!")
			go func() {
				_, writeErr := serverConn.Write(serverPayload)
				errCh <- writeErr
			}()

			clientRecvBuf := make([]byte, len(serverPayload))
			_, readErr = io.ReadFull(clientConn, clientRecvBuf)
			if readErr != nil {
				t.Fatalf("[%s] client read from server failed: %v", name, readErr)
			}
			if writeErr := <-errCh; writeErr != nil {
				t.Fatalf("[%s] server write failed: %v", name, writeErr)
			}
			if !bytes.Equal(clientRecvBuf, serverPayload) {
				t.Fatalf("[%s] server->client payload mismatch: got %v, want %v", name, clientRecvBuf, serverPayload)
			}
		})
	}
}

func TestAllCiphersPacketRoundTrip(t *testing.T) {
	ciphers := ListCipher()
	ciphers = append(ciphers, "DUMMY", "NONE", "PLAIN", "BLOWFISH-CFB", "BLOWFISH", "AES-128", "AES-192", "AES-256")

	password := "test-secret-password-123456"

	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			clientCipher, err := PickCipher(name, nil, password)
			if err != nil {
				t.Fatalf("PickCipher client failed for %s: %v", name, err)
			}
			serverCipher, err := PickCipher(name, nil, password)
			if err != nil {
				t.Fatalf("PickCipher server failed for %s: %v", name, err)
			}

			// Test packet encryption / decryption with different sizes: 1, 10, 100, 1400 bytes
			sizes := []int{1, 10, 64, 512, 1400}
			for _, size := range sizes {
				plain := make([]byte, size)
				_, _ = rand.Read(plain)

				// If StreamCipher, we can test shadowstream pack / unpack
				streamCiph, ok := clientCipher.(*StreamCipher)
				if !ok {
					// Dummy cipher
					continue
				}

				dst := make([]byte, streamCiph.IVSize()+len(plain))
				packed, err := streamCiph.Encrypter(dst[:streamCiph.IVSize()]).(interface {
					XORKeyStream(dst, src []byte)
				}), error(nil)
				_ = packed
				_ = err

				// Using shadowstream Conn or Packet functions:
				// Client packs:
				serverStreamCiph := serverCipher.(*StreamCipher)
				iv := make([]byte, streamCiph.IVSize())
				_, _ = rand.Read(iv)
				encrypted := make([]byte, len(plain))
				streamCiph.Encrypter(iv).XORKeyStream(encrypted, plain)

				// Server unpacks:
				decrypted := make([]byte, len(encrypted))
				serverStreamCiph.Decrypter(iv).XORKeyStream(decrypted, encrypted)

				if !bytes.Equal(decrypted, plain) {
					t.Fatalf("[%s size=%d] packet roundtrip mismatch", name, size)
				}
			}
		})
	}
}

package trojango

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"

	"github.com/stretchr/testify/require"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/pluginoption"
)

func TestSSCipherRoundTrip(t *testing.T) {
	ciphers := []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
	}

	for _, method := range ciphers {
		t.Run(method, func(t *testing.T) {
			serverSideCipher, err := NewSSCipher(method, "test_password_123")
			require.NoError(t, err)

			clientSideCipher, err := NewSSCipher(method, "test_password_123")
			require.NoError(t, err)

			cConn, sConn := net.Pipe()
			defer cConn.Close()
			defer sConn.Close()

			clientStream := clientSideCipher.StreamConn(cConn)
			serverStream := serverSideCipher.StreamConn(sConn)

			testMessage := []byte("Hello Trojan-Go with Shadowsocks AEAD secondary encryption!")

			errChan := make(chan error, 1)
			go func() {
				_, writeErr := clientStream.Write(testMessage)
				errChan <- writeErr
			}()

			buf := make([]byte, len(testMessage))
			_, readErr := io.ReadFull(serverStream, buf)
			require.NoError(t, readErr)
			require.Equal(t, testMessage, buf)

			require.NoError(t, <-errChan)
		})
	}
}

func TestMuxHandshakeAndStream(t *testing.T) {
	password := "my_mux_password"
	key := trojan.Key(password)

	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	dest := M.ParseSocksaddr("example.com:443")

	errChan := make(chan error, 1)

	// Mock Trojan-Go Server accepting MUX connection
	go func() {
		// Read 56 bytes key
		k := make([]byte, trojan.KeyLength)
		if _, err := io.ReadFull(sConn, k); err != nil {
			errChan <- err
			return
		}
		// Read CRLF
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(sConn, crlf); err != nil {
			errChan <- err
			return
		}
		// Read Command (0x7f)
		cmd := make([]byte, 1)
		if _, err := io.ReadFull(sConn, cmd); err != nil {
			errChan <- err
			return
		}
		if cmd[0] != trojan.CommandMux {
			errChan <- net.ErrClosed
			return
		}
		// Read target address (MUX_CONN:0)
		target, err := M.SocksaddrSerializer.ReadAddrPort(sConn)
		if err != nil {
			errChan <- err
			return
		}
		if target.Fqdn != "MUX_CONN" {
			errChan <- net.ErrClosed
			return
		}
		// Read CRLF
		if _, err := io.ReadFull(sConn, crlf); err != nil {
			errChan <- err
			return
		}

		// Server smux session
		cfg := smux.DefaultConfig()
		cfg.KeepAliveDisabled = true
		serverSession, err := smux.Server(sConn, cfg)
		if err != nil {
			errChan <- err
			return
		}
		defer serverSession.Close()

		stream, err := serverSession.AcceptStream()
		if err != nil {
			errChan <- err
			return
		}
		defer stream.Close()

		// Read simplesocks TCP command
		sCmd := make([]byte, 1)
		if _, err := io.ReadFull(stream, sCmd); err != nil {
			errChan <- err
			return
		}
		if sCmd[0] != trojan.CommandTCP {
			errChan <- net.ErrClosed
			return
		}
		dst, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			errChan <- err
			return
		}
		if dst.String() != dest.String() {
			errChan <- net.ErrClosed
			return
		}

		// Echo back data
		payload := make([]byte, 5)
		if _, err := io.ReadFull(stream, payload); err != nil {
			errChan <- err
			return
		}
		_, err = stream.Write(bytes.ToUpper(payload))
		errChan <- err
	}()

	// Client side
	err := trojan.ClientHandshakeRaw(cConn, key, trojan.CommandMux, M.Socksaddr{Fqdn: "MUX_CONN", Port: 0}, nil)
	require.NoError(t, err)

	cfg := smux.DefaultConfig()
	cfg.KeepAliveDisabled = true
	clientSession, err := smux.Client(cConn, cfg)
	require.NoError(t, err)
	defer clientSession.Close()

	stream, err := clientSession.OpenStream()
	require.NoError(t, err)
	defer stream.Close()

	// Simplesocks TCP header
	_, err = stream.Write([]byte{trojan.CommandTCP})
	require.NoError(t, err)
	err = M.SocksaddrSerializer.WriteAddrPort(stream, dest)
	require.NoError(t, err)

	_, err = stream.Write([]byte("hello"))
	require.NoError(t, err)

	resp := make([]byte, 5)
	_, err = io.ReadFull(stream, resp)
	require.NoError(t, err)
	require.Equal(t, "HELLO", string(resp))

	require.NoError(t, <-errChan)
}

func TestRegisterOutbound(t *testing.T) {
	registry := outbound.NewRegistry()
	RegisterOutbound(registry)
	_, loaded := registry.CreateOptions(pluginoption.TypeTrojanGo)
	require.True(t, loaded)
}

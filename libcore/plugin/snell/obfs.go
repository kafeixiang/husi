package snell

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type obfsConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *obfsConn) Read(b []byte) (int, error) {
	if c.reader != nil {
		n, err := c.reader.Read(b)
		if n > 0 && c.reader.Buffered() == 0 {
			c.reader = nil
		}
		return n, err
	}
	return c.Conn.Read(b)
}

func NewObfsConn(conn net.Conn, mode string, host string) (net.Conn, error) {
	if strings.EqualFold(mode, "http") {
		return newHttpObfsConn(conn, host)
	}
	// Snell obfs=tls is handled by the transport layer TLS dialer in NewOutbound
	return conn, nil
}

func newHttpObfsConn(conn net.Conn, host string) (net.Conn, error) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host
	} else {
		req.Host = conn.RemoteAddr().String()
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	err = req.Write(conn)
	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return &obfsConn{Conn: conn, reader: br}, nil
}

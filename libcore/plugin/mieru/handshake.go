package mieru

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
)

// PostDialHandshake completes the handshake after API client is connected to a server.
func PostDialHandshake(conn net.Conn, destination model.NetAddrSpec) (*model.Response, error) {
	req := &model.Request{
		DstAddr: destination.AddrSpec,
	}
	isTCP := strings.HasPrefix(destination.Network(), "tcp")
	isUDP := strings.HasPrefix(destination.Network(), "udp")
	if isTCP {
		req.Command = constant.Socks5ConnectCmd
	} else if isUDP {
		req.Command = constant.Socks5UDPAssociateCmd
	} else {
		return nil, fmt.Errorf("unsupported network type %s", destination.Network())
	}
	if err := req.WriteToSocks5(conn); err != nil {
		return nil, fmt.Errorf("failed to write socks5 connection request to the server: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	resp := &model.Response{}
	if err := resp.ReadFromSocks5(conn); err != nil {
		return nil, fmt.Errorf("failed to read socks5 connection response from the server: %w", err)
	}
	if resp.Reply != 0 {
		return nil, fmt.Errorf("server returned socks5 error code %d", resp.Reply)
	}
	return resp, nil
}

package obfs

import (
	"errors"
	"fmt"
	"net"
)

var (
	ErrTLS12TicketAuthIncorrectMagicNumber = errors.New("tls1.2_ticket_auth incorrect magic number")
	ErrTLS12TicketAuthTooShortData         = errors.New("tls1.2_ticket_auth too short data")
	ErrTLS12TicketAuthHMACError            = errors.New("tls1.2_ticket_auth hmac verifying failed")
)

type Obfs interface {
	StreamConn(net.Conn) net.Conn
}

type Creator func(b *Base) Obfs

var obfsList = make(map[string]struct {
	overhead int
	new      Creator
})

func register(name string, c Creator, o int) {
	obfsList[name] = struct {
		overhead int
		new      Creator
	}{overhead: o, new: c}
}

func PickObfs(name string, b *Base) (Obfs, int, error) {
	if choice, ok := obfsList[name]; ok {
		return choice.new(b), choice.overhead, nil
	}
	return nil, 0, fmt.Errorf("Obfs %s not supported", name)
}

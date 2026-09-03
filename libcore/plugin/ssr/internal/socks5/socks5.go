package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

type Addr []byte

func (a Addr) String() string {
	var host, port string

	switch a[0] {
	case AtypDomainName:
		hostLen := uint16(a[1])
		host = string(a[2 : 2+hostLen])
		port = strconv.Itoa((int(a[2+hostLen]) << 8) | int(a[2+hostLen+1]))
	case AtypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case AtypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}

	return net.JoinHostPort(host, port)
}

func (a Addr) UDPAddr() *net.UDPAddr {
	if len(a) == 0 {
		return nil
	}
	switch a[0] {
	case AtypIPv4:
		var ip [net.IPv4len]byte
		copy(ip[0:], a[1:1+net.IPv4len])
		return &net.UDPAddr{IP: net.IP(ip[:]), Port: int(binary.BigEndian.Uint16(a[1+net.IPv4len : 1+net.IPv4len+2]))}
	case AtypIPv6:
		var ip [net.IPv6len]byte
		copy(ip[0:], a[1:1+net.IPv6len])
		return &net.UDPAddr{IP: net.IP(ip[:]), Port: int(binary.BigEndian.Uint16(a[1+net.IPv6len : 1+net.IPv6len+2]))}
	}
	return nil
}

func SplitAddr(b []byte) Addr {
	addrLen := 1
	if len(b) < addrLen {
		return nil
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 2 {
			return nil
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = 1 + net.IPv4len + 2
	case AtypIPv6:
		addrLen = 1 + net.IPv6len + 2
	default:
		return nil
	}

	if len(b) < addrLen {
		return nil
	}

	return b[:addrLen]
}

func ParseAddr(s string) Addr {
	var addr Addr
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = AtypIPv4
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = AtypIPv6
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil
		}
		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = AtypDomainName
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}

	addr[len(addr)-2], addr[len(addr)-1] = byte(portnum>>8), byte(portnum)

	return addr
}

func ParseAddrToSocksAddr(addr net.Addr) Addr {
	var hostip net.IP
	var port int
	switch addr := addr.(type) {
	case *net.UDPAddr:
		hostip = addr.IP
		port = addr.Port
	case *net.TCPAddr:
		hostip = addr.IP
		port = addr.Port
	case nil:
		return nil
	}

	if hostip == nil {
		return ParseAddr(addr.String())
	}

	var parsed Addr
	if ip4 := hostip.To4(); ip4.DefaultMask() != nil {
		parsed = make([]byte, 1+net.IPv4len+2)
		parsed[0] = AtypIPv4
		copy(parsed[1:], ip4)
		binary.BigEndian.PutUint16(parsed[1+net.IPv4len:], uint16(port))
	} else {
		parsed = make([]byte, 1+net.IPv6len+2)
		parsed[0] = AtypIPv6
		copy(parsed[1:], hostip)
		binary.BigEndian.PutUint16(parsed[1+net.IPv6len:], uint16(port))
	}
	return parsed
}

func EncodeUDPPacket(addr Addr, payload []byte) (packet []byte, err error) {
	if addr == nil {
		err = errors.New("address is invalid")
		return
	}
	packet = bytes.Join([][]byte{{0, 0, 0}, addr, payload}, []byte{})
	return
}

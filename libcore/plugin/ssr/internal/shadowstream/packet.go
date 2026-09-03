package shadowstream

import (
	"crypto/rand"
	"errors"
	"io"
	"net"

	N "github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/net"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/pool"
)

var ErrShortPacket = errors.New("short packet")

func Pack(dst, plaintext []byte, s Cipher) ([]byte, error) {
	if len(dst) < s.IVSize()+len(plaintext) {
		return nil, io.ErrShortBuffer
	}
	iv := dst[:s.IVSize()]
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	s.Encrypter(iv).XORKeyStream(dst[len(iv):], plaintext)
	return dst[:len(iv)+len(plaintext)], nil
}

func UnpackInplace(pkt []byte, s Cipher) ([]byte, error) {
	if len(pkt) < s.IVSize() {
		return nil, ErrShortPacket
	}
	iv, dst := pkt[:s.IVSize()], pkt[s.IVSize():]
	s.Decrypter(iv).XORKeyStream(dst, dst)
	return dst, nil
}

func Unpack(dst, pkt []byte, s Cipher) ([]byte, error) {
	if len(pkt) < s.IVSize() {
		return nil, ErrShortPacket
	}
	if len(dst) < len(pkt)-s.IVSize() {
		return nil, io.ErrShortBuffer
	}
	iv := pkt[:s.IVSize()]
	s.Decrypter(iv).XORKeyStream(dst, pkt[len(iv):])
	return dst[:len(pkt)-len(iv)], nil
}

type PacketConn struct {
	N.EnhancePacketConn
	Cipher
}

func NewPacketConn(c N.EnhancePacketConn, ciph Cipher) *PacketConn {
	return &PacketConn{EnhancePacketConn: c, Cipher: ciph}
}

const maxPacketSize = 64 * 1024

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := pool.Get(maxPacketSize)
	defer pool.Put(buf)
	buf, err := Pack(buf, b, c.Cipher)
	if err != nil {
		return 0, err
	}
	_, err = c.EnhancePacketConn.WriteTo(buf, addr)
	return len(b), err
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.EnhancePacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := UnpackInplace(b[:n], c.Cipher)
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return len(bb), addr, err
}

func (c *PacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, addr, err = c.EnhancePacketConn.WaitReadFrom()
	if err != nil {
		return
	}
	data, err = UnpackInplace(data, c.Cipher)
	if err != nil {
		if put != nil {
			put()
		}
		data = nil
		put = nil
		return
	}
	return
}

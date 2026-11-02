package obfs

import (
	"bytes"
	"crypto/hmac"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	randv2 "math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/pool"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/tools"
)

func init() {
	register("tls1.2_ticket_auth", newTLS12Ticket, 5)
	register("tls1.2_ticket_fastauth", newTLS12TicketFastAuth, 5)
}

type tls12Ticket struct {
	*Base
	*authData
	fastauth bool
}

func newTLS12Ticket(b *Base) Obfs {
	r := &tls12Ticket{Base: b, authData: &authData{}}
	_, _ = crand.Read(r.clientID[:])
	return r
}

func newTLS12TicketFastAuth(b *Base) Obfs {
	r := &tls12Ticket{Base: b, authData: &authData{}, fastauth: true}
	_, _ = crand.Read(r.clientID[:])
	return r
}

type tls12TicketConn struct {
	net.Conn
	*tls12Ticket
	handshakeStatus     int
	serverHandshakeDone bool
	handshakeBuf        bytes.Buffer
	decoded             bytes.Buffer
	underDecoded        bytes.Buffer
	sendBuf             bytes.Buffer
}

func (t *tls12Ticket) StreamConn(c net.Conn) net.Conn {
	return &tls12TicketConn{Conn: c, tls12Ticket: t}
}

func (c *tls12TicketConn) parseServerHandshake(data []byte) (int, error) {
	if len(data) < 11+32+1+32 {
		return 0, nil
	}
	if data[0] != 0x16 || data[1] != 3 {
		return 0, errTLS12TicketAuthIncorrectMagicNumber
	}
	offset := 0
	sawCCS := false
	sawFinished := false
	for offset+5 <= len(data) {
		recType := data[offset]
		recLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if offset+5+recLen > len(data) {
			return 0, nil
		}
		offset += 5 + recLen
		if recType == 0x14 {
			sawCCS = true
		} else if sawCCS && recType == 0x16 {
			sawFinished = true
			break
		}
	}
	if !sawFinished {
		return 0, nil
	}
	totalHandshakeLen := offset

	if !hmac.Equal(data[33:43], c.hmacSHA1(data[11:33])[:10]) {
		return 0, fmt.Errorf("%w: verify hmac mismatch got %x want %x", errTLS12TicketAuthHMACError, data[33:43], c.hmacSHA1(data[11:33])[:10])
	}
	expectedHMAC := c.hmacSHA1(data[:offset-10])[:10]
	actualHMAC := data[offset-10 : offset]
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		return 0, fmt.Errorf("%w: total hmac mismatch got %x want %x offset=%d dataLen=%d", errTLS12TicketAuthHMACError, actualHMAC, expectedHMAC, offset, len(data))
	}
	return totalHandshakeLen, nil
}

func (c *tls12TicketConn) Read(b []byte) (int, error) {
	if c.decoded.Len() > 0 {
		return c.decoded.Read(b)
	}

	for !c.serverHandshakeDone {
		if c.handshakeBuf.Len() > 0 {
			consumed, err := c.parseServerHandshake(c.handshakeBuf.Bytes())
			if err != nil {
				return 0, err
			}
			if consumed > 0 {
				rem := c.handshakeBuf.Bytes()[consumed:]
				if len(rem) > 0 {
					c.underDecoded.Write(rem)
				}
				c.handshakeBuf.Reset()
				c.serverHandshakeDone = true
				if !c.fastauth {
					_, _ = c.Write(nil)
				}
				break
			}
		}

		buf := pool.Get(pool.RelayBufferSize)
		n, err := c.Conn.Read(buf)
		if n > 0 {
			c.handshakeBuf.Write(buf[:n])
		}
		pool.Put(buf)
		if err != nil {
			return 0, err
		}
	}

	for c.underDecoded.Len() > 5 {
		if !bytes.Equal(c.underDecoded.Bytes()[:3], []byte{0x17, 3, 3}) {
			c.underDecoded.Reset()
			return 0, errTLS12TicketAuthIncorrectMagicNumber
		}
		size := int(binary.BigEndian.Uint16(c.underDecoded.Bytes()[3:5]))
		if c.underDecoded.Len() < 5+size {
			break
		}
		c.underDecoded.Next(5)
		c.decoded.Write(c.underDecoded.Next(size))
	}
	if c.decoded.Len() > 0 {
		return c.decoded.Read(b)
	}

	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	c.underDecoded.Write(buf[:n])
	for c.underDecoded.Len() > 5 {
		if !bytes.Equal(c.underDecoded.Bytes()[:3], []byte{0x17, 3, 3}) {
			c.underDecoded.Reset()
			return 0, errTLS12TicketAuthIncorrectMagicNumber
		}
		size := int(binary.BigEndian.Uint16(c.underDecoded.Bytes()[3:5]))
		if c.underDecoded.Len() < 5+size {
			break
		}
		c.underDecoded.Next(5)
		c.decoded.Write(c.underDecoded.Next(size))
	}
	return c.decoded.Read(b)
}

func (c *tls12TicketConn) Write(b []byte) (int, error) {
	length := len(b)
	if c.handshakeStatus == 8 {
		buf := pool.GetBuffer()
		defer pool.PutBuffer(buf)
		for len(b) > 2048 {
			size := min(randv2.IntN(4096)+100, len(b))
			packData(buf, b[:size])
			b = b[size:]
		}
		if len(b) > 0 {
			packData(buf, b)
		}
		_, err := c.Conn.Write(buf.Bytes())
		if err != nil {
			return 0, err
		}
		return length, nil
	}

	if len(b) > 0 {
		packData(&c.sendBuf, b)
	}

	if c.handshakeStatus == 0 {
		c.handshakeStatus = 1

		data := pool.GetBuffer()
		defer pool.PutBuffer(data)

		data.Write([]byte{3, 3})
		c.packAuthData(data)
		data.WriteByte(0x20)
		data.Write(c.clientID[:])
		data.Write([]byte{0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a})
		data.Write([]byte{0x1, 0x0})

		ext := pool.GetBuffer()
		defer pool.PutBuffer(ext)

		host := c.getHost()
		ext.Write([]byte{0xff, 0x01, 0x00, 0x01, 0x00})
		packSNIData(ext, host)
		ext.Write([]byte{0, 0x17, 0, 0})
		c.packTicketBuf(ext, host)
		ext.Write([]byte{0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03})
		ext.Write([]byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00})
		ext.Write([]byte{0x00, 0x12, 0x00, 0x00})
		ext.Write([]byte{0x75, 0x50, 0x00, 0x00})
		ext.Write([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00})
		ext.Write([]byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18})

		_ = binary.Write(data, binary.BigEndian, uint16(ext.Len()))
		_, _ = data.ReadFrom(ext)

		ret := pool.GetBuffer()
		defer pool.PutBuffer(ret)

		ret.Write([]byte{0x16, 3, 1})
		_ = binary.Write(ret, binary.BigEndian, uint16(data.Len()+4))
		ret.Write([]byte{1, 0})
		_ = binary.Write(ret, binary.BigEndian, uint16(data.Len()))
		_, _ = ret.ReadFrom(data)

		_, err := c.Conn.Write(ret.Bytes())
		if err != nil {
			return 0, err
		}
		if c.fastauth {
			_, err = c.Write(nil)
			if err != nil {
				return 0, err
			}
		}
		return length, nil
	} else if c.handshakeStatus == 1 && len(b) == 0 {
		buf := pool.GetBuffer()
		defer pool.PutBuffer(buf)

		buf.Write([]byte{0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20})
		tools.AppendRandBytes(buf, 22)
		buf.Write(c.hmacSHA1(buf.Bytes())[:10])
		_, _ = buf.ReadFrom(&c.sendBuf)

		c.handshakeStatus = 8

		_, err := c.Conn.Write(buf.Bytes())
		return 0, err
	}
	return length, nil
}

func packData(buf *bytes.Buffer, data []byte) {
	buf.Write([]byte{0x17, 3, 3})
	_ = binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
}

func (t *tls12Ticket) packAuthData(buf *bytes.Buffer) {
	_ = binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	tools.AppendRandBytes(buf, 18)
	buf.Write(t.hmacSHA1(buf.Bytes()[buf.Len()-22:])[:10])
}

func packSNIData(buf *bytes.Buffer, u string) {
	uLen := uint16(len(u))
	buf.Write([]byte{0, 0})
	_ = binary.Write(buf, binary.BigEndian, uLen+5)
	_ = binary.Write(buf, binary.BigEndian, uLen+3)
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uLen)
	buf.WriteString(u)
}

func (c *tls12TicketConn) packTicketBuf(buf *bytes.Buffer, u string) {
	length := 16 * (randv2.IntN(17) + 8)
	buf.Write([]byte{0, 0x23})
	_ = binary.Write(buf, binary.BigEndian, uint16(length))
	tools.AppendRandBytes(buf, length)
}

func (t *tls12Ticket) hmacSHA1(data []byte) []byte {
	key := pool.Get(len(t.Key) + 32)
	defer pool.Put(key)
	copy(key, t.Key)
	copy(key[len(t.Key):], t.clientID[:])

	sha1Data := tools.HmacSHA1(key, data)
	return sha1Data[:10]
}

func (t *tls12Ticket) getHost() string {
	host := t.Param
	if len(host) == 0 {
		host = t.Host
	}
	if len(host) > 0 && host[len(host)-1] >= '0' && host[len(host)-1] <= '9' {
		host = ""
	}
	hosts := strings.Split(host, ",")
	host = hosts[randv2.IntN(len(hosts))]
	return host
}

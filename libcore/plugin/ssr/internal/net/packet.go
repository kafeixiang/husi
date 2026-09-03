package net

import (
	"net"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/pool"
)

type WaitReadFrom interface {
	WaitReadFrom() (data []byte, put func(), addr net.Addr, err error)
}

type EnhancePacketConn interface {
	net.PacketConn
	WaitReadFrom
}

func NewEnhancePacketConn(pc net.PacketConn) EnhancePacketConn {
	if enhancePC, isEnhancePC := pc.(EnhancePacketConn); isEnhancePC {
		return enhancePC
	}
	return &enhancePacketConn{PacketConn: pc}
}

type enhancePacketConn struct {
	net.PacketConn
}

func (c *enhancePacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	readBuf := pool.Get(pool.UDPBufferSize)
	put = func() {
		pool.Put(readBuf)
	}
	var readN int
	readN, addr, err = c.PacketConn.ReadFrom(readBuf)
	if readN > 0 {
		data = readBuf[:readN]
	} else {
		put()
		put = nil
	}
	return
}

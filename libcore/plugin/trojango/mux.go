package trojango

import (
	"context"
	crand "crypto/rand"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"
)

type stickyConn struct {
	net.Conn
	writeMu   sync.Mutex
	closeOnce sync.Once
	synQueue  chan []byte
	finQueue  chan []byte
}

func newStickyConn(conn net.Conn) *stickyConn {
	return &stickyConn{
		Conn:     conn,
		synQueue: make(chan []byte, 128),
		finQueue: make(chan []byte, 128),
	}
}

func (c *stickyConn) stickToPayload(p []byte) []byte {
	if len(c.synQueue) == 0 && len(c.finQueue) == 0 {
		return p
	}

	buf := make([]byte, 0, len(p)+16)
	for {
		select {
		case header := <-c.synQueue:
			buf = append(buf, header...)
		default:
			goto stick1
		}
	}
stick1:
	buf = append(buf, p...)
	for {
		select {
		case header := <-c.finQueue:
			buf = append(buf, header...)
		default:
			goto stick2
		}
	}
stick2:
	return buf
}

func (c *stickyConn) pushFrameHeader(queue chan []byte, header []byte) error {
	select {
	case queue <- header:
		return nil
	default:
		_, err := c.Conn.Write(c.stickToPayload(header))
		return err
	}
}

func (c *stickyConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 8 {
		if p[0] == 1 || p[0] == 2 { // smux protocol version 1 or 2
			switch p[1] {
			case 0: // cmdSYN
				header := make([]byte, 8)
				copy(header, p)
				return 8, c.pushFrameHeader(c.synQueue, header)
			case 1: // cmdFIN
				header := make([]byte, 8)
				copy(header, p)
				return 8, c.pushFrameHeader(c.finQueue, header)
			}
		}
	}
	_, err := c.Conn.Write(c.stickToPayload(p))
	return len(p), err
}

const closePaddingDeadline = 10 * time.Second

func (c *stickyConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		const maxPaddingLength = 512
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		_ = c.Conn.SetWriteDeadline(time.Now().Add(closePaddingDeadline))

		var padLen int
		var b [1]byte
		if _, randErr := crand.Read(b[:]); randErr == nil {
			padLen = int(b[0]) * maxPaddingLength / 256
		}
		padding := make([]byte, padLen)
		if padLen > 0 {
			_, _ = crand.Read(padding)
		}
		payload := c.stickToPayload(append(c.stickToPayload(nil), padding...))
		if len(payload) > 0 {
			_, _ = c.Conn.Write(payload)
		}
		_ = c.Conn.SetWriteDeadline(time.Time{})
		err = c.Conn.Close()
	})
	return err
}

type smuxSessionInfo struct {
	session        *smux.Session
	underlayConn   net.Conn
	activeStreams  atomic.Int32
	lastActiveTime time.Time
}

type SessionPool struct {
	mu          sync.Mutex
	outbound    *Outbound
	concurrency int
	idleTimeout time.Duration
	sessions    []*smuxSessionInfo
	closed      bool
}

func NewSessionPool(outbound *Outbound, concurrency int, idleTimeoutSec int) *SessionPool {
	if concurrency <= 0 {
		concurrency = 8
	}
	if idleTimeoutSec <= 0 {
		idleTimeoutSec = 60
	}
	p := &SessionPool{
		outbound:    outbound,
		concurrency: concurrency,
		idleTimeout: time.Duration(idleTimeoutSec) * time.Second,
	}
	go p.cleanLoop()
	return p
}

func (p *SessionPool) cleanLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		now := time.Now()
		var alive []*smuxSessionInfo
		var dead []*smuxSessionInfo
		for _, info := range p.sessions {
			if info.session.IsClosed() {
				dead = append(dead, info)
				continue
			}
			if info.activeStreams.Load() == 0 && now.Sub(info.lastActiveTime) > p.idleTimeout {
				dead = append(dead, info)
				continue
			}
			alive = append(alive, info)
		}
		p.sessions = alive
		p.mu.Unlock()

		for _, info := range dead {
			info.session.Close()
			info.underlayConn.Close()
		}
	}
}

func (p *SessionPool) getOrCreateSession(ctx context.Context) (*smuxSessionInfo, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}

	var dead []*smuxSessionInfo
	var usable *smuxSessionInfo
	for _, info := range p.sessions {
		if info.session.IsClosed() {
			dead = append(dead, info)
			continue
		}
		if usable == nil && int(info.activeStreams.Load()) < p.concurrency {
			usable = info
		}
	}
	if len(dead) > 0 {
		var alive []*smuxSessionInfo
		for _, info := range p.sessions {
			if !slices.Contains(dead, info) {
				alive = append(alive, info)
			}
		}
		p.sessions = alive
	}
	if usable != nil {
		usable.lastActiveTime = time.Now()
		p.mu.Unlock()
		for _, info := range dead {
			info.session.Close()
			info.underlayConn.Close()
		}
		return usable, nil
	}
	p.mu.Unlock()

	for _, info := range dead {
		info.session.Close()
		info.underlayConn.Close()
	}

	// Create new session outside mutex to avoid blocking other concurrent requests
	conn, err := p.outbound.dialUnderlay(ctx)
	if err != nil {
		return nil, err
	}

	// Trojan-Go Mux handshake: CommandMux (0x7f) + MUX_CONN (DomainName)
	err = trojan.ClientHandshakeRaw(conn, p.outbound.key, trojan.CommandMux, M.Socksaddr{Fqdn: "MUX_CONN", Port: 0}, nil)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "trojan-go mux handshake")
	}

	sticky := newStickyConn(conn)
	cfg := smux.DefaultConfig()
	session, err := smux.Client(sticky, cfg)
	if err != nil {
		sticky.Close()
		return nil, E.Cause(err, "smux client create")
	}

	info := &smuxSessionInfo{
		session:        session,
		underlayConn:   sticky,
		lastActiveTime: time.Now(),
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || ctx.Err() != nil {
		session.Close()
		sticky.Close()
		if p.closed {
			return nil, net.ErrClosed
		}
		return nil, ctx.Err()
	}
	p.sessions = append(p.sessions, info)
	return info, nil
}

func (p *SessionPool) removeSession(target *smuxSessionInfo) {
	p.mu.Lock()
	for i, info := range p.sessions {
		if info == target {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
	p.mu.Unlock()

	target.session.Close()
	target.underlayConn.Close()
}

func (p *SessionPool) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	for attempt := range 2 {
		info, err := p.getOrCreateSession(ctx)
		if err != nil {
			return nil, err
		}

		stream, err := info.session.OpenStream()
		if err != nil {
			p.removeSession(info)
			if attempt == 0 {
				continue
			}
			return nil, E.Cause(err, "open smux stream")
		}
		info.activeStreams.Add(1)

		// Simplesocks TCP handshake: CommandTCP(1) + AddrPort
		header := buf.NewSize(1 + M.SocksaddrSerializer.AddrPortLen(destination))
		if err := header.WriteByte(trojan.CommandTCP); err != nil {
			header.Release()
			stream.Close()
			info.activeStreams.Add(-1)
			return nil, E.Cause(err, "write simplesocks tcp command")
		}
		if err := M.SocksaddrSerializer.WriteAddrPort(header, destination); err != nil {
			header.Release()
			stream.Close()
			info.activeStreams.Add(-1)
			return nil, E.Cause(err, "write simplesocks tcp destination")
		}

		if _, err := stream.Write(header.Bytes()); err != nil {
			header.Release()
			stream.Close()
			info.activeStreams.Add(-1)
			p.removeSession(info)
			if attempt == 0 {
				continue
			}
			return nil, E.Cause(err, "write simplesocks tcp header")
		}
		header.Release()

		return &muxStreamConn{
			Stream: stream,
			onClose: func() {
				info.activeStreams.Add(-1)
				info.lastActiveTime = time.Now()
			},
		}, nil
	}
	return nil, net.ErrClosed
}

func (p *SessionPool) ListenPacket(ctx context.Context, destination M.Socksaddr) (bufio.BindPacketConn, error) {
	for attempt := range 2 {
		info, err := p.getOrCreateSession(ctx)
		if err != nil {
			return nil, err
		}

		stream, err := info.session.OpenStream()
		if err != nil {
			p.removeSession(info)
			if attempt == 0 {
				continue
			}
			return nil, E.Cause(err, "open smux stream for udp")
		}
		info.activeStreams.Add(1)

		// Simplesocks UDP associate handshake: CommandUDP(3) + UDP_CONN
		fakeAddr := M.Socksaddr{Fqdn: "UDP_CONN", Port: 0}
		header := buf.NewSize(1 + M.SocksaddrSerializer.AddrPortLen(fakeAddr))
		if err := header.WriteByte(trojan.CommandUDP); err != nil {
			header.Release()
			stream.Close()
			info.activeStreams.Add(-1)
			return nil, E.Cause(err, "write simplesocks udp command")
		}
		if err := M.SocksaddrSerializer.WriteAddrPort(header, fakeAddr); err != nil {
			header.Release()
			stream.Close()
			info.activeStreams.Add(-1)
			return nil, E.Cause(err, "write simplesocks udp destination")
		}

		if _, err := stream.Write(header.Bytes()); err != nil {
			header.Release()
			stream.Close()
			info.activeStreams.Add(-1)
			p.removeSession(info)
			if attempt == 0 {
				continue
			}
			return nil, E.Cause(err, "write simplesocks udp header")
		}
		header.Release()

		packetConn := &muxPacketConn{
			stream: stream,
			onClose: func() {
				info.activeStreams.Add(-1)
				info.lastActiveTime = time.Now()
			},
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	}
	return nil, net.ErrClosed
}

func (p *SessionPool) Reset() {
	p.mu.Lock()
	sessions := p.sessions
	p.sessions = nil
	p.mu.Unlock()

	for _, info := range sessions {
		info.session.Close()
		info.underlayConn.Close()
	}
}

func (p *SessionPool) Close() error {
	p.mu.Lock()
	p.closed = true
	sessions := p.sessions
	p.sessions = nil
	p.mu.Unlock()

	for _, info := range sessions {
		info.session.Close()
		info.underlayConn.Close()
	}
	return nil
}

type muxStreamConn struct {
	*smux.Stream
	onClose   func()
	closeOnce sync.Once
}

func (c *muxStreamConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.Stream.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

type muxPacketConn struct {
	stream    *smux.Stream
	onClose   func()
	closeOnce sync.Once
}

func (c *muxPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return trojan.ReadPacket(c.stream, buffer)
}

func (c *muxPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return trojan.WritePacket(c.stream, buffer, destination)
}

func (c *muxPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n = buffer.Len()
	if destination.IsDomain() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	return
}

func (c *muxPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return bufio.WritePacket(c, p, addr)
}

func (c *muxPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.stream.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *muxPacketConn) LocalAddr() net.Addr {
	return c.stream.LocalAddr()
}

func (c *muxPacketConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *muxPacketConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *muxPacketConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

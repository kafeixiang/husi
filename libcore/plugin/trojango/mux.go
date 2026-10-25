package trojango

import (
	"context"
	"net"
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
		for _, info := range p.sessions {
			if info.session.IsClosed() {
				info.session.Close()
				info.underlayConn.Close()
				continue
			}
			if info.activeStreams.Load() == 0 && now.Sub(info.lastActiveTime) > p.idleTimeout {
				info.session.Close()
				info.underlayConn.Close()
				continue
			}
			alive = append(alive, info)
		}
		p.sessions = alive
		p.mu.Unlock()
	}
}

func (p *SessionPool) getOrCreateSession(ctx context.Context) (*smuxSessionInfo, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}

	for _, info := range p.sessions {
		if !info.session.IsClosed() && int(info.activeStreams.Load()) < p.concurrency {
			info.lastActiveTime = time.Now()
			p.mu.Unlock()
			return info, nil
		}
	}
	p.mu.Unlock()

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

	cfg := smux.DefaultConfig()
	session, err := smux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "smux client create")
	}

	info := &smuxSessionInfo{
		session:        session,
		underlayConn:   conn,
		lastActiveTime: time.Now(),
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		session.Close()
		conn.Close()
		return nil, net.ErrClosed
	}
	p.sessions = append(p.sessions, info)
	return info, nil
}

func (p *SessionPool) removeSession(target *smuxSessionInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	target.session.Close()
	target.underlayConn.Close()
	for i, info := range p.sessions {
		if info == target {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
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
	defer p.mu.Unlock()
	for _, info := range p.sessions {
		info.session.Close()
		info.underlayConn.Close()
	}
	p.sessions = nil
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

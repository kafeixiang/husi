package ssr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/core"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/shadowstream"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/socks5"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/tools"
)

type SSRServerConfig struct {
	Method        string
	Password      string
	Obfs          string
	ObfsParam     string
	Protocol      string
	ProtocolParam string
}

type SSRMockServer struct {
	cfg        SSRServerConfig
	tcpLn      net.Listener
	udpLn      *net.UDPConn
	key        []byte
	userKey    []byte
	userID     [4]byte
	ivSize     int
	coreCipher core.Cipher
	closed     chan struct{}
	wg         sync.WaitGroup
}

func StartSSRMockServer(cfg SSRServerConfig) (*SSRMockServer, error) {
	method := strings.ToLower(strings.TrimSuffix(cfg.Method, "_compatible"))
	if method == "none" || method == "plain" || method == "" {
		method = "dummy"
	}
	ciph, err := core.PickCipher(method, nil, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("pick cipher: %w", err)
	}

	var (
		ivSize int
		key    []byte
	)
	if method == "dummy" {
		ivSize = 0
		key = core.Kdf(cfg.Password, 16)
	} else {
		sc := ciph.(*core.StreamCipher)
		ivSize = sc.IVSize()
		key = sc.Key
	}

	obfsName := strings.ToLower(strings.TrimSuffix(cfg.Obfs, "_compatible"))
	if obfsName == "" {
		obfsName = "plain"
	}
	protocolName := strings.ToLower(strings.TrimSuffix(cfg.Protocol, "_compatible"))
	if protocolName == "" {
		protocolName = "origin"
	}

	s := &SSRMockServer{
		cfg:        cfg,
		key:        key,
		ivSize:     ivSize,
		coreCipher: ciph,
		closed:     make(chan struct{}),
	}
	s.cfg.Method = method
	s.cfg.Obfs = obfsName
	s.cfg.Protocol = protocolName

	s.initUserData()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.tcpLn = tcpLn

	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: tcpPort}
	udpLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcpLn.Close()
		return nil, err
	}
	s.udpLn = udpLn

	s.wg.Add(2)
	go s.serveTCP()
	go s.serveUDP()

	return s, nil
}

func (s *SSRMockServer) initUserData() {
	if len(s.cfg.ProtocolParam) > 0 {
		params := strings.Split(s.cfg.ProtocolParam, ":")
		if len(params) > 1 {
			if id, err := strconv.ParseUint(params[0], 10, 32); err == nil {
				binary.LittleEndian.PutUint32(s.userID[:], uint32(id))
				switch s.cfg.Protocol {
				case "auth_aes128_md5":
					s.userKey = tools.MD5Sum([]byte(params[1]))
				case "auth_aes128_sha1":
					s.userKey = tools.SHA1Sum([]byte(params[1]))
				case "auth_chain_a", "auth_chain_b":
					s.userKey = []byte(params[1])
				}
			}
		}
	}
	if len(s.userKey) == 0 {
		s.userKey = s.key
	}
}

func (s *SSRMockServer) TCPAddr() string {
	return s.tcpLn.Addr().String()
}

func (s *SSRMockServer) Port() int {
	return s.tcpLn.Addr().(*net.TCPAddr).Port
}

func (s *SSRMockServer) Close() {
	close(s.closed)
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	if s.udpLn != nil {
		s.udpLn.Close()
	}
	s.wg.Wait()
}

func (s *SSRMockServer) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				return
			}
		}
		go s.handleTCP(conn)
	}
}

func (s *SSRMockServer) handleTCP(rawConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[SERVER PANIC] %v\n", r)
		}
		rawConn.Close()
	}()
	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. Obfs Unwrap / Handshake
	obfsConn, clientHello, err := s.serverHandleObfs(rawConn)
	if err != nil {
		fmt.Printf("[SERVER ERROR obfs %s] %v\n", s.cfg.Obfs, err)
		return
	}

	// 2. Stream Cipher Decrypt / Encrypt
	cipherConn, clientIV, err := s.serverHandleCipher(obfsConn)
	if err != nil {
		fmt.Printf("[SERVER ERROR cipher %s] %v\n", s.cfg.Method, err)
		return
	}
	_ = clientHello

	// 3. Protocol Unwrap / Handshake & SOCKS5 parsing
	targetAddr, payload, err := s.serverHandleProtocolAndRead(cipherConn, clientIV)
	if err != nil {
		fmt.Printf("[SERVER ERROR protocol %s] %v\n", s.cfg.Protocol, err)
		return
	}

	// If the initial chunk only contained the SOCKS5 address, read the next data chunk
	if len(payload) == 0 {
		var st *serverProtocolState
		if v, ok := serverStateMap.Load(cipherConn); ok {
			st = v.(*serverProtocolState)
		}
		payload, err = s.readClientDataChunk(cipherConn, st)
		if err != nil {
			fmt.Printf("[SERVER ERROR readChunk %s] %v\n", s.cfg.Protocol, err)
			return
		}
	}

	// 4. Handle Request (Echo back targetAddr and payload with server acknowledgement)
	responsePayload := append([]byte("ECHO:"), payload...)
	_ = targetAddr

	// 5. Send Response through Protocol + Cipher + Obfs
	err = s.serverSendResponse(cipherConn, responsePayload)
	if err != nil {
		fmt.Printf("[SERVER ERROR sendResp %s] %v\n", s.cfg.Protocol, err)
		return
	}
}

func (s *SSRMockServer) readClientDataChunk(conn net.Conn, st *serverProtocolState) ([]byte, error) {
	switch s.cfg.Protocol {
	case "origin":
		var buf [2048]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			return nil, err
		}
		return buf[:n], nil

	case "auth_sha1_v4":
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		length := int(binary.BigEndian.Uint16(lenBuf[:]))
		rest := make([]byte, length-2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, err
		}
		full := append(lenBuf[:], rest...)
		pos := int(full[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.BigEndian.Uint16(full[5:7])) + 4
		}
		return full[pos : length-4], nil

	case "auth_aes128_md5", "auth_aes128_sha1":
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		length := int(binary.LittleEndian.Uint16(lenBuf[:]))
		rest := make([]byte, length-2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, err
		}
		full := append(lenBuf[:], rest...)
		pos := int(full[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.LittleEndian.Uint16(full[5:7])) + 4
		}
		return full[pos : length-4], nil

	case "auth_chain_a", "auth_chain_b":
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		dataLen := int(binary.LittleEndian.Uint16(lenBuf[:]) ^ binary.LittleEndian.Uint16(st.lastClientHash[14:16]))
		randLen := st.randDataLength(dataLen, st.lastClientHash, &st.randomClient)
		restChunk := make([]byte, randLen+dataLen+2)
		if _, err := io.ReadFull(conn, restChunk); err != nil {
			return nil, err
		}
		pos := 0
		if dataLen > 0 && randLen > 0 {
			pos += getRandStartPos(randLen, &st.randomClient)
		}
		wanted := restChunk[pos : pos+dataLen]
		st.clientRC4.XORKeyStream(wanted, wanted)

		// Update st.lastClientHash
		macKey := append(append([]byte(nil), st.userKey...), 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(macKey[len(st.userKey):], st.packID)
		st.packID++
		fullChunk := append(lenBuf[:], restChunk[:len(restChunk)-2]...)
		st.lastClientHash = tools.HmacMD5(macKey, fullChunk)

		return wanted, nil

	default:
		return nil, errors.New("unsupported protocol")
	}
}

func (s *SSRMockServer) serverHandleObfs(conn net.Conn) (net.Conn, []byte, error) {
	switch s.cfg.Obfs {
	case "plain":
		return conn, nil, nil

	case "http_simple", "http_post":
		var buf [4096]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			return nil, nil, err
		}
		data := buf[:n]
		_, after, ok := bytes.Cut(data, []byte("\r\n\r\n"))
		if !ok {
			return nil, nil, errors.New("http obfs: header end not found")
		}

		before0, _, _ := bytes.Cut(data, []byte("\r\n"))
		firstLine := string(before0)
		slashIdx := strings.Index(firstLine, "/")
		httpIdx := strings.LastIndex(firstLine, " HTTP/1.1")
		if slashIdx == -1 || httpIdx <= slashIdx {
			return nil, nil, errors.New("http obfs: invalid request line")
		}
		hexPath := firstLine[slashIdx+1 : httpIdx]
		unescapedHex := strings.ReplaceAll(hexPath, "%", "")
		headData, err := hex.DecodeString(unescapedHex)
		if err != nil {
			return nil, nil, fmt.Errorf("http obfs: decode path hex: %w", err)
		}

		remainingData := after
		allData := append(headData, remainingData...)

		resp := "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			return nil, nil, err
		}

		return &bufferedPrefixConn{Conn: conn, prefix: allData}, nil, nil

	case "random_head":
		var buf [256]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			return nil, nil, err
		}
		if n < 8 {
			return nil, nil, errors.New("random_head: header too short")
		}
		dataLen := n - 4
		expectedCRC := 0xffffffff - crc32.ChecksumIEEE(buf[:dataLen])
		actualCRC := binary.LittleEndian.Uint32(buf[dataLen:n])
		if expectedCRC != actualCRC {
			return nil, nil, errors.New("random_head: crc mismatch")
		}
		if _, err := conn.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
			return nil, nil, err
		}
		return conn, nil, nil

	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		var buf [4096]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			return nil, nil, err
		}
		if n < 76 {
			return nil, nil, errors.New("tls obfs: client hello too short")
		}
		var clientID [32]byte
		copy(clientID[:], buf[44:76])

		// ServerHello + ChangeCipherSpec + Finished + HMAC (matching official shadowsocksr)
		key := append(append([]byte(nil), s.key...), clientID[:]...)
		var resp bytes.Buffer

		// 1. ServerHello
		var shBody bytes.Buffer
		shBody.Write([]byte{3, 3}) // tls version
		serverRand := make([]byte, 22)
		_, _ = crand.Read(serverRand)
		shBody.Write(serverRand)
		shBody.Write(tools.HmacSHA1(key, serverRand)[:10])
		shBody.WriteByte(0x20)
		shBody.Write(clientID[:])
		shBody.Write([]byte{0xc0, 0x2f, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00})

		resp.Write([]byte{0x16, 3, 3})
		_ = binary.Write(&resp, binary.BigEndian, uint16(shBody.Len()+4))
		resp.Write([]byte{0x02, 0x00})
		_ = binary.Write(&resp, binary.BigEndian, uint16(shBody.Len()))
		resp.Write(shBody.Bytes())

		// 2. ChangeCipherSpec
		resp.Write([]byte{0x14, 3, 3, 0x00, 0x01, 0x01})

		// 3. Finished record with 10-byte HMAC inside
		finishLen := 32
		finBody := make([]byte, finishLen-10)
		_, _ = crand.Read(finBody)

		var finRecord bytes.Buffer
		finRecord.Write([]byte{0x16, 3, 3})
		_ = binary.Write(&finRecord, binary.BigEndian, uint16(finishLen))
		finRecord.Write(finBody)

		dataToHmac := append(append([]byte(nil), resp.Bytes()...), finRecord.Bytes()...)
		hmacVal := tools.HmacSHA1(key, dataToHmac)[:10]

		resp.Write(finRecord.Bytes())
		resp.Write(hmacVal)

		if _, err := conn.Write(resp.Bytes()); err != nil {
			return nil, nil, err
		}

		appBuf := bytes.NewBuffer(nil)
		if idx := bytes.Index(buf[:n], []byte{0x17, 3, 3}); idx != -1 {
			appBuf.Write(buf[idx:n])
		} else {
			n2, err := conn.Read(buf[:])
			if err != nil {
				return nil, nil, err
			}
			idx2 := bytes.Index(buf[:n2], []byte{0x17, 3, 3})
			if idx2 == -1 {
				return nil, nil, errors.New("tls obfs: application data not found")
			}
			appBuf.Write(buf[idx2:n2])
		}

		return &tlsObfsConn{Conn: conn, readBuf: appBuf}, clientID[:], nil

	default:
		return conn, nil, nil
	}
}

type bufferedPrefixConn struct {
	net.Conn
	prefix []byte
}

func (c *bufferedPrefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

type tlsObfsConn struct {
	net.Conn
	readBuf *bytes.Buffer
	decBuf  *bytes.Buffer
}

func (c *tlsObfsConn) Read(b []byte) (int, error) {
	for {
		if c.decBuf != nil && c.decBuf.Len() > 0 {
			return c.decBuf.Read(b)
		}
		if c.readBuf.Len() >= 5 {
			data := c.readBuf.Bytes()
			if bytes.Equal(data[:3], []byte{0x17, 3, 3}) {
				recLen := int(binary.BigEndian.Uint16(data[3:5]))
				if c.readBuf.Len() >= 5+recLen {
					c.readBuf.Next(5)
					if c.decBuf == nil {
						c.decBuf = bytes.NewBuffer(nil)
					}
					c.decBuf.Write(c.readBuf.Next(recLen))
					continue
				}
			}
		}
		var temp [2048]byte
		nr, err := c.Conn.Read(temp[:])
		if err != nil {
			return 0, err
		}
		c.readBuf.Write(temp[:nr])
	}
}

func (c *tlsObfsConn) Write(b []byte) (int, error) {
	buf := make([]byte, 5+len(b))
	buf[0] = 0x17
	buf[1] = 3
	buf[2] = 3
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(b)))
	copy(buf[5:], b)
	_, err := c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

type serverCipherConn struct {
	net.Conn
	decrypter cipher.Stream
	encrypter cipher.Stream
}

func (c *serverCipherConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.decrypter != nil {
		c.decrypter.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (c *serverCipherConn) Write(b []byte) (int, error) {
	if c.encrypter == nil {
		return c.Conn.Write(b)
	}
	buf := make([]byte, len(b))
	c.encrypter.XORKeyStream(buf, b)
	return c.Conn.Write(buf)
}

func (s *SSRMockServer) serverHandleCipher(conn net.Conn) (net.Conn, []byte, error) {
	if s.cfg.Method == "dummy" {
		return conn, nil, nil
	}
	sc, ok := s.coreCipher.(*core.StreamCipher)
	if !ok {
		return conn, nil, nil
	}

	// 1. Read Client IV
	clientIV := make([]byte, sc.IVSize())
	if sc.IVSize() > 0 {
		if _, err := io.ReadFull(conn, clientIV); err != nil {
			return nil, nil, fmt.Errorf("read client IV: %w", err)
		}
	}
	decrypter := sc.Decrypter(clientIV)

	// 2. Generate and Send Server IV
	serverIV := make([]byte, sc.IVSize())
	if sc.IVSize() > 0 {
		if _, err := crand.Read(serverIV); err != nil {
			return nil, nil, err
		}
		if _, err := conn.Write(serverIV); err != nil {
			return nil, nil, fmt.Errorf("write server IV: %w", err)
		}
	}
	encrypter := sc.Encrypter(serverIV)

	return &serverCipherConn{
		Conn:      conn,
		decrypter: decrypter,
		encrypter: encrypter,
	}, clientIV, nil
}

type serverProtocolState struct {
	salt           string
	overhead       int
	userKey        []byte
	lastClientHash []byte
	lastServerHash []byte
	clientRC4      cipher.Stream
	serverRC4      cipher.Stream
	randomClient   tools.XorShift128Plus
	randomServer   tools.XorShift128Plus
	recvID         uint32
	packID         uint32
	dataSizeList   []int
	dataSizeList2  []int
}

var serverStateMap sync.Map

func (s *SSRMockServer) serverHandleProtocolAndRead(conn net.Conn, clientIV []byte) (string, []byte, error) {
	switch s.cfg.Protocol {
	case "origin":
		var buf [2048]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			return "", nil, err
		}
		addr := socks5.SplitAddr(buf[:n])
		if addr == nil {
			return "", nil, errors.New("parse socks5 addr failed")
		}
		payload := buf[len(addr):n]
		return addr.String(), payload, nil

	case "auth_sha1_v4":
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", nil, err
		}
		packedLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if packedLen < 28 {
			return "", nil, errors.New("auth_sha1_v4: auth header too short")
		}

		rest := make([]byte, packedLen-2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return "", nil, err
		}
		full := append(lenBuf[:], rest...)

		salt := []byte("auth_sha1_v4")
		crcData := append(append([]byte{lenBuf[0], lenBuf[1]}, salt...), s.key...)
		expectedCRC := crc32.ChecksumIEEE(crcData)
		actualCRC := binary.LittleEndian.Uint32(full[2:6])
		if expectedCRC != actualCRC {
			return "", nil, errors.New("auth_sha1_v4: crc32 mismatch")
		}

		pos := int(full[6])
		if pos < 255 {
			pos += 6
		} else {
			pos = int(binary.BigEndian.Uint16(full[7:9])) + 6
		}
		dataStart := pos + 12
		dataEnd := packedLen - 10
		if dataStart > dataEnd {
			return "", nil, errors.New("auth_sha1_v4: invalid data range")
		}
		plain := full[dataStart:dataEnd]
		addr := socks5.SplitAddr(plain)
		if addr == nil {
			return "", nil, errors.New("auth_sha1_v4: parse socks5 addr failed")
		}
		return addr.String(), plain[len(addr):], nil

	case "auth_aes128_md5", "auth_aes128_sha1":
		var header [27]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return "", nil, err
		}

		salt := s.cfg.Protocol
		cipherKey := core.Kdf(base64.StdEncoding.EncodeToString(s.userKey)+salt, 16)
		block, err := aes.NewCipher(cipherKey)
		if err != nil {
			return "", nil, err
		}
		iv := bytes.Repeat([]byte{0}, 16)
		cbc := cipher.NewCBCDecrypter(block, iv)
		decrypted := make([]byte, 16)
		cbc.CryptBlocks(decrypted, header[11:27])

		packedAuthDataLength := int(binary.LittleEndian.Uint16(decrypted[12:14]))
		randDataLength := int(binary.LittleEndian.Uint16(decrypted[14:16]))

		remainingBytes := packedAuthDataLength - 27
		if remainingBytes < 0 {
			return "", nil, errors.New("auth_aes128: negative remaining bytes")
		}
		rest := make([]byte, remainingBytes)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return "", nil, err
		}

		dataStart := 4 + randDataLength
		dataEnd := remainingBytes - 4
		if dataStart > dataEnd {
			return "", nil, errors.New("auth_aes128: invalid range")
		}
		plain := rest[dataStart:dataEnd]
		addr := socks5.SplitAddr(plain)
		if addr == nil {
			return "", nil, errors.New("auth_aes128: parse socks5 addr failed")
		}
		st := &serverProtocolState{
			userKey: s.userKey,
			salt:    salt,
			recvID:  1,
		}
		serverStateMap.Store(conn, st)
		return addr.String(), plain[len(addr):], nil

	case "auth_chain_a", "auth_chain_b":
		var header [36]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return "", nil, err
		}

		// 1. Rand bytes (4) + lastClientHash[:8] (8)
		macKey := append(append([]byte(nil), clientIV...), s.key...)
		lastClientHash := tools.HmacMD5(macKey, header[:4])
		if !bytes.Equal(lastClientHash[:8], header[4:12]) {
			return "", nil, errors.New("auth_chain: client hash mismatch")
		}

		// 2. Derive RC4 ciphers
		rc4Key := core.Kdf(base64.StdEncoding.EncodeToString(s.userKey)+base64.StdEncoding.EncodeToString(lastClientHash), 16)
		clientRC4, _ := rc4.NewCipher(rc4Key)
		serverRC4, _ := rc4.NewCipher(rc4Key)

		// 3. LastServerHash check on bytes [12:32]
		lastServerHash := tools.HmacMD5(s.userKey, header[12:32])
		if !bytes.Equal(lastServerHash[:4], header[32:36]) {
			return "", nil, errors.New("auth_chain: server hash mismatch")
		}

		overhead := 4
		if s.cfg.Obfs == "tls1.2_ticket_auth" || s.cfg.Obfs == "tls1.2_ticket_fastauth" {
			overhead += 5
		}

		st := &serverProtocolState{
			salt:           s.cfg.Protocol,
			overhead:       overhead,
			userKey:        s.userKey,
			lastClientHash: lastClientHash,
			lastServerHash: lastServerHash,
			clientRC4:      clientRC4,
			serverRC4:      serverRC4,
			recvID:         1,
			packID:         2, // Next chunk from client will have packID=2
		}
		if s.cfg.Protocol == "auth_chain_b" {
			st.initChainBDataSize(s.key)
		}

		// 4. Data chunk follows: read 2 bytes encoded length
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", nil, err
		}
		dataLen := int(binary.LittleEndian.Uint16(lenBuf[:]) ^ binary.LittleEndian.Uint16(lastClientHash[14:16]))
		randLen := st.randDataLength(dataLen, lastClientHash, &st.randomClient)

		restChunk := make([]byte, randLen+dataLen+2)
		if _, err := io.ReadFull(conn, restChunk); err != nil {
			return "", nil, err
		}

		pos := 0
		if dataLen > 0 && randLen > 0 {
			pos += getRandStartPos(randLen, &st.randomClient)
		}
		// Compute st.lastClientHash using packID=1 BEFORE decrypting in place
		firstMacKey := append(append([]byte(nil), st.userKey...), 1, 0, 0, 0)
		fullChunk := append(lenBuf[:], restChunk[:len(restChunk)-2]...)
		st.lastClientHash = tools.HmacMD5(firstMacKey, fullChunk)

		wanted := restChunk[pos : pos+dataLen]
		clientRC4.XORKeyStream(wanted, wanted)

		addr := socks5.SplitAddr(wanted)
		if addr == nil {
			return "", nil, errors.New("auth_chain: parse socks5 addr failed")
		}
		serverStateMap.Store(conn, st)
		return addr.String(), wanted[len(addr):], nil

	default:
		return "", nil, errors.New("unsupported protocol")
	}
}

func (st *serverProtocolState) initChainBDataSize(key []byte) {
	st.randomServer.InitFromBin(key)
	length := st.randomServer.Next()%8 + 4
	for ; length > 0; length-- {
		st.dataSizeList = append(st.dataSizeList, int(st.randomServer.Next()%2340%2040%1440))
	}
	sort.Ints(st.dataSizeList)

	length = st.randomServer.Next()%16 + 8
	for ; length > 0; length-- {
		st.dataSizeList2 = append(st.dataSizeList2, int(st.randomServer.Next()%2340%2040%1440))
	}
	sort.Ints(st.dataSizeList2)
}

func (st *serverProtocolState) randDataLength(length int, lastHash []byte, random *tools.XorShift128Plus) int {
	if st.salt == "auth_chain_b" {
		if length >= 1440 {
			return 0
		}
		random.InitFromBinAndLength(lastHash, length)
		pos := sort.Search(len(st.dataSizeList), func(i int) bool { return st.dataSizeList[i] >= length+st.overhead })
		finalPos := pos + int(random.Next()%uint64(len(st.dataSizeList)))
		if finalPos < len(st.dataSizeList) {
			return st.dataSizeList[finalPos] - length - st.overhead
		}
		pos = sort.Search(len(st.dataSizeList2), func(i int) bool { return st.dataSizeList2[i] >= length+st.overhead })
		finalPos = pos + int(random.Next()%uint64(len(st.dataSizeList2)))
		if finalPos < len(st.dataSizeList2) {
			return st.dataSizeList2[finalPos] - length - st.overhead
		}
		if finalPos < pos+len(st.dataSizeList2)-1 {
			return 0
		}
		if length > 1300 {
			return int(random.Next() % 31)
		}
		if length > 900 {
			return int(random.Next() % 127)
		}
		if length > 400 {
			return int(random.Next() % 521)
		}
		return int(random.Next() % 1021)
	}
	// auth_chain_a
	if length > 1440 {
		return 0
	}
	random.InitFromBinAndLength(lastHash, length)
	if length > 1300 {
		return int(random.Next() % 31)
	}
	if length > 900 {
		return int(random.Next() % 127)
	}
	if length > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func getRandStartPos(length int, random *tools.XorShift128Plus) int {
	if length == 0 {
		return 0
	}
	return int(int64(random.Next()%8589934609) % int64(length))
}

func (s *SSRMockServer) serverSendResponse(conn net.Conn, resp []byte) error {
	switch s.cfg.Protocol {
	case "origin":
		_, err := conn.Write(resp)
		return err

	case "auth_sha1_v4":
		dataLength := len(resp)
		packedDataLength := 2 + 2 + 1 + dataLength + 4
		buf := make([]byte, packedDataLength)
		binary.BigEndian.PutUint16(buf[:2], uint16(packedDataLength))
		binary.LittleEndian.PutUint16(buf[2:4], uint16(crc32.ChecksumIEEE(buf[:2])&0xffff))
		buf[4] = 1 // size=0 -> byte(size+1)=1
		copy(buf[5:5+dataLength], resp)
		binary.LittleEndian.PutUint32(buf[packedDataLength-4:], adler32.Checksum(buf[:packedDataLength-4]))
		_, err := conn.Write(buf)
		return err

	case "auth_aes128_md5", "auth_aes128_sha1":
		v, ok := serverStateMap.Load(conn)
		if !ok {
			return errors.New("server state not found")
		}
		st := v.(*serverProtocolState)
		macKey := append(append([]byte(nil), st.userKey...), 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(macKey[len(st.userKey):], st.recvID)
		st.recvID++

		dataLength := len(resp)
		packedDataLength := 2 + 2 + 1 + dataLength + 4
		buf := make([]byte, packedDataLength)
		binary.LittleEndian.PutUint16(buf[:2], uint16(packedDataLength))
		hmacFunc := tools.HmacSHA1
		if s.cfg.Protocol == "auth_aes128_md5" {
			hmacFunc = tools.HmacMD5
		}
		copy(buf[2:4], hmacFunc(macKey, buf[:2])[:2])
		buf[4] = 1 // size=0 -> byte(size+1)=1
		copy(buf[5:5+dataLength], resp)
		copy(buf[packedDataLength-4:], hmacFunc(macKey, buf[:packedDataLength-4])[:4])
		_, err := conn.Write(buf)
		return err

	case "auth_chain_a", "auth_chain_b":
		v, ok := serverStateMap.Load(conn)
		if !ok {
			return errors.New("server state not found")
		}
		st := v.(*serverProtocolState)
		payload := append([]byte{0xaa, 0xbb}, resp...)
		dataLength := len(payload)
		randLen := st.randDataLength(dataLength, st.lastServerHash, &st.randomServer)
		length := dataLength + randLen

		buf := make([]byte, 2+length+2)
		encodedLen := uint16(dataLength) ^ binary.LittleEndian.Uint16(st.lastServerHash[14:16])
		binary.LittleEndian.PutUint16(buf[:2], encodedLen)

		encPayload := make([]byte, dataLength)
		st.serverRC4.XORKeyStream(encPayload, payload)

		pos := 2
		if dataLength > 0 && randLen > 0 {
			pos += getRandStartPos(randLen, &st.randomServer)
		}
		copy(buf[pos:pos+dataLength], encPayload)

		macKey := append(append([]byte(nil), st.userKey...), 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(macKey[len(st.userKey):], st.recvID)
		st.recvID++

		serverHash := tools.HmacMD5(macKey, buf[:length+2])
		st.lastServerHash = serverHash
		copy(buf[length+2:], serverHash[:2])

		_, err := conn.Write(buf)
		return err

	default:
		_, err := conn.Write(resp)
		return err
	}
}

// UDP Serving
func (s *SSRMockServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := s.udpLn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				return
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handleUDP(pkt, clientAddr)
	}
}

func (s *SSRMockServer) handleUDP(pkt []byte, clientAddr net.Addr) {
	// 1. Cipher Unpack
	var (
		decrypted []byte
		err       error
	)
	if s.cfg.Method == "dummy" {
		decrypted = pkt
	} else {
		sc := s.coreCipher.(*core.StreamCipher)
		decrypted, err = shadowstream.UnpackInplace(pkt, sc)
		if err != nil {
			return
		}
	}

	// 2. Protocol DecodePacket
	payload, err := s.serverDecodeUDPPacket(decrypted)
	if err != nil {
		return
	}

	// 3. SOCKS5 UDP Address parsing
	targetAddr := socks5.SplitAddr(payload)
	if targetAddr == nil {
		return
	}
	userPayload := payload[len(targetAddr):]

	// 4. Echo back with target address
	echoData := append([]byte("UDP-ECHO:"), userPayload...)
	respPlain := append(append([]byte(nil), targetAddr...), echoData...)

	// 5. Protocol EncodePacket
	encodedPkt, err := s.serverEncodeUDPPacket(respPlain)
	if err != nil {
		return
	}

	// 6. Cipher Pack
	var finalPkt []byte
	if s.cfg.Method == "dummy" {
		finalPkt = encodedPkt
	} else {
		sc := s.coreCipher.(*core.StreamCipher)
		finalPkt = make([]byte, sc.IVSize()+len(encodedPkt))
		finalPkt, err = shadowstream.Pack(finalPkt, encodedPkt, sc)
		if err != nil {
			return
		}
	}

	_, _ = s.udpLn.WriteTo(finalPkt, clientAddr)
}

func (s *SSRMockServer) serverDecodeUDPPacket(b []byte) ([]byte, error) {
	switch s.cfg.Protocol {
	case "origin", "auth_sha1_v4":
		return b, nil

	case "auth_aes128_md5", "auth_aes128_sha1":
		if len(b) < 8 {
			return nil, errors.New("auth_aes128 udp: too short")
		}
		hmacFunc := tools.HmacSHA1
		if s.cfg.Protocol == "auth_aes128_md5" {
			hmacFunc = tools.HmacMD5
		}
		expectedHMAC := hmacFunc(s.userKey, b[:len(b)-4])[:4]
		if !hmac.Equal(expectedHMAC, b[len(b)-4:]) {
			return nil, errors.New("auth_aes128 udp: hmac mismatch")
		}
		return b[:len(b)-8], nil

	case "auth_chain_a", "auth_chain_b":
		if len(b) < 8 {
			return nil, errors.New("auth_chain udp: too short")
		}
		if !hmac.Equal(tools.HmacMD5(s.userKey, b[:len(b)-1])[:1], b[len(b)-1:]) {
			return nil, errors.New("auth_chain udp: hmac mismatch")
		}
		authData := b[len(b)-8 : len(b)-5]
		md5Data := tools.HmacMD5(s.key, authData)
		var randClient tools.XorShift128Plus
		randClient.InitFromBin(md5Data)
		randLen := int(randClient.Next() % 127)

		key := core.Kdf(base64.StdEncoding.EncodeToString(s.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
		rc4Cipher, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(b) < 8+randLen {
			return nil, errors.New("auth_chain udp: packet too short for randLen")
		}
		wanted := b[:len(b)-8-randLen]
		rc4Cipher.XORKeyStream(wanted, wanted)
		return wanted, nil

	default:
		return b, nil
	}
}

func (s *SSRMockServer) serverEncodeUDPPacket(b []byte) ([]byte, error) {
	switch s.cfg.Protocol {
	case "origin", "auth_sha1_v4":
		return b, nil

	case "auth_aes128_md5", "auth_aes128_sha1":
		hmacFunc := tools.HmacSHA1
		if s.cfg.Protocol == "auth_aes128_md5" {
			hmacFunc = tools.HmacMD5
		}
		tag := hmacFunc(s.key, b)[:4]
		return append(b, tag...), nil

	case "auth_chain_a", "auth_chain_b":
		authData := make([]byte, 7)
		_, _ = crand.Read(authData)
		md5Data := tools.HmacMD5(s.key, authData)

		var randServer tools.XorShift128Plus
		randServer.InitFromBin(md5Data)
		randLen := int(randServer.Next() % 127)

		key := core.Kdf(base64.StdEncoding.EncodeToString(s.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
		rc4Cipher, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		enc := make([]byte, len(b))
		rc4Cipher.XORKeyStream(enc, b)

		buf := append([]byte(nil), enc...)
		if randLen > 0 {
			randBytes := make([]byte, randLen)
			_, _ = crand.Read(randBytes)
			buf = append(buf, randBytes...)
		}
		buf = append(buf, authData...)
		tag := tools.HmacMD5(s.userKey, buf)[:1]
		buf = append(buf, tag...)
		return buf, nil

	default:
		return b, nil
	}
}

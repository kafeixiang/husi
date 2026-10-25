package trojango

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	payloadSizeMask = 0x3FFF // 16*1024 - 1
)

type SSCipher struct {
	method      string
	saltSize    int
	key         []byte
	constructor func(key []byte) (cipher.AEAD, error)
}

func kdf(password []byte, keySize int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keySize {
		h.Write(prev)
		h.Write(password)
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keySize]
}

func NewSSCipher(method, password string) (*SSCipher, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	c := &SSCipher{method: method}
	switch method {
	case "aes-128-gcm":
		c.saltSize = 16
		c.constructor = func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	case "aes-192-gcm":
		c.saltSize = 24
		c.constructor = func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	case "aes-256-gcm":
		c.saltSize = 32
		c.constructor = func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	case "chacha20-ietf-poly1305":
		c.saltSize = 32
		c.constructor = chacha20poly1305.New
	default:
		return nil, fmt.Errorf("unsupported shadowsocks method: %s", method)
	}

	c.key = kdf([]byte(password), c.saltSize)
	return c, nil
}

func (c *SSCipher) deriveSubkey(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.saltSize)
	kdfReader := hkdf.New(sha1.New, c.key, salt, []byte("ss-subkey"))
	if _, err := io.ReadFull(kdfReader, subkey); err != nil {
		return nil, err
	}
	return c.constructor(subkey)
}

func (c *SSCipher) StreamConn(conn net.Conn) net.Conn {
	return &ssStreamConn{
		Conn:   conn,
		cipher: c,
	}
}

type ssStreamConn struct {
	net.Conn
	cipher *SSCipher
	r      *ssReader
	w      *ssWriter
	rMu    sync.Mutex
	wMu    sync.Mutex
}

func (c *ssStreamConn) initReader() error {
	salt := make([]byte, c.cipher.saltSize)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := c.cipher.deriveSubkey(salt)
	if err != nil {
		return err
	}
	c.r = newSSReader(c.Conn, aead)
	return nil
}

func (c *ssStreamConn) Read(b []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *ssStreamConn) initWriter() error {
	salt := make([]byte, c.cipher.saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	aead, err := c.cipher.deriveSubkey(salt)
	if err != nil {
		return err
	}
	if _, err := c.Conn.Write(salt); err != nil {
		return err
	}
	c.w = newSSWriter(c.Conn, aead)
	return nil
}

func (c *ssStreamConn) Write(b []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

type ssWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	nonce []byte
	buf   []byte
}

func newSSWriter(w io.Writer, aead cipher.AEAD) *ssWriter {
	return &ssWriter{
		w:     w,
		aead:  aead,
		buf:   make([]byte, 2+aead.Overhead()+payloadSizeMask+aead.Overhead()),
		nonce: make([]byte, aead.NonceSize()),
	}
}

func (w *ssWriter) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewReader(b))
	return int(n), err
}

func (w *ssWriter) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	for {
		offset := 2 + w.aead.Overhead()
		payloadBuf := w.buf[offset : offset+payloadSizeMask]
		nr, er := r.Read(payloadBuf)
		if nr > 0 {
			total += int64(nr)
			w.buf[0], w.buf[1] = byte(nr>>8), byte(nr)
			w.aead.Seal(w.buf[:0], w.nonce, w.buf[:2], nil)
			incrementNonce(w.nonce)

			w.aead.Seal(payloadBuf[:0], w.nonce, payloadBuf[:nr], nil)
			incrementNonce(w.nonce)

			chunkLen := offset + nr + w.aead.Overhead()
			if _, ew := w.w.Write(w.buf[:chunkLen]); ew != nil {
				return total, ew
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			return total, er
		}
	}
	return total, nil
}

type ssReader struct {
	r        io.Reader
	aead     cipher.AEAD
	nonce    []byte
	buf      []byte
	leftover []byte
}

func newSSReader(r io.Reader, aead cipher.AEAD) *ssReader {
	return &ssReader{
		r:     r,
		aead:  aead,
		buf:   make([]byte, payloadSizeMask+aead.Overhead()),
		nonce: make([]byte, aead.NonceSize()),
	}
}

func (r *ssReader) readChunk() (int, error) {
	lenBuf := r.buf[:2+r.aead.Overhead()]
	if _, err := io.ReadFull(r.r, lenBuf); err != nil {
		return 0, err
	}
	_, err := r.aead.Open(lenBuf[:0], r.nonce, lenBuf, nil)
	incrementNonce(r.nonce)
	if err != nil {
		return 0, err
	}

	size := (int(lenBuf[0])<<8 | int(lenBuf[1])) & payloadSizeMask
	payloadBuf := r.buf[:size+r.aead.Overhead()]
	if _, err := io.ReadFull(r.r, payloadBuf); err != nil {
		return 0, err
	}
	_, err = r.aead.Open(payloadBuf[:0], r.nonce, payloadBuf, nil)
	incrementNonce(r.nonce)
	if err != nil {
		return 0, err
	}
	return size, nil
}

func (r *ssReader) Read(b []byte) (int, error) {
	if len(r.leftover) > 0 {
		n := copy(b, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}

	n, err := r.readChunk()
	if err != nil {
		return 0, err
	}
	m := copy(b, r.buf[:n])
	if m < n {
		r.leftover = r.buf[m:n]
	}
	return m, nil
}

func incrementNonce(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

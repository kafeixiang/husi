package core

import (
	"crypto/md5"
	"errors"
	"net"
	"sort"
	"strings"

	N "github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/net"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/ssr/internal/shadowstream"
)

type Cipher interface {
	StreamConnCipher
	PacketConnCipher
}

type StreamConnCipher interface {
	StreamConn(net.Conn) net.Conn
}

type PacketConnCipher interface {
	PacketConn(N.EnhancePacketConn) N.EnhancePacketConn
}

var ErrCipherNotSupported = errors.New("cipher not supported")

type streamCipherEntry struct {
	KeySize int
	New     func(key []byte) (shadowstream.Cipher, error)
}

func extraCipherFactory(name string) func(key []byte) (shadowstream.Cipher, error) {
	return func(k []byte) (shadowstream.Cipher, error) {
		return shadowstream.NewExtraCipher(name, k)
	}
}

var streamList = map[string]streamCipherEntry{
	"AES-128-CTR":       {16, shadowstream.AESCTR},
	"AES-192-CTR":       {24, shadowstream.AESCTR},
	"AES-256-CTR":       {32, shadowstream.AESCTR},
	"AES-128-CFB":       {16, shadowstream.AESCFB},
	"AES-192-CFB":       {24, shadowstream.AESCFB},
	"AES-256-CFB":       {32, shadowstream.AESCFB},
	"AES-128-CFB8":      {16, extraCipherFactory("AES-128-CFB8")},
	"AES-192-CFB8":      {24, extraCipherFactory("AES-192-CFB8")},
	"AES-256-CFB8":      {32, extraCipherFactory("AES-256-CFB8")},
	"AES-128-OFB":       {16, extraCipherFactory("AES-128-OFB")},
	"AES-192-OFB":       {24, extraCipherFactory("AES-192-OFB")},
	"AES-256-OFB":       {32, extraCipherFactory("AES-256-OFB")},
	"CAMELLIA-128-CFB":  {16, extraCipherFactory("CAMELLIA-128-CFB")},
	"CAMELLIA-192-CFB":  {24, extraCipherFactory("CAMELLIA-192-CFB")},
	"CAMELLIA-256-CFB":  {32, extraCipherFactory("CAMELLIA-256-CFB")},
	"CAMELLIA-128-CFB8": {16, extraCipherFactory("CAMELLIA-128-CFB8")},
	"CAMELLIA-192-CFB8": {24, extraCipherFactory("CAMELLIA-192-CFB8")},
	"CAMELLIA-256-CFB8": {32, extraCipherFactory("CAMELLIA-256-CFB8")},
	"RC4-MD5":           {16, shadowstream.RC4MD5},
	"RC4-MD5-6":         {16, extraCipherFactory("RC4-MD5-6")},
	"RC4":               {16, extraCipherFactory("RC4")},
	"BF-CFB":            {16, extraCipherFactory("BF-CFB")},
	"CAST5-CFB":         {16, extraCipherFactory("CAST5-CFB")},
	"DES-CFB":           {8, extraCipherFactory("DES-CFB")},
	"IDEA-CFB":          {16, extraCipherFactory("IDEA-CFB")},
	"RC2-CFB":           {16, extraCipherFactory("RC2-CFB")},
	"SEED-CFB":          {16, extraCipherFactory("SEED-CFB")},
	"CHACHA20-IETF":     {32, shadowstream.Chacha20IETF},
	"XCHACHA20":         {32, shadowstream.Xchacha20},
	"CHACHA20":          {32, shadowstream.ChaCha20},
	"XSALSA20":          {32, extraCipherFactory("XSALSA20")},
	"SALSA20":           {32, extraCipherFactory("SALSA20")},
	"TABLE":             {16, shadowstream.Table},
	"RABBIT":            {16, extraCipherFactory("RABBIT")},
	"HC128":             {16, extraCipherFactory("HC128")},
	"ZUC128":            {16, extraCipherFactory("ZUC128")},
}

func ListCipher() []string {
	var l []string
	for k := range streamList {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

func PickCipher(name string, key []byte, password string) (Cipher, error) {
	name = strings.ToUpper(strings.ReplaceAll(name, "_", "-"))

	switch name {
	case "DUMMY", "NONE", "PLAIN":
		return &dummy{}, nil
	}

	if choice, ok := streamList[name]; ok {
		if len(key) == 0 {
			key = Kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadowstream.KeySizeError(choice.KeySize)
		}
		ciph, err := choice.New(key)
		return &StreamCipher{Cipher: ciph, Key: key}, err
	}

	return nil, ErrCipherNotSupported
}

type StreamCipher struct {
	shadowstream.Cipher

	Key []byte
}

func (ciph *StreamCipher) StreamConn(c net.Conn) net.Conn { return shadowstream.NewConn(c, ciph) }
func (ciph *StreamCipher) PacketConn(c N.EnhancePacketConn) N.EnhancePacketConn {
	return shadowstream.NewPacketConn(c, ciph)
}

type dummy struct{}

func (dummy) StreamConn(c net.Conn) net.Conn                       { return c }
func (dummy) PacketConn(c N.EnhancePacketConn) N.EnhancePacketConn { return c }

func Kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

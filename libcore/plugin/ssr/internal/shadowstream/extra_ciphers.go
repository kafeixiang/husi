package shadowstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"

	"github.com/deatil/go-cryptobin/cipher/camellia"
	"github.com/deatil/go-cryptobin/cipher/hc"
	"github.com/deatil/go-cryptobin/cipher/idea"
	"github.com/deatil/go-cryptobin/cipher/rabbit"
	"github.com/deatil/go-cryptobin/cipher/rc2"
	"github.com/deatil/go-cryptobin/cipher/salsa20"
	"github.com/deatil/go-cryptobin/cipher/seed"
	"github.com/deatil/go-cryptobin/cipher/xsalsa20"
	"github.com/deatil/go-cryptobin/mode"
	"github.com/emmansun/gmsm/zuc"
	"golang.org/x/crypto/blowfish" //nolint:staticcheck
	"golang.org/x/crypto/cast5"    //nolint:staticcheck
)

type extraCipher struct {
	keyLen     int
	ivLen      int
	encFactory func(key []byte, iv []byte) (cipher.Stream, error)
	decFactory func(key []byte, iv []byte) (cipher.Stream, error)
	key        []byte
}

func (c *extraCipher) IVSize() int {
	return c.ivLen
}

func (c *extraCipher) Encrypter(iv []byte) cipher.Stream {
	s, _ := c.encFactory(c.key, iv)
	return s
}

func (c *extraCipher) Decrypter(iv []byte) cipher.Stream {
	s, _ := c.decFactory(c.key, iv)
	return s
}

//nolint:staticcheck
func blockCFBEnc(blockCreator func([]byte) (cipher.Block, error)) func([]byte, []byte) (cipher.Stream, error) {
	return func(key, iv []byte) (cipher.Stream, error) {
		blk, err := blockCreator(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewCFBEncrypter(blk, iv), nil
	}
}

//nolint:staticcheck
func blockCFBDec(blockCreator func([]byte) (cipher.Block, error)) func([]byte, []byte) (cipher.Stream, error) {
	return func(key, iv []byte) (cipher.Stream, error) {
		blk, err := blockCreator(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewCFBDecrypter(blk, iv), nil
	}
}

func blockCFB8Enc(blockCreator func([]byte) (cipher.Block, error)) func([]byte, []byte) (cipher.Stream, error) {
	return func(key, iv []byte) (cipher.Stream, error) {
		blk, err := blockCreator(key)
		if err != nil {
			return nil, err
		}
		return mode.NewCFB8Encrypter(blk, iv), nil
	}
}

func blockCFB8Dec(blockCreator func([]byte) (cipher.Block, error)) func([]byte, []byte) (cipher.Stream, error) {
	return func(key, iv []byte) (cipher.Stream, error) {
		blk, err := blockCreator(key)
		if err != nil {
			return nil, err
		}
		return mode.NewCFB8Decrypter(blk, iv), nil
	}
}

//nolint:staticcheck
func blockOFB(blockCreator func([]byte) (cipher.Block, error)) func([]byte, []byte) (cipher.Stream, error) {
	return func(key, iv []byte) (cipher.Stream, error) {
		blk, err := blockCreator(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewOFB(blk, iv), nil
	}
}

func NewExtraCipher(name string, key []byte) (Cipher, error) {
	enc := blockCFBEnc
	dec := blockCFBDec
	enc8 := blockCFB8Enc
	dec8 := blockCFB8Dec
	ofb := blockOFB

	switch name {
	case "AES-128-CFB8":
		return &extraCipher{16, 16, enc8(aes.NewCipher), dec8(aes.NewCipher), key}, nil
	case "AES-192-CFB8":
		return &extraCipher{24, 16, enc8(aes.NewCipher), dec8(aes.NewCipher), key}, nil
	case "AES-256-CFB8":
		return &extraCipher{32, 16, enc8(aes.NewCipher), dec8(aes.NewCipher), key}, nil

	case "AES-128-OFB":
		return &extraCipher{16, 16, ofb(aes.NewCipher), ofb(aes.NewCipher), key}, nil
	case "AES-192-OFB":
		return &extraCipher{24, 16, ofb(aes.NewCipher), ofb(aes.NewCipher), key}, nil
	case "AES-256-OFB":
		return &extraCipher{32, 16, ofb(aes.NewCipher), ofb(aes.NewCipher), key}, nil

	case "CAMELLIA-128-CFB":
		return &extraCipher{16, 16, enc(camellia.NewCipher), dec(camellia.NewCipher), key}, nil
	case "CAMELLIA-192-CFB":
		return &extraCipher{24, 16, enc(camellia.NewCipher), dec(camellia.NewCipher), key}, nil
	case "CAMELLIA-256-CFB":
		return &extraCipher{32, 16, enc(camellia.NewCipher), dec(camellia.NewCipher), key}, nil

	case "CAMELLIA-128-CFB8":
		return &extraCipher{16, 16, enc8(camellia.NewCipher), dec8(camellia.NewCipher), key}, nil
	case "CAMELLIA-192-CFB8":
		return &extraCipher{24, 16, enc8(camellia.NewCipher), dec8(camellia.NewCipher), key}, nil
	case "CAMELLIA-256-CFB8":
		return &extraCipher{32, 16, enc8(camellia.NewCipher), dec8(camellia.NewCipher), key}, nil

	case "RC4-MD5-6":
		return &extraCipher{16, 6, rc4Md5Factory, rc4Md5Factory, key}, nil
	case "RC4":
		return &extraCipher{16, 0, rc4Factory, rc4Factory, key}, nil

	case "BF-CFB":
		bf := func(k []byte) (cipher.Block, error) { return blowfish.NewCipher(k) }
		return &extraCipher{16, 8, enc(bf), dec(bf), key}, nil
	case "CAST5-CFB":
		c5 := func(k []byte) (cipher.Block, error) { return cast5.NewCipher(k) }
		return &extraCipher{16, 8, enc(c5), dec(c5), key}, nil
	case "DES-CFB":
		d := func(k []byte) (cipher.Block, error) { return des.NewCipher(k) }
		return &extraCipher{8, 8, enc(d), dec(d), key}, nil
	case "IDEA-CFB":
		id := func(k []byte) (cipher.Block, error) { return idea.NewCipher(k) }
		return &extraCipher{16, 8, enc(id), dec(id), key}, nil
	case "RC2-CFB":
		r2 := func(k []byte) (cipher.Block, error) { return rc2.NewCipher(k, 16) }
		return &extraCipher{16, 8, enc(r2), dec(r2), key}, nil
	case "SEED-CFB":
		sd := func(k []byte) (cipher.Block, error) { return seed.NewCipher(k) }
		return &extraCipher{16, 16, enc(sd), dec(sd), key}, nil

	case "XSALSA20":
		return &extraCipher{32, 24, xsalsa20Factory, xsalsa20Factory, key}, nil
	case "SALSA20":
		return &extraCipher{32, 8, salsa20Factory, salsa20Factory, key}, nil
	case "RABBIT":
		return &extraCipher{16, 8, rabbitFactory, rabbitFactory, key}, nil
	case "HC128":
		return &extraCipher{16, 16, hc128Factory, hc128Factory, key}, nil
	case "ZUC128":
		return &extraCipher{16, 16, zuc128Factory, zuc128Factory, key}, nil
	}
	return nil, ErrShortPacket
}

func rc4Md5Factory(key, iv []byte) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	return rc4.NewCipher(h.Sum(nil))
}

func rc4Factory(key, iv []byte) (cipher.Stream, error) {
	return rc4.NewCipher(key)
}

func xsalsa20Factory(key, iv []byte) (cipher.Stream, error) {
	return xsalsa20.NewCipher(key, iv)
}

func salsa20Factory(key, iv []byte) (cipher.Stream, error) {
	return salsa20.NewCipher(key, iv)
}

func rabbitFactory(key, iv []byte) (cipher.Stream, error) {
	return rabbit.NewCipher(key, iv)
}

func hc128Factory(key, iv []byte) (cipher.Stream, error) {
	return hc.NewCipher(key, iv)
}

func zuc128Factory(key, iv []byte) (cipher.Stream, error) {
	return zuc.NewCipher(key, iv)
}

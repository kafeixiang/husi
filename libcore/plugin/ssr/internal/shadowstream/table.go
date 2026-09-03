package shadowstream

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"sort"
)

type TableCipher struct {
	key []byte
	enc tableCipherStream
	dec tableCipherStream
}

type tableCipherStream []byte

func (t tableCipherStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		dst[i] = t[src[i]]
	}
}

func (t *TableCipher) IVSize() int { return 0 }

func (t *TableCipher) Encrypter(iv []byte) cipher.Stream {
	return t.enc
}

func (t *TableCipher) Decrypter(iv []byte) cipher.Stream {
	return t.dec
}

func Table(key []byte) (Cipher, error) {
	enc, dec := newTableCipher(key)
	return &TableCipher{
		key: key,
		enc: enc,
		dec: dec,
	}, nil
}

const tableSize = 256

func newTableCipher(key []byte) (enc, dec tableCipherStream) {
	enc = make([]byte, tableSize)
	dec = make([]byte, tableSize)
	table := make([]uint64, tableSize)

	var a uint64
	buf := bytes.NewBuffer(key)
	_ = binary.Read(buf, binary.LittleEndian, &a)
	for i := uint64(0); i < tableSize; i++ {
		table[i] = i
	}
	for i := uint64(1); i < 1024; i++ {
		step := i
		sort.SliceStable(table, func(x, y int) bool {
			return int64(a%(table[x]+step)-a%(table[y]+step)) < 0
		})
	}
	for i := 0; i < tableSize; i++ {
		enc[i] = byte(table[i])
	}
	for i := 0; i < tableSize; i++ {
		dec[enc[i]] = byte(i)
	}
	return enc, dec
}

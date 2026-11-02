package shadowstream

import (
	"crypto/cipher"
	"crypto/md5"
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
	for i := range len(src) {
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

	h := md5.Sum(key)
	a := binary.LittleEndian.Uint64(h[:8])
	for i := range uint64(tableSize) {
		table[i] = i
	}
	for i := uint64(1); i < 1024; i++ {
		step := i
		sort.SliceStable(table, func(x, y int) bool {
			return a%(table[x]+step) < a%(table[y]+step)
		})
	}
	for i := range tableSize {
		enc[i] = byte(table[i])
	}
	for i := range tableSize {
		dec[enc[i]] = byte(i)
	}
	return enc, dec
}

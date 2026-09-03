package shadowstream

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20"
)

func newChaCha20(nonce, key []byte) cipher.Stream {
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	return c
}

type chacha20key []byte

func (k chacha20key) IVSize() int                       { return chacha20.NonceSize }
func (k chacha20key) Encrypter(iv []byte) cipher.Stream { return newChaCha20(iv, k) }
func (k chacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }

func ChaCha20(key []byte) (Cipher, error) {
	if len(key) != chacha20.KeySize {
		return nil, KeySizeError(chacha20.KeySize)
	}
	return chacha20key(key), nil
}

type chacha20ietfkey []byte

func (k chacha20ietfkey) IVSize() int                       { return chacha20.NonceSize }
func (k chacha20ietfkey) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k chacha20ietfkey) Encrypter(iv []byte) cipher.Stream { return newChaCha20(iv, k) }

func Chacha20IETF(key []byte) (Cipher, error) {
	if len(key) != chacha20.KeySize {
		return nil, KeySizeError(chacha20.KeySize)
	}
	return chacha20ietfkey(key), nil
}

type xchacha20key []byte

func (k xchacha20key) IVSize() int                       { return chacha20.NonceSizeX }
func (k xchacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k xchacha20key) Encrypter(iv []byte) cipher.Stream { return newChaCha20(iv, k) }

func Xchacha20(key []byte) (Cipher, error) {
	if len(key) != chacha20.KeySize {
		return nil, KeySizeError(chacha20.KeySize)
	}
	return xchacha20key(key), nil
}

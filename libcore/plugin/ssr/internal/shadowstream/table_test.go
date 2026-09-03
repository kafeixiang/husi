package shadowstream

import (
	"bytes"
	"testing"
)

func TestTableCipher(t *testing.T) {
	key := []byte("1234567890123456")
	ciph, err := Table(key)
	if err != nil {
		t.Fatalf("Table error: %v", err)
	}

	enc := ciph.Encrypter(nil)
	dec := ciph.Decrypter(nil)

	plain := []byte("hello table cipher test 123456")
	cipherText := make([]byte, len(plain))
	decrypted := make([]byte, len(plain))

	enc.XORKeyStream(cipherText, plain)
	dec.XORKeyStream(decrypted, cipherText)

	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("decrypted %s != plain %s", decrypted, plain)
	}
}

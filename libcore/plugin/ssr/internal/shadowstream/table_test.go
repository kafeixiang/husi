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

func TestTablePythonCompat(t *testing.T) {
	// target1 from official shadowsocks table.py for key "foobar!"
	wantEnc := []byte{
		60, 53, 84, 138, 217, 94, 88, 23, 39, 242, 219, 35, 12, 157, 165, 181,
		255, 143, 83, 247, 162, 16, 31, 209, 190, 171, 115, 65, 38, 41, 21,
		245, 236, 46, 121, 62, 166, 233, 44, 154, 153, 145, 230, 49, 128, 216,
	}

	enc1, _ := newTableCipher([]byte("foobar!"))
	for i := 0; i < len(wantEnc); i++ {
		if enc1[i] != wantEnc[i] {
			t.Fatalf("mismatch at %d: got %d, want %d", i, enc1[i], wantEnc[i])
		}
	}
}

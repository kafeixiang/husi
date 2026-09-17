package protocol

import (
	"testing"
)

func TestPickProtocol(t *testing.T) {
	protocols := []string{
		"origin",
		"auth_sha1_v4",
		"auth_aes128_md5",
		"auth_aes128_sha1",
		"auth_chain_a",
		"auth_chain_b",
	}

	base := &Base{
		Key:      []byte("1234567890123456"),
		Overhead: 10,
		Param:    "123:userkey",
	}

	for _, name := range protocols {
		t.Run(name, func(t *testing.T) {
			p, err := PickProtocol(name, base)
			if err != nil {
				t.Fatalf("PickProtocol(%s) error: %v", name, err)
			}
			if p == nil {
				t.Fatalf("PickProtocol(%s) returned nil", name)
			}
		})
	}

	_, err := PickProtocol("invalid_protocol", base)
	if err == nil {
		t.Fatalf("expected error for invalid protocol")
	}
}

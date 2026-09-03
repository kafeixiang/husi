package obfs

import (
	"testing"
)

func TestPickObfs(t *testing.T) {
	obfses := []string{
		"plain",
		"http_post",
		"http_simple",
		"random_head",
		"tls1.2_ticket_auth",
		"tls1.2_ticket_fastauth",
	}

	base := &Base{
		Host:   "example.com",
		Port:   443,
		Key:    []byte("1234567890123456"),
		IVSize: 16,
		Param:  "test.com",
	}

	for _, name := range obfses {
		t.Run(name, func(t *testing.T) {
			o, _, err := PickObfs(name, base)
			if err != nil {
				t.Fatalf("PickObfs(%s) error: %v", name, err)
			}
			if o == nil {
				t.Fatalf("PickObfs(%s) returned nil", name)
			}
		})
	}

	_, _, err := PickObfs("invalid_obfs", base)
	if err == nil {
		t.Fatalf("expected error for invalid obfs")
	}
}

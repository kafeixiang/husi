package libcore

import (
	"strings"
	"testing"

	"filippo.io/age"
)

func TestValidateAgeIdentities(t *testing.T) {
	x25519Identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybridIdentity, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		text    string
		wantErr bool
	}{
		{
			name:    "single identity",
			text:    x25519Identity.String(),
			wantErr: false,
		},
		{
			name:    "multiple identities",
			text:    strings.Join([]string{x25519Identity.String(), hybridIdentity.String()}, "\n"),
			wantErr: false,
		},
		{
			name:    "blank",
			text:    "",
			wantErr: true,
		},
		{
			name:    "recipient is not identity",
			text:    x25519Identity.Recipient().String(),
			wantErr: true,
		},
		{
			name:    "invalid text",
			text:    "AGE-SECRET-KEY-1INVALID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAgeIdentities(tt.text)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAgeIdentities() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

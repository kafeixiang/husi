package libcore

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAgeIdentities(t *testing.T) {
	x25519Identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	hybridIdentity, err := age.GenerateHybridIdentity()
	require.NoError(t, err)

	tests := []struct {
		name    string
		text    string
		wantErr bool
	}{
		{
			name:    "x25519 identity",
			text:    x25519Identity.String(),
			wantErr: false,
		},
		{
			name:    "hybrid identity",
			text:    hybridIdentity.String(),
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
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAgeArmorDecrypt(t *testing.T) {
	identity1, err := age.GenerateHybridIdentity()
	require.NoError(t, err)
	identity2, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	plaintext := []byte("What the dog doing?")

	// Encrypt with identity1's recipient
	var encryptedBuf bytes.Buffer
	armorWriter := armor.NewWriter(&encryptedBuf)
	w, err := age.Encrypt(armorWriter, identity1.Recipient())
	require.NoError(t, err)
	_, err = w.Write(plaintext)
	require.NoError(t, err)
	err = w.Close()
	require.NoError(t, err)
	err = armorWriter.Close()
	require.NoError(t, err)
	encryptedData := encryptedBuf.Bytes()

	tests := []struct {
		name       string
		identities []age.Identity
		wantErr    bool
	}{
		{
			name:       "decrypt with correct identity",
			identities: []age.Identity{identity1},
			wantErr:    false,
		},
		{
			name:       "decrypt with multiple identities (first matches)",
			identities: []age.Identity{identity1, identity2},
			wantErr:    false,
		},
		{
			name:       "decrypt with multiple identities (second matches)",
			identities: []age.Identity{identity2, identity1},
			wantErr:    false,
		},
		{
			name:       "decrypt with wrong identity",
			identities: []age.Identity{identity2},
			wantErr:    true,
		},
		{
			name:       "decrypt with no identities",
			identities: []age.Identity{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := newAgeArmorDecryptReader(bytes.NewReader(encryptedData), tt.identities)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			decrypted, err := io.ReadAll(reader)
			require.NoError(t, err)

			assert.Equal(t, plaintext, decrypted)
		})
	}
}

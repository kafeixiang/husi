package libcore

import (
	"bytes"
	"errors"
	"io"

	E "github.com/sagernet/sing/common/exceptions"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func ValidateAgeIdentities(text string) error {
	_, err := parseAgeIdentities(text)
	return err
}

func parseAgeIdentities(text string) ([]age.Identity, error) {
	return age.ParseIdentities(bytes.NewReader([]byte(text)))
}

func newAgeArmorDecryptReader(reader io.Reader, identities []age.Identity) (io.Reader, error) {
	reader = armor.NewReader(reader)

	var err error
	for i, identity := range identities {
		reader, err = age.Decrypt(reader, identity)
		if err != nil {
			return nil, E.Cause(wrapAgeError(err), "age decrypt at ", i)
		}
	}
	return reader, nil
}

func wrapAgeError(err error) error {
	if _, isNoIdentityMatchError := errors.AsType[*age.NoIdentityMatchError](err); isNoIdentityMatchError {
		return E.Cause(err, "identity did not match payload")
	}
	return err
}

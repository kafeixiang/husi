package tools

import (
	"bytes"
	"crypto/rand"
	"io"
)

func AppendRandBytes(b *bytes.Buffer, length int) {
	_, _ = b.ReadFrom(io.LimitReader(rand.Reader, int64(length)))
}

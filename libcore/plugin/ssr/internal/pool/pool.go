package pool

import (
	"bytes"
	"sync"
)

const (
	RelayBufferSize = 2048
	UDPBufferSize   = 2048
)

var bufferPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

func Get(size int) []byte {
	return make([]byte, size)
}

func Put(buf []byte) {
	// Memory buffer cleanup if pool implementation expands
}

func GetBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func PutBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}

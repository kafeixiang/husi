package pool

import (
	"errors"
	"math/bits"
	"sync"
)

var defaultAllocator = NewAllocator()

type Allocator struct {
	buffers []sync.Pool
}

func NewAllocator() *Allocator {
	alloc := new(Allocator)
	alloc.buffers = make([]sync.Pool, 17) // 1B -> 64K
	for k := range alloc.buffers {
		i := k
		alloc.buffers[k].New = func() any {
			return make([]byte, 1<<uint32(i))
		}
	}
	return alloc
}

func (alloc *Allocator) Get(size int) []byte {
	switch {
	case size < 0:
		panic("alloc.Get: len out of range")
	case size == 0:
		return nil
	case size > 65536:
		return make([]byte, size)
	default:
		bits := msb(size)
		if size == 1<<bits {
			return alloc.buffers[bits].Get().([]byte)[:size]
		}

		return alloc.buffers[bits+1].Get().([]byte)[:size]
	}
}

func (alloc *Allocator) Put(buf []byte) error {
	if cap(buf) == 0 || cap(buf) > 65536 {
		return nil
	}

	bits := msb(cap(buf))
	if cap(buf) != 1<<bits {
		return errors.New("allocator Put() incorrect buffer size")
	}

	alloc.buffers[bits].Put(buf)
	return nil
}

func msb(size int) uint16 {
	return uint16(bits.Len32(uint32(size)) - 1)
}

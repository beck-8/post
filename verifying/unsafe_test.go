package verifying

import (
	"testing"
	"unsafe"
)

type T struct {
	Counter uint64
	Label1  byte
	Label2  byte
	Label3  byte
	Label4  byte
	Padding [4]byte
}

func Benchmark_ByteConv(b *testing.B) {
	t1 := &T{1, 0xa0, 0xb0, 0xc0, 0xd0, [4]byte{}}
	size := unsafe.Sizeof(*t1)
	b.Log(size)
	b.Logf("%#v\n", t1)

	data := (*(*[1<<31 - 1]byte)(unsafe.Pointer(t1)))[:size]
	b.Logf("%#v\n", data)

	t2 := (*T)(unsafe.Pointer(&data[0]))
	b.Logf("%#v\n", t2)
}

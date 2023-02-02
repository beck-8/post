package oracle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"runtime"
	"testing"
)

func Benchmark_CTR(b *testing.B) {
	key := []byte("challenge and nonce as key!!!!!!")

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	chans := make([]chan struct{}, 0, runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		ch := make(chan struct{})
		chans = append(chans, ch)
	}

	b.StartTimer()
	for i := 0; i < runtime.NumCPU(); i++ {
		go func(i int) {
			out := make([]byte, c.BlockSize())
			in := make([]byte, c.BlockSize())
			ctrHash(c, chans[i], out, in, (1<<30)*(i-1), (1<<30)*i-1)
			_ = out
		}(i)
	}

	for _, ch := range chans {
		<-ch
	}
	b.StopTimer()

	b.Log("calculated", 1<<30*runtime.NumCPU(), "hashes")
}

func ctrHash(c cipher.Block, ch chan struct{}, out, in []byte, start, end int) chan struct{} {
	iv := make([]byte, c.BlockSize())
	binary.BigEndian.PutUint64(iv[:8], uint64(start))
	ctr := cipher.NewCTR(c, iv)

	for i := start; i < end; i++ {
		binary.BigEndian.PutUint64(in[:8], uint64(i)) // the label in our case just one byte (unless we change it)
		ctr.XORKeyStream(out, in)
	}
	close(ch)
	return ch
}

func Benchmark_Sha(b *testing.B) {
	key := []byte("challenge and nonce as key!!!!!!")

	out := make([]byte, sha256.Size)
	in := make([]byte, 0, len(key)+8+16)

	sha := sha256.New()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		sha.Reset()
		in = append(in[:0], key...)
		binary.BigEndian.PutUint64(in[len(key):len(key)+8], uint64(i))

		label := []byte(fmt.Sprintf("label %10d", i)) // the label in our case just one byte (unless we change it)
		in = append(in, label...)
		sha.Write(in)
		sha.Sum(out)
	}
	_ = hex.EncodeToString(out)
	b.StopTimer()
}

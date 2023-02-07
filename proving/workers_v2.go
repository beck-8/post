package proving

import (
	"context"
	"crypto/aes"
	"encoding/binary"
	"log"
	"math"

	"github.com/zeebo/blake3"
)

const N = 256 * 1024 * 1024 * 1024
const B = 16
const numNonces = 20

type IndexReporterNew interface {
	Report(ctx context.Context, nonce uint32, idx uint64) (stop bool)
}

func le40(b []byte) uint64 {
	_ = b[4]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32
}

// Get an uint64 that consists of 34 bits from the data slice starting from bit i.
func le34(data []byte, i uint) uint64 {
	if int(i) > (len(data)*8)-34 {
		log.Panicf("index is out of range (%d > %d)", i, (len(data)*8)-34)
	}
	b := data[i/8 : (i/8)+5]
	x := binary.LittleEndian.Uint32(b)
	// Combine the two values into an uint64
	z := uint64(x) | uint64(b[4])<<32
	// Shift the result to the right by the remaining bits
	z = z >> (i % 8)
	// Return the 34 bits from the data slice
	return z & 0x3FFFFFFFFFFFF
}

func workNewBlakeD40(ctx context.Context, data <-chan *batch, reporter IndexReporterNew, ch Challenge, difficulty []byte) {
	const m = 512 // Blake's output size in bits
	const d = 40  // padded to 40 bits
	const dsize = d / 8

	h := blake3.New()
	out := make([]byte, dsize*numNonces)
	difficultyVal := le40(difficulty)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			block := labels[:B]
			labels = labels[B:]

			{
				h.Reset()
				h.Write(ch)
				h.Write(block)
				h.Write([]byte{0})
				d := h.Digest()
				d.Read(out) // streams variable length output
			}

			for i := 0; i < numNonces; i++ {
				// padded to 5 bytes to avoid bit arithmetic
				if le40(out[i*dsize:]) <= difficultyVal {
					reporter.Report(ctx, uint32(i), index)
				}
			}
			index++
		}
		batch.Release()
	}
}

func workNewBlake(ctx context.Context, data <-chan *batch, reporter IndexReporterNew, ch Challenge, difficulty []byte) {
	const m = 512 // Blake's output size in bits
	// d: |d| = log2(N) - log2(B). Assumed both N and B are power of 2.
	const d = 34
	// numOuts = ceil(numNonces * |d| / m )
	numOuts := uint8(math.Ceil(float64(numNonces*d) / m))

	h := blake3.New()
	out := make([]byte, numOuts*64)
	difficultyVal := le34(difficulty, 0)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			block := labels[:B]
			labels = labels[B:]

			for i := uint8(0); i < numOuts; i++ {
				h.Reset()
				h.Write(ch)
				h.Write(block)
				h.Write([]byte{i})
				d := h.Digest()
				d.Read(out[i*64 : i*64+64])
			}

			for j := uint(0); j < numNonces; j++ {
				val := le34(out, j*d)
				if val <= difficultyVal {
					if stop := reporter.Report(ctx, uint32(j), index); stop {
						batch.Release()
						return
					}
				}
			}
			index++
		}
		batch.Release()
	}
}

func workNewBlakeD34BiggerOutSize(ctx context.Context, data <-chan *batch, reporter IndexReporterNew, ch Challenge, difficulty []byte) {
	const m = 512 // Blake's output size in bits
	// d: |d| = log2(N) - log2(B). Assumed both N and B are power of 2.
	const d = 34
	// numOuts = ceil(numNonces * |d| / m )
	numOuts := uint8(math.Ceil(float64(numNonces*d) / m))

	h := blake3.New()
	out := make([]byte, numOuts*64)
	difficultyVal := le34(difficulty, 0)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			block := labels[:B]
			labels = labels[B:]

			{
				h.Reset()
				h.Write(ch)
				h.Write(block)
				h.Write([]byte{0})
				d := h.Digest()
				d.Read(out)
			}

			for j := uint(0); j < numNonces; j++ {
				val := le34(out, j*d)
				if val <= difficultyVal {
					if stop := reporter.Report(ctx, uint32(j), index); stop {
						batch.Release()
						return
					}
				}
			}
			index++
		}
		batch.Release()
	}
}

func workNewAES(ctx context.Context, data <-chan *batch, reporter IndexReporterNew, ch Challenge, difficulty []byte) {
	const m = 128 // AES output size in bits
	const blockSize = m / 8
	// d: |d| = log2(N) - log2(B). Assumed both N and B are power of 2.
	const dd = 34
	// numOuts = ceil(numNonces * |d| / m )
	numOuts := uint8(math.Ceil(float64(numNonces*dd) / m))
	difficultyVal := le34(difficulty, 0)

	c, err := aes.NewCipher(ch)
	if err != nil {
		log.Fatal(err)
	}
	out := make([]byte, numOuts*blockSize)

	for batch := range data {
		index := batch.Index
		labels := batch.Data
		for len(labels) > 0 {
			block := labels[:B]
			labels = labels[B:]

			for i := uint8(0); i < numOuts; i++ {
				c.Encrypt(out[i*blockSize:(i+1)*blockSize], block)
			}

			for j := uint(0); j < numNonces; j++ {
				val := le34(out, j*dd)
				if val <= difficultyVal {
					if stop := reporter.Report(ctx, uint32(j), index); stop {
						batch.Release()
						return
					}
				}
			}
			index++
		}
		batch.Release()
	}
}

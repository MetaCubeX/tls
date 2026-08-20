//go:build !go1.27

package tls

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
)

// setGlobalRandom provides the deterministic ChaCha8 stream used by
// testing/cryptotest, using the Go 1.27 random-reader behavior.
func setGlobalRandom(t *testing.T, seed uint64) {
	t.Helper()
	t.Setenv("GODEBUG", "cryptocustomrand=1,"+os.Getenv("GODEBUG"))

	var seedBytes [32]byte
	binary.LittleEndian.PutUint64(seedBytes[:8], seed)
	r := &discardingMaybeReadByteReader{
		Reader: &lockedChaCha8Reader{reader: newChaCha8Reader(seedBytes)},
	}

	previous := cryptorand.Reader
	cryptorand.Reader = r
	t.Cleanup(func() {
		cryptorand.Reader = previous
	})
}

type discardingMaybeReadByteReader struct {
	io.Reader
}

func (r *discardingMaybeReadByteReader) Read(p []byte) (int, error) {
	if len(p) == 1 && calledFromMaybeReadByte() {
		// Go 1.27 recognizes the global testing reader and no longer advances
		// its deterministic stream for randutil.MaybeReadByte.
		p[0] = 0
		return 1, nil
	}
	return r.Reader.Read(p)
}

// calledFromMaybeReadByte distinguishes the discarded compatibility read from
// legitimate one-byte reads, such as RSA PKCS #1 v1.5 padding. io.Reader does
// not otherwise expose enough context to tell them apart.
func calledFromMaybeReadByte() bool {
	var callers [8]uintptr
	n := runtime.Callers(2, callers[:])
	frames := runtime.CallersFrames(callers[:n])
	for {
		frame, more := frames.Next()
		if frame.Function == "crypto/internal/randutil.MaybeReadByte" {
			return true
		}
		if !more {
			return false
		}
	}
}

var _ io.Reader = (*discardingMaybeReadByteReader)(nil)

type lockedChaCha8Reader struct {
	sync.Mutex
	reader *chaCha8Reader
}

func (r *lockedChaCha8Reader) Read(p []byte) (int, error) {
	r.Lock()
	defer r.Unlock()
	return r.reader.Read(p)
}

var _ io.Reader = (*lockedChaCha8Reader)(nil)

type chaCha8Reader struct {
	state   chaCha8State
	readBuf [8]byte
	readLen int
}

func newChaCha8Reader(seed [32]byte) *chaCha8Reader {
	r := new(chaCha8Reader)
	r.state.init(seed)
	return r
}

func (r *chaCha8Reader) uint64() uint64 {
	for {
		if value, ok := r.state.next(); ok {
			return value
		}
		r.state.refill()
	}
}

func (r *chaCha8Reader) Read(p []byte) (n int, err error) {
	if r.readLen > 0 {
		copied := copy(p, r.readBuf[len(r.readBuf)-r.readLen:])
		r.readLen -= copied
		p = p[copied:]
		n += copied
	}
	for len(p) >= 8 {
		binary.LittleEndian.PutUint64(p, r.uint64())
		p = p[8:]
		n += 8
	}
	if len(p) > 0 {
		binary.LittleEndian.PutUint64(r.readBuf[:], r.uint64())
		n += copy(p, r.readBuf[:])
		r.readLen = 8 - len(p)
	}
	return n, nil
}

const (
	chaCha8CounterIncrement = 4
	chaCha8CounterMaximum   = 16
	chaCha8ChunkSize        = 32
	chaCha8ReseedSize       = 4
)

type chaCha8State struct {
	buffer  [chaCha8ChunkSize]uint64
	seed    [4]uint64
	index   uint32
	length  uint32
	counter uint32
}

func (s *chaCha8State) init(seed [32]byte) {
	for i := range s.seed {
		s.seed[i] = binary.LittleEndian.Uint64(seed[i*8:])
	}
	chaCha8Block(&s.seed, &s.buffer, 0)
	s.counter = 0
	s.index = 0
	s.length = chaCha8ChunkSize
}

func (s *chaCha8State) next() (uint64, bool) {
	if s.index >= s.length {
		return 0, false
	}
	value := s.buffer[s.index&31]
	s.index++
	return value, true
}

func (s *chaCha8State) refill() {
	s.counter += chaCha8CounterIncrement
	if s.counter == chaCha8CounterMaximum {
		copy(s.seed[:], s.buffer[len(s.buffer)-chaCha8ReseedSize:])
		s.counter = 0
	}
	chaCha8Block(&s.seed, &s.buffer, s.counter)
	s.index = 0
	s.length = uint32(len(s.buffer))
	if s.counter == chaCha8CounterMaximum-chaCha8CounterIncrement {
		s.length -= chaCha8ReseedSize
	}
}

func chaCha8Block(seed *[4]uint64, output *[chaCha8ChunkSize]uint64, counter uint32) {
	var blocks [16][4]uint32
	constants := [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
	for word, value := range constants {
		for lane := range blocks[word] {
			blocks[word][lane] = value
		}
	}
	for word := 0; word < 8; word++ {
		value := uint32(seed[word/2] >> (32 * (word % 2)))
		for lane := range blocks[word+4] {
			blocks[word+4][lane] = value
		}
	}
	for lane := range blocks[12] {
		blocks[12][lane] = counter + uint32(lane)
	}

	for lane := 0; lane < 4; lane++ {
		b0, b1, b2, b3 := blocks[0][lane], blocks[1][lane], blocks[2][lane], blocks[3][lane]
		b4, b5, b6, b7 := blocks[4][lane], blocks[5][lane], blocks[6][lane], blocks[7][lane]
		b8, b9, b10, b11 := blocks[8][lane], blocks[9][lane], blocks[10][lane], blocks[11][lane]
		b12, b13, b14, b15 := blocks[12][lane], blocks[13][lane], blocks[14][lane], blocks[15][lane]

		for round := 0; round < 4; round++ {
			b0, b4, b8, b12 = chaCha8QuarterRound(b0, b4, b8, b12)
			b1, b5, b9, b13 = chaCha8QuarterRound(b1, b5, b9, b13)
			b2, b6, b10, b14 = chaCha8QuarterRound(b2, b6, b10, b14)
			b3, b7, b11, b15 = chaCha8QuarterRound(b3, b7, b11, b15)
			b0, b5, b10, b15 = chaCha8QuarterRound(b0, b5, b10, b15)
			b1, b6, b11, b12 = chaCha8QuarterRound(b1, b6, b11, b12)
			b2, b7, b8, b13 = chaCha8QuarterRound(b2, b7, b8, b13)
			b3, b4, b9, b14 = chaCha8QuarterRound(b3, b4, b9, b14)
		}

		blocks[0][lane], blocks[1][lane], blocks[2][lane], blocks[3][lane] = b0, b1, b2, b3
		blocks[4][lane] += b4
		blocks[5][lane] += b5
		blocks[6][lane] += b6
		blocks[7][lane] += b7
		blocks[8][lane] += b8
		blocks[9][lane] += b9
		blocks[10][lane] += b10
		blocks[11][lane] += b11
		blocks[12][lane], blocks[13][lane], blocks[14][lane], blocks[15][lane] = b12, b13, b14, b15
	}

	for word := range blocks {
		output[word*2] = uint64(blocks[word][0]) | uint64(blocks[word][1])<<32
		output[word*2+1] = uint64(blocks[word][2]) | uint64(blocks[word][3])<<32
	}
}

func chaCha8QuarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = d<<16 | d>>16
	c += d
	b ^= c
	b = b<<12 | b>>20
	a += b
	d ^= a
	d = d<<8 | d>>24
	c += d
	b ^= c
	b = b<<7 | b>>25
	return a, b, c, d
}

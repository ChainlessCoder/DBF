package nonce_distbf

import (
	"crypto/sha512"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/willf/bloom"
)

func TestXorHash(t *testing.T) {
	type args struct {
		a [32]byte
		b [32]byte
	}
	var ca [32]byte
	var cb [32]byte
	var cc [32]byte
	copy(ca[:], []byte("12345678901234567890123456789012"))
	copy(cb[:], []byte("12345678901234567890123456789011"))
	copy(cc[:], []byte("12345678901234567890123456789013"))
	tests := []struct {
		name string
		args args
		want [32]byte
	}{
		{
			name: "id1 xor id2",
			args: args{
				a: ca,
				b: cb,
			},
			want: [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3},
		},
		{
			name: "id1 xor id3",
			args: args{
				a: ca,
				b: cc,
			},
			want: [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := xorHash(tt.args.a, tt.args.b)
			assert.Equalf(t, got, tt.want, "xor() = %v, want %v", got, tt.want)
		})
	}
}

func TestMax(t *testing.T) {
	type args struct {
		a uint
		b uint
	}
	tests := []struct {
		name string
		args args
		want uint
	}{
		{
			name: "max of two int",
			args: args{
				a: 100,
				b: 101,
			},
			want: 101,
		},
		{
			name: "max of two int",
			args: args{
				a: 100,
				b: 99,
			},
			want: 100,
		},
		{
			name: "max of two int",
			args: args{
				a: 100,
				b: 100,
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := max(tt.args.a, tt.args.b)
			assert.Equalf(t, got, tt.want, "max() = %v, want %v", got, tt.want)
		})
	}
}

// tests are done under assumption that fpr=0.1
// want result is taken from https://bitbucket.org/ww/bloom/src/829aa19d01d9/bloom.go
func TestEstimateParameters(t *testing.T) {
	type args struct {
		n1 uint
		n2 uint
	}
	type want struct {
		k uint
		m uint
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "estimate parameters",
			args: args{
				n1: 100,
				n2: 101,
			},
			want: want{k: 4, m: 485},
		},
		{
			name: "estimate parameters",
			args: args{
				n1: 100,
				n2: 99,
			},
			want: want{k: 4, m: 480},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, k := EstimateParameters(tt.args.n1, tt.args.n2)
			got := want{m: m, k: k}
			assert.Equalf(t, got, tt.want, "max() = %v, want %v", got, tt.want)
		})
	}
}

func TestHashOfXor(t *testing.T) {
	d := DistBF{}
	k := 10
	d.k = uint(10)
	d.m = 100
	otherNode := []byte("12345678901234567890123456789011")
	hashes := d.hashOfXOR(otherNode)
	// there should be k hashes
	if len(hashes) != k {
		t.Fatal("there are not k hashes")
	}
	// check for uniqueness
	hashesUniqueness := make(map[[sha512.Size256]byte]bool)
	for i := 0; i < k; i++ {
		hash := hashes[i]
		if ok := hashesUniqueness[hash]; ok {
			t.Fatal("hash previously existed")
		} else {
			hashesUniqueness[hash] = true
		}
	}
}

func TestAddElementHash(t *testing.T) {
	// first part are steps 1-3
	d := DistBF{}
	k := 10
	d.k = uint(10)
	d.m = 100
	otherNode := []byte("12345678901234567890123456789011")
	hashes := d.hashOfXOR(otherNode)
	// there should be k hashes
	if len(hashes) != k {
		t.Fatal("there are not k hashes")
	}
	// check for uniqueness
	hashesUniqueness := make(map[[sha512.Size256]byte]bool)
	for i := 0; i < k; i++ {
		hash := hashes[i]
		if ok := hashesUniqueness[hash]; ok {
			t.Fatal("hash previously existed")
		} else {
			hashesUniqueness[hash] = true
		}
	}
	// now we add hashes of element
	element := []byte("message")
	oldHashes := make([][sha512.Size256]byte, len(hashes))
	copy(oldHashes, hashes)
	d.addElementHash(element, hashes)
	// check for uniqueness and if it changes
	newHashes := make(map[[sha512.Size256]byte]bool)
	for i := 0; i < k; i++ {
		hash := hashes[i]
		if hashes[i] == oldHashes[i] {
			t.Fatal("hash did not change")
		}
		if ok := newHashes[hash]; ok {
			t.Fatal("hash previously existed")
		} else {
			newHashes[hash] = true
		}
	}
}

// this is more of an example than a test
func TestNew(t *testing.T) {
	dbf := New(1, 5)
	if dbf.k == 0 || dbf.m == 0 {
		t.Fatal("the distributed bloom filter should not have m=0 or k=0")
	}
}

// this is more of an example than a test
func TestHashModulo(t *testing.T) {
	dbf := New(10, 11)
	otherNode := []byte("12345678901234567890123456789011")
	element := []byte("message")
	hashes := dbf.hashOfXOR(otherNode)
	dbf.addElementHash(element, hashes)
	modulus := dbf.hashesModulo(hashes)
	if len(modulus) != int(dbf.k) {
		t.Fatal("there must be k bit strings")
	}
	for _, modulo := range modulus {
		if !(modulo < dbf.m) {
			t.Fatal("range of modulo is not m")
		}
	}
}

// this is more of an example than a test
func TestAdd(t *testing.T) {
	dbf := New(10, 11)
	otherNode := []byte("12345678901234567890123456789011")
	element := []byte("message")
	dbf.Add(element, otherNode)
}

func BenchmarkAdd(b *testing.B) {
	dbf := New(uint(b.N), uint(b.N))
	otherNode := []byte("12345678901234567890123456789011")
	for i := 0; i < b.N; i++ {
		elem := randStringBytes(8)
		dbf.Add([]byte(elem), otherNode)
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		rand.Seed(time.Now().UnixNano())
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func BenchmarkAddBloomFilter(b *testing.B) {
	filter := bloom.New(uint(20*b.N), 4) // load of 20, 5 keys
	for i := 0; i < b.N; i++ {
		elem := randStringBytes(8)
		filter.Add([]byte(elem))
	}
}

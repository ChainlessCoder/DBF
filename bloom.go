package nonce_distbf

import (
	"crypto/sha512"
	"math"
	"github.com/willf/bitset"
)


var elements [][]byte

type DistBF struct {
	b *bitset.BitSet
	m uint
	k uint
}

// Init function populates the variables with their initial values
func Init(elems [][]byte) {
	elements = elems
}

// New function return the DBF generated from the sizes of to peers
func New(n uint, fpr float64) *DistBF {
	m, k := EstimateParameters(n, fpr)
	return &DistBF{m: m, k: k, b: bitset.New(m)}
}

// EstimateParameters estimates requirements for m and k.
// Based on https://bitbucket.org/ww/bloom/src/829aa19d01d9/bloom.go
func EstimateParameters(n uint, fpr float64) (m uint, k uint) {
	m = uint(math.Ceil(-1 * float64(n) * math.Log(fpr) / math.Pow(math.Log(2), 2)))
	k = uint(math.Ceil(math.Log(2) * float64(m) / float64(n)))
	return
}

func xorHash(a, b [sha512.Size256]byte) [sha512.Size256]byte {
	var c [sha512.Size256]byte
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// in this branch we are not xor, but we keep the naming
// hashOfXOR functions hashes the XOR of nodes ID, and for the i'th iteration we append to XOR
// result integer i and then hash it with sha512_256
func (dbf *DistBF) seedValues(seed []byte) (ret [][sha512.Size256]byte) {
	for i := 0; i < int(dbf.k); i++ {
		ret = append(ret, iHash(seed, i))
	}
	return
}

// addElementHash xor the result of function hashOfXOR with the hash of element (component wise)❤
func (dbf *DistBF) addElementHash(element []byte, hashes [][sha512.Size256]byte) {
	h := hashElement(element)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = xorHash(hashes[i], h)
	}
}

// hashesModule find the location where to set bits in Bloom Filter
func (dbf *DistBF) hashesModulo(hashes [][sha512.Size256]byte) (ret []uint) {
	for _, hash := range hashes {
		ret = append(ret, byteModuloM(dbf.m, hash))
	}
	return
}

// Add element to DBF
// TODO: save hashes of elements
func (dbf *DistBF) Add(element []byte, seed []byte) {
	hashes := dbf.seedValues(seed)
	dbf.addElementHash(element, hashes)
	locations := dbf.hashesModulo(hashes)
	for _, location := range locations {
		dbf.b.Set(location)
	}
}

// compare takes two bitset arrays and returns whether they are comparable (coordinate wise)
// TODO: optimize to find difference only once
func compare(bc1, bc2 *bitset.BitSet) (bool, uint, uint) {

	firstBigger := bc1.Difference(bc2).Count()
	secondBigger := bc2.Difference(bc1).Count()
	if firstBigger != 0 && secondBigger != 0 {
		return false, firstBigger, secondBigger
	}
	return true, firstBigger, secondBigger
}

// syncBloomFilter tests if the otherNode has our elements
// TODO: optimize, combine with compare?
func (dbf *DistBF) syncBloomFilter(nonce []byte, otherBF *bitset.BitSet) [][]byte {
	var ret [][]byte

	for _, elem := range elements {
		if !dbf.Verify(elem, nonce, otherBF) {
			ret = append(ret, elem)
		}
	}

	return ret
}

// Verify returns true if element is in DBF, false otherwise
func (dbf *DistBF) Verify(elem, seed []byte, b *bitset.BitSet) bool {
	hashes := dbf.seedValues(seed)
	dbf.addElementHash(elem, hashes)
	locations := dbf.hashesModulo(hashes)
	for i := uint(0); i < dbf.k; i++ {
		if !b.Test(locations[i]) {
			return false
		}
	}
	return true
}

func (dbf *DistBF) B() *bitset.BitSet {
	return dbf.b
}

func NewDBFBitSet(b *bitset.BitSet) *DistBF {
	return nil
}
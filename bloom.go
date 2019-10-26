package DBF

import (
	"crypto/sha512"
	"math"

	"github.com/willf/bitset"
)

// DistBF is the dbf struct
type DistBF struct {
	b *bitset.BitSet
	m uint
	k uint
	h [][sha512.Size256]byte
}

// NewDbf function return the DBF generated from the sizes of to peers
func NewDbf(n uint, fpr float64, s []byte) *DistBF {
	m, k := EstimateParameters(n, fpr)
	h := seedHashes(s, k)
	return &DistBF{h: h, m: m, k: k, b: bitset.New(m)}
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

func seedHashes(seedValue []byte, k uint) (ret [][sha512.Size256]byte) {
	for i := 0; i < int(k); i++ {
		ret = append(ret, iHash(seedValue, i))
	}
	return
}

// addElementHash xor the result of function hashOfXOR with the hash of element (component wise)❤
func addElementHash(element []byte, hashes [][sha512.Size256]byte) [][sha512.Size256]byte {
	ret := make([][sha512.Size256]byte, len(hashes))
	h := hashElement(element)
	for i := 0; i < len(hashes); i++ {
		ret[i] = xorHash(hashes[i], h)
	}
	return ret
}

// hashesModule find the location where to set bits in Bloom Filter
func hashesModulo(m uint, hashes [][sha512.Size256]byte) (ret []uint) {
	for _, hash := range hashes {
		ret = append(ret, byteModuloM(m, hash))
	}
	return
}

// Add element to DBF
func (dbf *DistBF) Add(element []byte) {
	tmp := addElementHash(element, dbf.h)
	locations := hashesModulo(dbf.m, tmp)
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
func (dbf *DistBF) syncBloomFilter(nonce []byte, otherBF *bitset.BitSet, elements [][]byte) [][]byte {
	var ret [][]byte

	for _, elem := range elements {
		if !VerifyBitArray(dbf, elem, otherBF) {
			ret = append(ret, elem)
		}
	}

	return ret
}

// VerifyElement returns true if element is in DBF, false otherwise
func (dbf *DistBF) VerifyElement(elem []byte) bool {
	tmp := addElementHash(elem, dbf.h)
	locations := hashesModulo(dbf.m, tmp)
	for i := uint(0); i < dbf.k; i++ {
		if !dbf.b.Test(locations[i]) {
			return false
		}
	}
	return true
}

// VerifyBitArray returns true if element is in the other DBF, false otherwise
func VerifyBitArray(dbf *DistBF, elem []byte, b *bitset.BitSet) bool {
	tmp := addElementHash(elem, dbf.h)
	locations := hashesModulo(dbf.m, tmp)
	for i := uint(0); i < dbf.k; i++ {
		if !b.Test(locations[i]) {
			return false
		}
	}
	return true
}

func (dbf *DistBF) BitArray() *bitset.BitSet {
	return dbf.b
}

func NewDBFBitSet(b *bitset.BitSet) *DistBF {
	return nil
}

// GetBitIndices returns the indices of every 1 in the dbf
func (dbf *DistBF) GetBitIndices() (indices []uint) {
	for i := uint(0); i < dbf.m; i++ {
		if dbf.b.Test(i) {
			indices = append(indices, i)
		}
	}
	return
}

// GetElementIndices returns the dbf indices an element would have if mapped to the dbf
func (dbf *DistBF) GetElementIndices(elem []byte) (indices []uint) {
	tmp := addElementHash(elem, dbf.h)
	indices = hashesModulo(dbf.m, tmp)
	return
}

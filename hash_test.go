package nonce_distbf

import (
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIHash(t *testing.T) {
	// for this we want to Test that no two hashes are equal
	data := []byte("message")
	k := 10
	hashes := make(map[[sha512.Size256]byte]bool)
	for i := 0; i < k; i++ {
		hash := iHash(data, i)
		if ok := hashes[hash]; ok {
			t.Fatal("hash previously existed")
		} else {
			hashes[hash] = true
		}
	}
}

func TestHashElement(t *testing.T) {
	element := []byte("message")
	hash := hashElement(element)
	want := [sha512.Size256]byte{14, 154, 200, 188, 223, 90, 235, 90, 3, 69, 16, 141, 94, 156, 154, 255, 169, 210, 86, 1, 3,
		63, 112, 56, 107, 77, 53, 51, 212, 45, 16, 248}
	t.Run("hash of element", func(t *testing.T) {
		assert.Equalf(t, hash, want, "hashElement() = %v, want %v", hash, want)
	})
}

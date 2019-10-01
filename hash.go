package nonce_distbf

import (
	"crypto/sha512"
)

// iHash returns the ith hashed value
func iHash(data []byte, i int) [sha512.Size256]byte {
	newData := append(data, byte(i))
	return sha512.Sum512_256(newData)
}

func hashElement(element []byte) [sha512.Size256]byte {
	return sha512.Sum512_256(element)
}

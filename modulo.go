package nonce_distbf

import (
	"crypto/sha512"
	"encoding/binary"
)

func byteModuloM(m uint, hash [sha512.Size256]byte) uint {
	x := uintFromBytes(hash[:]) % m
	return x
}

func uintFromBytes(bytes []byte) uint {
	data := binary.BigEndian.Uint64(bytes)
	return uint(data)
}

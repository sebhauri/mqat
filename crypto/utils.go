package crypto

import (
	"bytes"
	constants "mqat/const"

	"golang.org/x/crypto/sha3"
)

func H(data []byte) [constants.HASH_BYTES]byte {
	return sha3.Sum256(bytes.Clone(data))
}

func Nrand256(n int, seed []byte) []uint8 {
	if n <= 0 {
		return nil
	}
	out := make([]uint8, n)
	sha3.ShakeSum256(out, seed)
	return out
}

func Nrand128(n int, seed []byte) []uint8 {
	if n <= 0 {
		return nil
	}
	out := make([]uint8, n)
	sha3.ShakeSum128(out, seed)
	return out
}

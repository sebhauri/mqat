package crypto

import (
	"bytes"

	"golang.org/x/crypto/sha3"
	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/math"
)

func H(data []byte) [constants.HASH_BYTES]byte {
	return sha3.Sum256(bytes.Clone(data))
}

func Nrand256(n int, seed []byte) []math.Gf256 {
	if n <= 0 {
		return nil
	}
	out := make([]uint8, n)
	sha3.ShakeSum256(out, seed)
	return out
}

func Nrand128(n int, seed []byte) []math.Gf256 {
	if n <= 0 {
		return nil
	}
	out := make([]uint8, n)
	sha3.ShakeSum128(out, seed)
	return out
}

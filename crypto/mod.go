package crypto

import "sebastienhauri.ch/mqt/math"

type PublicKey struct {
	seed []byte
	v    []math.Gf31
}
type SecretKey struct {
	sk   []byte
	seed []byte
}
type KeyPair struct {
	P PublicKey
	S SecretKey
}
type Message []byte
type Signature []byte

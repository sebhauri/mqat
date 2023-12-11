package crypto

type PublicKey struct {
	seed []byte
	v    []uint8
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

package crypto

// //////////////////////////////////////
// MQAT
// //////////////////////////////////////
type MQAT struct {
	n, m                int
	salt_len            int
	random_sys_seed_len int
	uov                 *UOV
	mqdss               *MQDSS
}

type MQATSecretKey struct {
	uov_sk          *UOVSecretKey
	seed_random_sys []byte
}

type MQATPublicKey struct {
	uov_pk          *UOVPublicKey
	seed_random_sys []byte
}

type MQATToken struct {
	token           []byte
	salt            []byte
	mqdss_signature []byte
}

// //////////////////////////////////////
// UOV
// //////////////////////////////////////
type UOV struct {
	m, n        int
	pk_seed_len int
	sk_seed_len int
}

type UOVSecretKey struct {
	seed_sk      []byte
	trapdoor_o   []uint8
	matrices_p1i []uint8
	matrices_si  []uint8
}

type UOVPublicKey struct {
	seed_pk []byte
	P1i     []uint8
	P2i     []uint8
	P3i     []uint8
}

// //////////////////////////////////////
// MQDSS
// //////////////////////////////////////
type MQDSS struct {
	N, M int
	R    int
	flen int
}

type MQDSSPublicKey struct {
	seed []byte
	v    []uint8
}
type MQDSSSecretKey struct {
	sk   []byte
	seed []byte
}

type Message []byte
type Signature []byte

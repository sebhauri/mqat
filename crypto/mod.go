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
	trapdoor_o   []uint8 // column-major
	matrices_p1i []uint8
	matrices_si  []uint8
	// Matrices Pi1 and Si are encoded as Pi1 and Pi2 below respectively.
}

type UOVPublicKey struct {
	seed_pk         []byte
	quadratic_map_p []uint8 // Pi1 || Pi2 || Pi3
	// Each sequence of m matrix is encoded in an m-fold interleaved fashion.
	// The elements from each matrix appear in the encoding in row-major order.
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

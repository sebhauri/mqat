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
	M, N      int
	PkSeedLen int
	SkSeedLen int
}

type UOVSecretKey struct {
	Seed []byte
	O    []uint8
	Si   []uint8
	Pk   *UOVPublicKey
}

type UOVPublicKey struct {
	Seed []byte
	P1i  []uint8
	P2i  []uint8
	P3i  []uint8
}

// //////////////////////////////////////
// MQDSS
// //////////////////////////////////////
type MQDSS struct {
	M, N      int
	R         int
	PkSeedLen int
	SkSeedLen int
}

type MQDSSPublicKey struct {
	P1 []uint8
	P2 []uint8
	P3 []uint8
	R  []uint8
	V  []uint8
}
type MQDSSSecretKey struct {
	S  []uint8
	Pk *MQDSSPublicKey
}

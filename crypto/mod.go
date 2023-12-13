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
	uov_csk *UOVSecretKey
	seedR   []byte
}

type MQATPublicKey struct {
	uov_cpk *UOVPublicKey
	seedR   []byte
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
	seed_sk []byte
	seed_pk []byte
}

type UOVPublicKey struct {
	seed_pk []byte
	Pi3     []uint8
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

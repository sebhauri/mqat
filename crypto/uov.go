package crypto

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
	constants "sebastienhauri.ch/mqt/const"
)

func NewUOV(m, n, salt_len, pk_seed_len, sk_seed_len int) *UOV {
	uov := new(UOV)
	uov.M = m
	uov.N = n
	uov.SaltLen = salt_len
	uov.PkSeedLen = pk_seed_len
	uov.SkSeedLen = sk_seed_len
	return uov
}

func (uov *UOV) KeyGen(m, n int) (*UOVSecretKey, *UOVPublicKey) {
	uov_csk := new(UOVSecretKey)
	uov_cpk := new(UOVPublicKey)

	uov_seed_sk := make([]byte, constants.UOV_SK_SEED_LEN)
	_, err := rand.Read(uov_seed_sk)
	if err != nil {
		return nil, nil
	}
	uov_seed_pk := make([]byte, constants.UOV_PK_SEED_LEN)
	_, err = rand.Read(uov_seed_pk)
	if err != nil {
		return nil, nil
	}
	uov_csk.seed_sk = bytes.Clone(uov_seed_sk)
	uov_csk.seed_pk = bytes.Clone(uov_seed_pk)
	uov_cpk.seed_pk = bytes.Clone(uov_seed_pk)

	O := expandSk(uov_seed_sk, m, n)
	if O == nil {
		return nil, nil
	}
	Pi1, Pi2 := expandP(uov_seed_pk, m, n)
	if Pi1 == nil || Pi2 == nil {
		return nil, nil
	}
	Pi3 := derivePi3(O, Pi1, Pi2, m, n)
	if Pi3 == nil {
		return nil, nil
	}
	uov_cpk.Pi3 = Pi3

	return uov_csk, uov_cpk
}

////////////////////////////////////////////////////////////////////////////////
// Utills
////////////////////////////////////////////////////////////////////////////////

func expandSk(seed []byte, m, n int) []uint8 {
	if len(seed) < constants.UOV_SK_SEED_LEN {
		return nil
	}
	output_len := m * (n - m)
	out := make([]uint8, output_len)
	sha3.ShakeSum256(out, seed)
	return out
}

func expandP(seed []byte, m, n int) ([]uint8, []uint8) {
	if len(seed) < constants.UOV_PK_SEED_LEN {
		return nil, nil
	}

	P1s_output_len := m * (n - m) * (n - m - 1) / 2
	P2s_output_len := m * m * (n - m)
	total_len := P1s_output_len + P2s_output_len
	out := make([]uint8, total_len)
	sha3.ShakeSum128(out, seed)
	P1 := out[:P1s_output_len]
	P2 := out[P1s_output_len:]
	if len(P1) != P1s_output_len || len(P2) != P2s_output_len {
		return nil, nil
	}
	return P1, P2
}

func derivePi3(O, Pi1, Pi2 []uint8, m, n int) []uint8 {
	return nil
}

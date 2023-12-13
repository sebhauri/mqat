package crypto

import (
	"bytes"
	"crypto/rand"

	constants "sebastienhauri.ch/mqt/const"
)

func NewUOV(m, n, pk_seed_len, sk_seed_len int) *UOV {
	uov := new(UOV)
	uov.M = m
	uov.N = n
	uov.PkSeedLen = pk_seed_len
	uov.SkSeedLen = sk_seed_len
	return uov
}

func (uov *UOV) KeyGen(m, n int) (*UOVSecretKey, *UOVPublicKey) {
	uov_csk := new(UOVSecretKey)
	uov_cpk := new(UOVPublicKey)

	uov_seed_sk := make([]byte, constants.UOV_SK_SEED_LEN/8)
	_, err := rand.Read(uov_seed_sk)
	if err != nil {
		return nil, nil
	}
	uov_seed_pk := make([]byte, constants.UOV_PK_SEED_LEN/8)
	_, err = rand.Read(uov_seed_pk)
	if err != nil {
		return nil, nil
	}
	uov_csk.seed_sk = bytes.Clone(uov_seed_sk)
	uov_csk.seed_pk = bytes.Clone(uov_seed_pk)
	uov_cpk.seed_pk = bytes.Clone(uov_seed_pk)

	O := Nrand256(m*(n-m), uov_seed_sk)
	if O == nil {
		return nil, nil
	}
	P1s_output_len := m * (n - m) * (n - m - 1) / 2
	P2s_output_len := m * m * (n - m)
	total_len := P1s_output_len + P2s_output_len
	Pi12 := Nrand128(total_len, uov_seed_pk)
	Pi1 := Pi12[:P1s_output_len]
	Pi2 := Pi12[P1s_output_len:]
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
// Helpers
////////////////////////////////////////////////////////////////////////////////

func derivePi3(O, Pi1, Pi2 []uint8, m, n int) []uint8 {
	return nil
}

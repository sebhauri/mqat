package crypto

import (
	"bytes"
	"crypto/rand"

	"sebastienhauri.ch/mqt/math"
)

func NewUOV(m, n, pk_seed_len, sk_seed_len int) *UOV {
	uov := new(UOV)
	uov.m = m
	uov.n = n
	uov.pk_seed_len = pk_seed_len
	uov.sk_seed_len = sk_seed_len
	return uov
}

func (uov *UOV) KeyGen(m, n int) (*UOVSecretKey, *UOVPublicKey) {
	uov_sk := new(UOVSecretKey)
	uov_pk := new(UOVPublicKey)

	uov_seed_sk := make([]byte, uov.sk_seed_len/8)
	_, err := rand.Read(uov_seed_sk)
	if err != nil {
		return nil, nil
	}
	uov_seed_pk := make([]byte, uov.sk_seed_len/8)
	_, err = rand.Read(uov_seed_pk)
	if err != nil {
		return nil, nil
	}
	uov_sk.seed_sk = bytes.Clone(uov_seed_sk)
	uov_pk.seed_pk = bytes.Clone(uov_seed_pk)

	O := Nrand256(m*(n-m), uov_seed_sk)
	if O == nil {
		return nil, nil
	}
	uov_sk.trapdoor_o = O

	P1s_output_len := m * (n - m) * (n - m + 1) / 2
	P2s_output_len := m * m * (n - m)
	total_len := P1s_output_len + P2s_output_len
	Pi12 := Nrand128(total_len, uov_seed_pk)
	Pi1 := Pi12[:P1s_output_len]
	Pi2 := Pi12[P1s_output_len:]
	if Pi1 == nil || Pi2 == nil {
		return nil, nil
	}
	uov_sk.matrices_p1i = Pi1
	uov_sk.matrices_si = deriveSi(O, Pi1, Pi2)

	Pi3 := derivePi3(O, Pi1, Pi2, m, n)
	if Pi3 == nil {
		return nil, nil
	}
	uov_pk.quadratic_map_p = append(Pi12, Pi3...)

	return uov_sk, uov_pk
}

func (uov *UOV) Sign(message []uint8, sk *UOVSecretKey) []uint8 {
	var ctr uint8 = 0
	for ctr = 0; ctr <= 255; ctr++ {
		seed := append(message, sk.seed_sk...)
		seed = append(seed, ctr)
		v := Nrand256(uov.n-uov.m, seed)
		L := make([]uint8, 0)
		for i := 0; i < uov.m; i++ {
			for j := 0; j < uov.m; j++ {
				var acc uint8 = 0
				for k := 0; k < uov.n-uov.m; k++ {
					acc ^= math.Mul(v[k], sk.matrices_si[k*uov.m*uov.m+j*uov.m+i])
				}
				L = append(L, acc)
			}
		}
		if isInvertible(L) {
			y := bytes.Clone(message)
			for i := 0; i < uov.n-uov.m; i++ {
				for j := i; j < uov.n-uov.m; j++ {
					t := math.Mul(v[i], v[j])
					for k := 0; k < uov.m; k++ {
						ijk := uov.m*(i*uov.n-i*uov.m-i*(i+1)/2*uov.m) + uov.m*j + k
						y[k] ^= math.Mul(sk.matrices_p1i[ijk], t)
					}
				}
			}
			x := solve(L, y)
			for i := 0; i < uov.n-uov.m; i++ {
				var acc uint8 = 0
				for j := 0; j < uov.m; j++ {
					acc ^= math.Mul(sk.trapdoor_o[i+j*(uov.n-uov.m)], x[j])
				}
				v[i] ^= acc
			}
			s := append(v, x...)
			return s
		}
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

func deriveSi(O, Pi1, Pi2 []uint8) []uint8

func derivePi3(O, Pi1, Pi2 []uint8, m, n int) []uint8

func isInvertible(L []uint8) bool

func solve(A, b []uint8) []uint8

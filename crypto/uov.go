package crypto

import (
	"bytes"
	"crypto/rand"
	"mqat/math"
)

func NewUOV(m, n, pk_seed_len, sk_seed_len int) *UOV {
	uov := new(UOV)
	uov.M = m
	uov.N = n
	uov.PkSeedLen = pk_seed_len
	uov.SkSeedLen = sk_seed_len
	return uov
}

func (uov *UOV) KeyGen() (*UOVSecretKey, *UOVPublicKey) {
	uov_sk := new(UOVSecretKey)
	uov_pk := new(UOVPublicKey)

	uov_seed_sk := make([]byte, uov.SkSeedLen/8)
	_, err := rand.Read(uov_seed_sk)
	if err != nil {
		return nil, nil
	}
	uov_seed_pk := make([]byte, uov.PkSeedLen/8)
	_, err = rand.Read(uov_seed_pk)
	if err != nil {
		return nil, nil
	}
	uov_sk.Seed = bytes.Clone(uov_seed_sk)
	uov_pk.Seed = bytes.Clone(uov_seed_pk)

	O := Nrand256(uov.M*(uov.N-uov.M), uov_seed_sk)
	if O == nil {
		return nil, nil
	}
	uov_sk.O = O

	P1s_output_len := uov.M * (uov.N - uov.M) * (uov.N - uov.M + 1) / 2
	P2s_output_len := uov.M * uov.M * (uov.N - uov.M)
	total_len := P1s_output_len + P2s_output_len
	Pi12 := Nrand128(total_len, uov_seed_pk)
	Pi1 := Pi12[:P1s_output_len]
	Pi2 := Pi12[P1s_output_len:]
	if Pi1 == nil || Pi2 == nil {
		return nil, nil
	}
	uov_sk.Si = deriveSi(O, Pi1, Pi2, uov.M, uov.N)

	Pi3 := derivePi3(O, Pi1, Pi2, uov.M, uov.N)
	if Pi3 == nil {
		return nil, nil
	}
	uov_pk.P1i = Pi1
	uov_pk.P2i = Pi2
	uov_pk.P3i = Pi3
	uov_sk.P1i = Pi1
	return uov_sk, uov_pk
}

func (uov *UOV) Sign(message []uint8, sk *UOVSecretKey) []uint8 {
	lenSi := (uov.N - uov.M) * uov.M
	lenP1i := (uov.N - uov.M) * (uov.N - uov.M + 1) / 2
	for ctr := 0; ctr < 256; ctr++ {
		seed := append(message, sk.Seed...)
		seed = append(seed, byte(ctr))
		v := Nrand256(uov.N-uov.M, seed)
		L := make([]uint8, 0)
		vec := math.NewVector(v)
		vec_t := math.T(vec)
		for i := 0; i < uov.M; i++ {
			Si := math.NewDenseMatrix(uov.N-uov.M, uov.M,
				sk.Si[i*lenSi:(i+1)*lenSi])
			res := math.MulMat(vec_t, Si)
			if len(res.Data) != uov.M {
				return nil
			}
			L = append(L, res.Data...)
		}
		matL := math.NewDenseMatrix(uov.M, uov.M, L)
		y := bytes.Clone(message)
		for i := 0; i < uov.M; i++ {
			P1i := math.NewUpperTriangle(
				math.NewDenseMatrix(uov.N-uov.M, uov.N-uov.M,
					sk.P1i[i*lenP1i:(i+1)*lenP1i]))
			res := math.MulMat(math.MulMat(vec_t, P1i), vec)
			if len(res.Data) != 1 {
				return nil
			}
			y[i] ^= res.Data[0]
		}
		vecY := math.NewVector(y)
		x := math.Solve(matL, vecY)
		if x.Data == nil {
			continue
		}
		O := sk.O
		for i := 0; i < uov.M; i++ {
			e := make([]uint8, uov.M)
			e[i] = 1
			O = append(O, e...)
		}
		OBar := math.NewDenseMatrix(uov.N, uov.M, O)
		res := math.MulMat(OBar, x)
		if len(res.Data) != uov.N {
			return nil
		}

		v = append(v, make([]uint8, uov.M)...)
		for i := 0; i < uov.N; i++ {
			v[i] ^= res.Data[i]
		}
		return v
	}
	return nil
}

func (uov *UOV) Verify(message, signature []uint8, pk *UOVPublicKey) bool {
	res := math.MQP(pk.P1i, pk.P2i, pk.P3i, signature, uov.M)
	return bytes.Equal(message, res)
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

func deriveSi(O, Pi1, Pi2 []uint8, m, n int) []uint8 {
	res := make([]uint8, 0)
	for i := 0; i < m; i++ {
		P1 := math.NewUpperTriangle(math.NewDenseMatrix(n-m, n-m, Pi1[i*(n-m)*(n-m+1)/2:(i+1)*(n-m)*(n-m+1)/2]))
		P1T := math.T(P1)
		OM := math.NewDenseMatrix(n-m, m, O)
		P2 := math.NewDenseMatrix(n-m, m, Pi2[i*(n-m)*m:(i+1)*(n-m)*m])
		Si := math.AddMat(math.MulMat(math.AddMat(P1, P1T), OM), P2)
		res = append(res, Si.Data...)
	}
	if len(res) != m*(n-m)*m {
		return nil
	}
	return res
}

func derivePi3(O, Pi1, Pi2 []uint8, m, n int) []uint8 {
	Omat := math.NewDenseMatrix(n-m, m, O)
	OmatT := math.T(Omat)
	lenP1 := (n - m) * (n - m + 1) / 2
	lenP2 := (n - m) * m
	res := make([]uint8, 0)
	for i := 0; i < m; i++ {
		P1 := math.NewUpperTriangle(math.NewDenseMatrix(n-m, n-m, Pi1[i*lenP1:(i+1)*lenP1]))
		P2 := math.NewDenseMatrix(n-m, m, Pi2[i*lenP2:(i+1)*lenP2])
		M := math.AddMat(math.MulMat(math.MulMat(OmatT, P1), Omat), math.MulMat(OmatT, P2))
		r, c := M.Dims()
		if r != m || c != m {
			return nil
		}
		MT := math.T(M)
		M_plus_MT := math.AddMat(M, MT)
		for i := 0; i < m; i++ {
			res = append(res, M.At(i, i))
			for j := i + 1; j < m; j++ {
				res = append(res, M_plus_MT.At(i, j))
			}
		}
	}
	return res
}

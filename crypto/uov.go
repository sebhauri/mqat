package crypto

import (
	"bytes"
	"crypto/rand"

	"github.com/sirupsen/logrus"
	"sebastienhauri.ch/mqt/math"
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
	uov_sk.P1i = Pi1
	uov_sk.Si = deriveSi(O, Pi1, Pi2, uov.M, uov.N)

	Pi3 := derivePi3(O, Pi1, Pi2, uov.M, uov.N)
	if Pi3 == nil {
		return nil, nil
	}
	uov_pk.P1i = Pi1
	uov_pk.P2i = Pi2
	uov_pk.P3i = Pi3
	return uov_sk, uov_pk
}

func (uov *UOV) Sign(message []uint8, sk *UOVSecretKey) []uint8 {
	lenSi := (uov.N - uov.M) * uov.M
	lenPi := (uov.N - uov.M) * (uov.N - uov.M)
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
		if isInvertible(L) {
			y := bytes.Clone(message)
			for i := 0; i < uov.M; i++ {
				Pi := math.NewUpperTriangle(
					math.NewDenseMatrix(uov.N-uov.M, uov.N-uov.M,
						sk.P1i[i*lenPi:(i+1)*lenPi]))
				res := math.MulMat(math.MulMat(vec_t, Pi), vec)
				if len(res.Data) != 1 {
					return nil
				}
				y[i] ^= res.Data[0]
			}
			x := Solve(L, y, uov.M)
			if x == nil {
				continue
			}
			for i := 0; i < uov.N-uov.M; i++ {
				var acc uint8 = 0
				for j := 0; j < uov.M; j++ {
					acc ^= math.Mul(sk.O[i+j*(uov.N-uov.M)], x[j])
				}
				v[i] ^= acc
			}
			s := append(v, x...)
			return s
		}
	}
	return nil
}

func (uov *UOV) Verify(message, signature []uint8, pk *UOVPublicKey) bool {
	vec := math.NewVector(signature)

	lenP1 := (uov.N - uov.M) * (uov.N - uov.M + 1) / 2
	lenP2 := (uov.N - uov.M) * uov.M
	lenP3 := uov.M * (uov.M + 1) / 2

	res := make([]uint8, 0)
	for k := 0; k < uov.M; k++ {
		var acc uint8 = 0
		P1 := math.NewUpperTriangle(
			math.NewDenseMatrix(
				uov.N-uov.M, uov.N-uov.M,
				pk.P1i[k*lenP1:(k+1)*lenP1],
			),
		)
		P2 := math.NewDenseMatrix(
			uov.N-uov.M, uov.M, pk.P2i[k*lenP2:(k+1)*lenP2],
		)
		P3 := math.NewUpperTriangle(
			math.NewDenseMatrix(
				uov.M, uov.M, pk.P3i[k*lenP3:(k+1)*lenP3],
			),
		)
		for i := 0; i < uov.N; i++ {
			for j := i; j < uov.N; j++ {
				t := math.Mul(vec.At(i, 0), vec.At(j, 0))
				if j < uov.N-uov.M {
					acc ^= math.Mul(t, P1.At(i, j))
				} else {
					if i < uov.N-uov.M {
						acc ^= math.Mul(t, P2.At(i, j-uov.N+uov.M))
					} else {
						acc ^= math.Mul(t, P3.At(i-uov.N+uov.M, j-uov.N+uov.M))
					}
				}
			}
		}
		res = append(res, acc)
	}
	logrus.Println(res)
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

func isInvertible(L []uint8) bool {
	return true
}

func Solve(A, b []uint8, m int) []uint8 {
	Ab := make([]uint8, 0)
	for i := 0; i < m; i++ {
		for j := 0; j < m; j++ {
			Ab = append(Ab, A[i*m+j])
		}
		Ab = append(Ab, b[i])
	}
	if len(Ab) != (m+1)*m {
		return nil
	}

	AbMat := math.NewDenseMatrix(m, m+1, Ab)
	for i := 0; i < m; i++ {
		for j := i + 1; j < m; j++ {
			if AbMat.At(i, i) == 0 {
				for k := i; k < m+1; k++ {
					AbMat.Set(i, k, AbMat.At(i, k)^AbMat.At(j, k))
				}
			}
		}
		if AbMat.At(i, i) == 0 {
			return nil
		}
		pi := math.Inv(AbMat.At(i, i))
		for k := i; k < m+1; k++ {
			AbMat.Set(i, k, math.Mul(pi, AbMat.At(i, k)))
		}
		for j := i + 1; j < m; j++ {
			aji := AbMat.At(j, i)
			for k := i; k < m+1; k++ {
				AbMat.Set(j, k, AbMat.At(j, k)^math.Mul(aji, AbMat.At(i, k)))
			}
		}
	}

	for i := m - 1; i > 0; i-- {
		aim := AbMat.At(i, m)
		for j := 0; j < i; j++ {
			AbMat.Set(j, m, AbMat.At(j, m)^math.Mul(AbMat.At(j, i), aim))
		}
	}

	res := make([]uint8, 0)
	r, c := AbMat.Dims()
	for i := 0; i < r; i++ {
		res = append(res, AbMat.At(i, c-1))
	}
	return res
}

package test

import (
	"bytes"
	"testing"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/crypto"
	"sebastienhauri.ch/mqt/math"
)

func TestUOVKeygen(t *testing.T) {
	n := constants.N
	m := constants.M
	uov := crypto.NewUOV(m, n, constants.UOV_PK_SEED_LEN, constants.UOV_SK_SEED_LEN)
	sk, pk := uov.KeyGen()

	Pi1 := pk.P1i
	P1Len := (uov.N - uov.M) * (uov.N - uov.M + 1) / 2
	Pi2 := pk.P2i
	P2Len := (uov.N - uov.M) * uov.M
	Pi3 := pk.P3i
	P3Len := uov.M * (uov.M + 1) / 2
	Si := sk.Si
	O := math.NewDenseMatrix((uov.N - uov.M), uov.M, sk.O)
	OT := math.T(O)

	for i := 0; i < uov.M; i++ {
		P1 := math.NewUpperTriangle(
			math.NewDenseMatrix(
				(uov.N - uov.M), (uov.N - uov.M), Pi1[i*P1Len:(i+1)*P1Len]),
		)
		P2 := math.NewDenseMatrix(
			(uov.N - uov.M), uov.M, Pi2[i*P2Len:(i+1)*P2Len],
		)
		P3 := math.NewUpperTriangle(
			math.NewDenseMatrix(
				uov.M, uov.M, Pi3[i*P3Len:(i+1)*P3Len]),
		)
		S := math.NewDenseMatrix(
			(uov.N - uov.M), uov.M, Si[i*P2Len:(i+1)*P2Len],
		)

		// test that si is correct
		SPrime := math.AddMat(math.MulMat(math.AddMat(P1, math.T(P1)), O), P2)
		if !bytes.Equal(S.Data, SPrime.Data) {
			t.Error("Error in keygen.")
			return
		}

		// test P3 is correct
		M := math.AddMat(math.MulMat(math.MulMat(OT, P1), O), math.MulMat(OT, P2))
		SkewSym := math.AddMat(M, P3)
		r, c := SkewSym.Dims()
		if r != uov.M || c != uov.M {
			t.Error("Error in sizes")
			return
		}
		for i := 0; i < r; i++ {
			for j := 0; j < c; j++ {
				if SkewSym.At(i, j) != SkewSym.At(j, i) {
					t.Error("Not skew-symmetric !!")
					return
				}
			}
		}
	}
}

func TestUOVCorrectness(t *testing.T) {
	n := constants.N
	m := constants.M
	uov := crypto.NewUOV(m, n, constants.UOV_PK_SEED_LEN, constants.UOV_SK_SEED_LEN)
	sk, pk := uov.KeyGen()

	msg := crypto.Nrand128(constants.N, []byte{0})
	t.Log(len(msg), "x =", msg)
	res := mq(m, n, msg, pk)
	t.Log(len(res), "P(x) =", res)

	if !uov.Verify(res, msg, pk) {
		t.Error("Evaluation does not verify")
		return
	}

	sig := uov.Sign(msg, sk)
	t.Log(len(sig), "x' =", sig)

	res2 := mq(m, n, sig, pk)
	t.Log(len(res2), "P(x') =", res2)
}

func TestSolve(t *testing.T) {
	A := []uint8{
		1, 2, 3, 7,
		4, 57, 145, 9,
		132, 35, 87, 101,
		0, 189, 37, 12,
	}
	x := crypto.Nrand128(4, []byte{1})
	t.Log("x =", x)

	matA := math.NewDenseMatrix(4, 4, A)
	vecX := math.NewVector(x)

	b := math.MulMat(matA, vecX)
	if b == nil {
		return
	}
	t.Log("b =", b.Data)

	xPrime := crypto.Solve(A, b.Data, 4)
	if xPrime == nil {
		t.Log("x' is nil")
	}
	t.Log("x' =", xPrime)

	if !bytes.Equal(x, xPrime) {
		t.Error("results dont match.")
	}
}

func mq(m, n int, msg []uint8, pk *crypto.UOVPublicKey) []uint8 {
	vec := math.NewVector(msg)
	lenP1 := (n - m) * (n - m + 1) / 2
	lenP2 := (n - m) * m
	lenP3 := m * (m + 1) / 2

	res := make([]uint8, 0)
	for k := 0; k < m; k++ {
		var acc uint8 = 0
		P1 := math.NewUpperTriangle(
			math.NewDenseMatrix(
				n-m, n-m,
				pk.P1i[k*lenP1:(k+1)*lenP1],
			),
		)
		P2 := math.NewDenseMatrix(
			n-m, m, pk.P2i[k*lenP2:(k+1)*lenP2],
		)
		P3 := math.NewUpperTriangle(
			math.NewDenseMatrix(
				m, m, pk.P3i[k*lenP3:(k+1)*lenP3],
			),
		)
		for i := 0; i < n; i++ {
			for j := i; j < n; j++ {
				t := math.Mul(vec.At(i, 0), vec.At(j, 0))
				if j < n-m {
					acc ^= math.Mul(t, P1.At(i, j))
				} else {
					if i < n-m {
						acc ^= math.Mul(t, P2.At(i, j-n+m))
					} else {
						acc ^= math.Mul(t, P3.At(i-n+m, j-n+m))
					}
				}
			}
		}
		res = append(res, acc)
	}
	return res
}

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

	x := crypto.Nrand128(constants.N, []byte{0})
	t.Log(len(x), "x =", x)
	Px := math.MQUOV(pk.P1i, pk.P2i, pk.P3i, x, m)
	t.Log(len(Px), "P(x) =", Px)

	if !uov.Verify(Px, x, pk) {
		t.Error("Evaluation does not verify")
		return
	}

	sig := uov.Sign(Px, sk)
	t.Log(len(sig), "x' =", sig)

	if !uov.Verify(Px, x, pk) {
		t.Error("Signature does not verify")
		return
	}
	res2 := math.MQUOV(pk.P1i, pk.P2i, pk.P3i, sig, m)
	t.Log(len(res2), "P(x') =", res2)
}

package test

import (
	"bytes"
	"testing"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/crypto"
	"sebastienhauri.ch/mqt/math"
)

func TestUOVCorrectness(t *testing.T) {
	n := constants.N
	m := constants.M
	uov := crypto.NewUOV(m, n, constants.UOV_PK_SEED_LEN, constants.UOV_SK_SEED_LEN)
	sk, pk := uov.KeyGen()

	msg := crypto.Nrand128(constants.N, []byte{0})
	t.Log(len(msg), msg)
	res := mq(m, n, msg, pk)
	t.Log(len(res), res)

	sig := uov.Sign(msg, sk)
	t.Log(len(sig), sig)

	res2 := mq(m, n, sig, pk)
	t.Log(len(res2), res2)
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

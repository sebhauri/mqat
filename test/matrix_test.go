package test

import (
	"bytes"
	"mqat/crypto"
	"mqat/math"
	"testing"
)

func matrixEqual(A, B math.Matrix) bool {
	m, n := A.Dims()
	mB, nB := B.Dims()
	if mB != m || nB != n {
		return false
	}
	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			if A.At(i, j) != B.At(i, j) {
				return false
			}
		}
	}
	return true
}

func TestNewDenseMatrix(t *testing.T) {
	n := 4
	m := 6
	// will panic if new dense accesses invalid memory
	mat := math.NewDenseMatrix(n, m, nil)
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			v := mat.At(i, j)
			if v != 0 {
				t.Error("matrix was expected to be zero")
			}
		}
	}
}

func TestDims(t *testing.T) {
	A := math.NewDenseMatrix(3, 4, nil)
	m, n := A.Dims()
	if m != 3 || n != 4 {
		t.Errorf("matrix had shape (%d,%d), expected (3,4)", m, n)
	}
}

func TestMatTranspose(t *testing.T) {
	inp := math.NewDenseMatrix(2, 3, []uint8{
		1, 2, 3,
		4, 5, 6})
	exp := math.NewDenseMatrix(3, 2, []uint8{
		1, 4,
		2, 5,
		3, 6})
	inpT := math.T(inp)
	if !matrixEqual(exp, inpT) {
		t.Error("matrix transpose did not match expectation")
	}
}

func TestMatUpperTriangle(t *testing.T) {
	inp1 := math.NewDenseMatrix(3, 3, []uint8{
		1, 2, 3,
		0, 4, 5,
		0, 0, 6})
	inp2 := math.NewDenseMatrix(3, 3, []uint8{
		1, 2, 3,
		4, 5,
		6})
	inpUT := math.NewUpperTriangle(inp2)
	r1, c1 := inp1.Dims()
	r2, c2 := inpUT.Dims()
	if r1 != r2 || c1 != c2 {
		t.Error("bad dimensions for UT matrix")
		return
	}

	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			a := inp1.At(i, j)
			b := inpUT.At(i, j)
			t.Logf("(%d, %d) : %d  %d)", i, j, a, b)
			if a != b {
				t.Error("bad indexes UT matrix")
				return
			}
		}
	}
}

func TestMatAdd(t *testing.T) {
	inp := math.NewDenseMatrix(2, 3, []uint8{
		1, 2, 3,
		4, 5, 6,
	})
	sub := math.NewDenseMatrix(2, 3, []uint8{
		2, 3, 4,
		5, 6, 7,
	})
	exp := math.NewDenseMatrix(2, 3, []uint8{
		3, 1, 7,
		1, 3, 1,
	})
	out := math.AddMat(inp, sub)
	if !matrixEqual(exp, out) {
		t.Error("matrix sub did not match expectation")
	}
}

func TestMatMul(t *testing.T) {
	inp := math.NewDenseMatrix(2, 3, []uint8{
		127, 22, 30,
		48, 54, 69,
	})
	sub := math.NewDenseMatrix(3, 2, []uint8{
		29, 31,
		111, 52,
		240, 7,
	})
	exp := math.NewDenseMatrix(2, 2, []uint8{
		97, 141,
		149, 233,
	})
	out := math.MulMat(inp, sub)
	if !matrixEqual(exp, out) {
		t.Error("matrix sub did not match expectation")
	}
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
	vecB := math.NewVector(b.Data)

	xPrime := math.Solve(matA, vecB)
	if xPrime.Data == nil {
		t.Log("x' is nil")
	}
	t.Log("x' =", xPrime)

	if !bytes.Equal(x, xPrime.Data) {
		t.Error("results dont match.")
	}
}

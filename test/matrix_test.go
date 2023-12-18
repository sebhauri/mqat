package test

import (
	"testing"

	"sebastienhauri.ch/mqt/math"
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

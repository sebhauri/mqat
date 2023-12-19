package test

import (
	"crypto/rand"
	"testing"

	"sebastienhauri.ch/mqt/math"
)

func TestMul(t *testing.T) {
	var a uint8 = 76
	var b uint8 = 85
	t.Logf("a=%d, b=%d", a, b)
	c := math.Mul(a, b)

	if c != 77 {
		t.Errorf("Multiplication not working !!!")
	}
	t.Logf("a=%d, b=%d", a, b)
}

func TestInverse(t *testing.T) {
	a := make([]uint8, 1)
	rand.Read(a)
	a1 := math.Mul(a[0], 1)
	t.Log(a1)
	b := math.Inv(a[0])
	t.Log(b)
	one := math.Mul(a[0], b)
	if one != 1 {
		t.Error("Inverse is incorrect")
	}
}

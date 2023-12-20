package test

import (
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
	for i := 1; i < 256; i++ {
		a := uint8(i)
		b := math.Inv(a)
		if math.Mul(a, b) != 1 {
			t.Errorf("%d * %d != 1", a, b)
			return
		}
	}
}

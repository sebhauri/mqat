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

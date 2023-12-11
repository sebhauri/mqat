package test

import (
	"testing"

	"sebastienhauri.ch/mqt/math"
)

func TestMul(t *testing.T) {
	var a uint8 = 76
	var b uint8 = 85
	c := math.Mul(a, b)

	if c != 77 {
		t.Errorf("Multiplication not working !!!")
	}
}

package test

import (
	"testing"

	"sebastienhauri.ch/mqt/math"
)

const q = 31
const m = 64
const n = 128
const flen = m * (n*(n+1)/2 + n)

func TestMQ(t *testing.T) {
	x_seed := []byte{0}
	F_seed := []byte{1}
	x := math.Gf31_nrand(n, x_seed)
	F := math.Gf31_nrand_signed(flen, F_seed)
	fx := math.MQ(F, x, m)
	t.Logf("fx=%v", fx)

	var x2 [n]int
	var fx2 [m]int
	var F2 [flen]int
	for i := 0; i < n; i++ {
		x2[i] = int(x[i])
	}
	for i := 0; i < flen; i++ {
		F2[i] = int(F[i])
	}
	filen := n * (n + 1) / 2
	xij := make([]int, filen)
	k := 0
	for i := 0; i < n && k < filen; i++ {
		for j := i; j < n && k < filen; j++ {
			xij[k] = (x2[i]*x2[j] + q) % q
			k++
		}
	}
	xijxi := append(xij, x2[:]...)
	if len(xijxi) != filen+n {
		t.Errorf("xijxi does not have good length.")
	}
	for i := 0; i < m; i++ {
		fxi := 0
		for j := 0; j < filen+n; j++ {
			fxi += (xijxi[j]*F2[i*(filen+n)+j] + q) % q
		}
		fx2[i] = (fxi + q) % q
	}
	t.Logf("fx'=%v", fx2)

	for i, v := range fx2 {
		if v != int(fx[i]) {
			t.Errorf("MQ does return wrong result.")
		}
	}
}

func TestG(t *testing.T) {
	x_seed := []byte{0}
	y_seed := []byte{2}
	F_seed := []byte{1}
	x := math.Gf31_nrand(n, x_seed)
	y := math.Gf31_nrand(n, y_seed)
	F := math.Gf31_nrand_signed(flen, F_seed)
	fx := math.MQ(F, x, m)
	fy := math.MQ(F, y, m)
	var xplusy [n]uint8
	for i := 0; i < n; i++ {
		xplusy[i] = uint8((int(x[i]) + int(y[i])) % q)
	}
	fxplusy := math.MQ(F, xplusy[:], m)
	gxy := math.G(F, x, y, m)

	t.Logf("f(x)=%v", fx)
	t.Logf("f(y)=%v", fy)
	t.Logf("f(x+y)=%v", fxplusy)
	t.Logf("gxy=%v", gxy)

	for i := 0; i < m; i++ {
		tmp := (int(fxplusy[i]) - int(fx[i]) - int(fy[i]) + 62) % 31
		if int(gxy[i]) != tmp {
			t.Errorf("%d) %d = %d - %d - %d != %d ", i, tmp, fxplusy[i], fx[i], fy[i], gxy[i])
		}
	}
}

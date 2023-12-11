package test

import (
	"testing"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/math"
)

func TestMQ(t *testing.T) {
	x_seed := []byte{0}
	F_seed := []byte{1}
	x := math.Nrand(constants.N, x_seed)
	F := math.Nrand(constants.FLEN, F_seed)
	fx := math.MQ(F, x, constants.M)
	t.Logf("fx=%v", fx)

	x2 := make([]uint8, constants.N)
	fx2 := make([]uint8, constants.M)
	F2 := make([]uint8, constants.FLEN)
	for i := 0; i < constants.N; i++ {
		x2[i] = x[i]
	}
	for i := 0; i < constants.FLEN; i++ {
		F2[i] = F[i]
	}
	filen := constants.N * (constants.N + 1) / 2
	xij := make([]uint8, filen)
	k := 0
	for i := 0; i < constants.N && k < filen; i++ {
		for j := i; j < constants.N && k < filen; j++ {
			xij[k] = math.Mul(x2[i], x2[j])
			k++
		}
	}
	xijxi := append(xij, x2[:]...)
	if len(xijxi) != filen+constants.N {
		t.Errorf("xijxi does not have good length.")
		return
	}
	for i := 0; i < constants.M; i++ {
		var fxi uint8 = 0
		for j := 0; j < filen+constants.N; j++ {
			fxi += math.Mul(xijxi[j], F2[i*(filen+constants.N)+j])
		}
		fx2[i] = fxi
	}
	t.Logf("fx'=%v", fx2)

	for i, v := range fx2 {
		if v != fx[i] {
			t.Errorf("MQ does return wrong result.")
			return
		}
	}
}

func TestG(t *testing.T) {
	x_seed := []byte{0}
	y_seed := []byte{2}
	F_seed := []byte{1}
	x := math.Nrand(constants.N, x_seed)
	y := math.Nrand(constants.N, y_seed)
	F := math.Nrand(constants.FLEN, F_seed)
	fx := math.MQ(F, x, constants.M)
	fy := math.MQ(F, y, constants.M)
	xplusy := make([]uint8, constants.N)
	for i := 0; i < constants.N; i++ {
		xplusy[i] = x[i] + y[i]
	}
	fxplusy := math.MQ(F, xplusy[:], constants.M)
	gxy := math.G(F, x, y, constants.M)

	t.Logf("f(x)=%v", fx)
	t.Logf("f(y)=%v", fy)
	t.Logf("f(x+y)=%v", fxplusy)
	t.Logf("gxy=%v", gxy)

	for i := 0; i < constants.M; i++ {
		tmp := (int(fxplusy[i]) - int(fx[i]) - int(fy[i]) + 62) % 31
		if int(gxy[i]) != tmp {
			t.Errorf("%d) %d = %d - %d - %d != %d ", i, tmp, fxplusy[i], fx[i], fy[i], gxy[i])
			return
		}
	}
}

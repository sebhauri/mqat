package test

import (
	"testing"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/math"
)

func TestCorrectness(t *testing.T) {
	x_seed := []byte{0}
	F_seed := []byte{1}
	seed := []byte{2}
	alpha_seed := []byte{3}
	F := math.Gf31_nrand_signed(uint(constants.FLEN), F_seed)
	x := math.Gf31_nrand(uint(constants.N), x_seed)
	v := math.MQ(F, x, constants.M)
	r0t0e0 := math.Gf31_nrand(uint((2*constants.N + constants.M)), seed)
	r0 := r0t0e0[:constants.N]
	r1 := make([]uint8, len(r0))
	t0 := r0t0e0[constants.N : 2*constants.N]
	t1 := make([]uint8, len(t0))
	e0 := r0t0e0[2*constants.N:]
	e1 := make([]uint8, len(e0))
	G := make([]uint8, 0)

	// compute r1
	for i := 0; i < constants.N; i++ {
		r1i := int(x[i]) - int(r0[i])
		r1[i] = math.Mod31(uint16((r1i >> 15) + (r1i & 0x7FFF)))
	}

	// compute G = G(t0, r1) + e0
	G = append(G, math.G(F, t0, r1, uint8(constants.M))...)
	for i := 0; i < constants.M; i++ {
		gi := int(G[i]) + int(e0[i])
		G[i] = math.Mod31(uint16((gi >> 15) + (gi & 0x7FFF)))
	}

	// generate aplpha
	alpha := math.Gf31_nrand(1, alpha_seed)

	// compute t1
	for i := 0; i < constants.N; i++ {
		t1i := int(alpha[0])*int(r0[i]) - int(t0[i])
		t1[i] = math.Mod31(uint16((t1i >> 15) + (t1i & 0x7FFF)))
	}

	// compute e1
	Fr0 := math.MQ(F, r0, uint8(constants.M))
	for i := 0; i < constants.M; i++ {
		e1i := int(alpha[0])*int(Fr0[i]) - int(e0[i])
		e1[i] = math.Mod31(uint16((e1i >> 15) + (e1i & 0x7FFF)))
	}

	// CHECKS:
	///////////////////////////////////////////////////////////////////////////

	// t0 = alpha * r0 - t1
	for i := 0; i < constants.N; i++ {
		t0i := int(alpha[0])*int(r0[i]) - int(t1[i])
		t0i_mod31 := math.Mod31(uint16((t0i >> 15) + (t0i & 0x7FFF)))
		if t0i_mod31 != t0[i] {
			t.Errorf("Error in recomputing t0.")
			return
		}
	}

	// e0 = alpha * F(r0) - e1
	for i := 0; i < constants.M; i++ {
		e0i := int(alpha[0])*int(Fr0[i]) - int(e1[i])
		e0i_mod31 := math.Mod31(uint16((e0i >> 15) + (e0i & 0x7FFF)))
		if e0i_mod31 != e0[i] {
			t.Errorf("Error in recomputing e0.")
			return
		}
	}

	// G(t0, r1) + e0 = alpha * (v - F(r1)) - G(r1, t1) - e1
	Fr1 := math.MQ(F, r1, constants.M)
	Gr1t1 := math.G(F, r1, t1, constants.M)
	for i := 0; i < constants.M; i++ {
		gi := int(alpha[0])*(int(v[i])-int(Fr1[i])) - int(Gr1t1[i]) - int(e1[i])
		gi_mod31 := math.Mod31(uint16((gi >> 15) + (gi & 0x7FFF)))
		if gi_mod31 != G[i] {
			t.Errorf("%d != %d*(%d - %d) - %d - %d (= %d)", G[i], alpha[0], v[i], Fr1[i], Gr1t1[i], e1[i], gi_mod31)
			return
		}
	}
}

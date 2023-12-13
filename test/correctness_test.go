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
	F := math.Nrand128(constants.FLEN, F_seed)
	x := math.Nrand256(constants.N, x_seed)
	v := math.MQ(F, x, constants.M)
	r0t0e0 := math.Nrand256(2*constants.N+constants.M, seed)
	r0 := r0t0e0[:constants.N]
	r1 := make([]uint8, len(r0))
	t0 := r0t0e0[constants.N : 2*constants.N]
	t1 := make([]uint8, len(t0))
	e0 := r0t0e0[2*constants.N:]
	e1 := make([]uint8, len(e0))
	G := make([]uint8, 0)

	// compute r1
	for i := 0; i < constants.N; i++ {
		r1i := x[i] ^ r0[i]
		r1[i] = r1i
	}

	// compute G = G(t0, r1) + e0
	G = append(G, math.G(F, t0, r1, constants.M)...)
	for i := 0; i < constants.M; i++ {
		gi := G[i] ^ e0[i]
		G[i] = gi
	}

	// generate aplpha
	alpha := math.Nrand256(1, alpha_seed)

	// compute t1
	for i := 0; i < constants.N; i++ {
		t1i := math.Mul(alpha[0], r0[i]) ^ t0[i]
		t1[i] = t1i
	}

	// compute e1
	Fr0 := math.MQ(F, r0, constants.M)
	for i := 0; i < constants.M; i++ {
		e1i := math.Mul(alpha[0], Fr0[i]) ^ e0[i]
		e1[i] = e1i
	}

	// CHECKS:
	///////////////////////////////////////////////////////////////////////////

	// t0 = alpha * r0 - t1
	for i := 0; i < constants.N; i++ {
		t0i := math.Mul(alpha[0], r0[i]) ^ t1[i]
		if t0i != t0[i] {
			t.Errorf("Error in recomputing t0.")
			return
		}
	}

	// e0 = alpha * F(r0) - e1
	for i := 0; i < constants.M; i++ {
		e0i := math.Mul(alpha[0], Fr0[i]) ^ e1[i]
		if e0i != e0[i] {
			t.Errorf("Error in recomputing e0.")
			return
		}
	}

	// G(t0, r1) + e0 = alpha * (v - F(r1)) - G(r1, t1) - e1
	Fr1 := math.MQ(F, r1, constants.M)
	Gr1t1 := math.G(F, r1, t1, constants.M)
	for i := 0; i < constants.M; i++ {
		gi := math.Mul(alpha[0], v[i]^Fr1[i]) ^ Gr1t1[i] ^ e1[i]
		if gi != G[i] {
			t.Errorf("%d) %d != %d*(%d - %d) - %d - %d (= %d)", i, G[i], alpha[0], v[i], Fr1[i], Gr1t1[i], e1[i], gi)
			return
		}
	}
}

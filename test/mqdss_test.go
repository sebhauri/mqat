package test

import (
	"testing"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/crypto"
	"sebastienhauri.ch/mqt/math"
)

func TestMQDSSCorrectness(t *testing.T) {
	n := constants.N
	m := constants.M
	x_seed := []byte{0}
	R_seed := []byte{1}
	P_seed := []byte{4}
	seed := []byte{2}
	alpha_seed := []byte{3}
	R := crypto.Nrand128(math.Flen(m, m), R_seed)
	P := crypto.Nrand128(math.Flen(m, n), P_seed)
	P1 := P[:m*(n-m)*(n-m+1)/2]
	P2 := P[m*(n-m)*(n-m+1)/2 : m*(n-m)*(n-m+1)/2+m*m*(n-m)]
	P3 := P[m*(n-m)*(n-m+1)/2+m*m*(n-m):]
	x := crypto.Nrand256(n+m, x_seed)
	v := math.MQ(P1, P2, P3, R, x, m, n)
	r0t0e0 := crypto.Nrand256(2*(n+m)+m, seed)
	r0 := r0t0e0[:n+m]
	r1 := make([]uint8, len(r0))
	t0 := r0t0e0[n+m : 2*(n+m)]
	t1 := make([]uint8, len(t0))
	e0 := r0t0e0[2*(n+m):]
	e1 := make([]uint8, len(e0))
	G := make([]uint8, 0)

	// compute r1
	for i := 0; i < n+m; i++ {
		r1i := x[i] ^ r0[i]
		r1[i] = r1i
	}

	// compute G = G(t0, r1) + e0
	G = append(G, math.G(P1, P2, P3, R, t0, r1, m, n)...)
	for i := 0; i < m; i++ {
		gi := G[i] ^ e0[i]
		G[i] = gi
	}

	// generate aplpha
	alpha := crypto.Nrand256(1, alpha_seed)

	// compute t1
	for i := 0; i < n+m; i++ {
		t1i := math.Mul(alpha[0], r0[i]) ^ t0[i]
		t1[i] = t1i
	}

	// compute e1
	Fr0 := math.MQ(P1, P2, P3, R, r0, m, n)
	for i := 0; i < m; i++ {
		e1i := math.Mul(alpha[0], Fr0[i]) ^ e0[i]
		e1[i] = e1i
	}

	// CHECKS:
	///////////////////////////////////////////////////////////////////////////

	// t0 = alpha * r0 - t1
	for i := 0; i < n+m; i++ {
		t0i := math.Mul(alpha[0], r0[i]) ^ t1[i]
		if t0i != t0[i] {
			t.Errorf("Error in recomputing t0.")
			return
		}
	}

	// e0 = alpha * F(r0) - e1
	for i := 0; i < m; i++ {
		e0i := math.Mul(alpha[0], Fr0[i]) ^ e1[i]
		if e0i != e0[i] {
			t.Errorf("Error in recomputing e0.")
			return
		}
	}

	// G(t0, r1) + e0 = alpha * (v - F(r1)) - G(r1, t1) - e1
	Fr1 := math.MQ(P1, P2, P3, R, r1, m, n)
	Gr1t1 := math.G(P1, P2, P3, R, r1, t1, m, n)
	for i := 0; i < m; i++ {
		gi := math.Mul(alpha[0], v[i]^Fr1[i]) ^ Gr1t1[i] ^ e1[i]
		if gi != G[i] {
			t.Errorf("%d) %d != %d*(%d - %d) - %d - %d (= %d)", i, G[i], alpha[0], v[i], Fr1[i], Gr1t1[i], e1[i], gi)
			return
		}
	}
}

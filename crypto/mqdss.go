package crypto

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/math"
)

func NewMQDSS(m, n, r, pk_seed_len, sk_seed_len int) *MQDSS {
	if m <= 0 || n <= 0 || r <= 0 || m > n {
		return nil
	}
	mqdss := new(MQDSS)
	mqdss.M = m
	mqdss.N = n
	mqdss.R = r
	mqdss.PkSeedLen = pk_seed_len
	mqdss.SkSeedLen = sk_seed_len
	return mqdss
}

// TODO: handling errors better
func (mqdss *MQDSS) KeyGen() (*MQDSSSecretKey, *MQDSSPublicKey) {
	m := mqdss.M
	n := mqdss.N - mqdss.M

	sk := new(MQDSSSecretKey)
	pk := new(MQDSSPublicKey)
	seed_S_P_R := make([]byte, 2*mqdss.PkSeedLen/8+mqdss.SkSeedLen/8)
	_, err := rand.Read(seed_S_P_R)
	if err != nil {
		return nil, nil
	}

	pk.R = Nrand128(math.Flen(m, m), seed_S_P_R[:mqdss.PkSeedLen/8])
	P := Nrand128(math.Flen(m, n), seed_S_P_R[mqdss.PkSeedLen/8:2*mqdss.PkSeedLen/8])
	P1len := m * (n - m) * (n - m + 1) / 2
	P2len := m * m * (n - m)
	pk.P1 = P[:P1len]
	pk.P2 = P[P1len : P1len+P2len]
	pk.P3 = P[P1len+P2len:]

	sk.S = Nrand256(mqdss.N, seed_S_P_R[2*mqdss.PkSeedLen/8:])
	pk.V = math.MQ(pk.P1, pk.P2, pk.P3, pk.R, sk.S, m, n)
	sk.Pk = pk

	return sk, pk
}

func (mqdss *MQDSS) KeyPair(P1, P2, P3, R, S, V []uint8) (*MQDSSSecretKey, *MQDSSPublicKey) {
	sk := new(MQDSSSecretKey)
	pk := new(MQDSSPublicKey)

	sk.S = S
	pk.P1 = P1
	pk.P2 = P2
	pk.P3 = P3
	pk.R = R
	pk.V = V
	sk.Pk = pk

	return sk, pk
}

func (mqdss *MQDSS) Sign(message []uint8, sk *MQDSSSecretKey) []byte {
	seedC := append(sk.Pk.P1, sk.Pk.P2...)
	seedC = append(seedC, sk.Pk.P3...)
	seedC = append(seedC, sk.Pk.R...)
	seedC = append(seedC, message...)
	C := H(seedC)
	seedD := append(C[:], message...)
	D := H(seedD)
	seed := make([]byte, mqdss.SkSeedLen)
	_, err := rand.Read(seed)
	if err != nil {
		return nil
	}
	r0t0e0 := Nrand256((2*mqdss.N+mqdss.M)*mqdss.R, seed)
	r0 := r0t0e0[:mqdss.R*mqdss.N]
	r1 := make([]uint8, len(r0))
	t0 := r0t0e0[uint(mqdss.R)*uint(mqdss.N) : 2*uint(mqdss.R)*uint(mqdss.N)]
	t1 := make([]uint8, len(t0))
	e0 := r0t0e0[2*uint(mqdss.R)*uint(mqdss.N):]
	e1 := make([]uint8, len(e0))
	G := make([]uint8, 0)

	sk_gf256 := sk.S
	for i := 0; i < mqdss.R; i++ {
		for j := 0; j < mqdss.N; j++ {
			r1ij := sk_gf256[j] ^ r0[j+i*int(mqdss.N)]
			r1[j+i*int(mqdss.N)] = r1ij
		}
		G = append(G,
			math.G(sk.Pk.P1, sk.Pk.P2, sk.Pk.P3, sk.Pk.R,
				t0[i*int(mqdss.N):(i+1)*int(mqdss.N)],
				r1[i*int(mqdss.N):(i+1)*int(mqdss.N)],
				mqdss.M, mqdss.N-mqdss.M)...)
	}
	for i := 0; i < mqdss.R*mqdss.M; i++ {
		gi := G[i] ^ e0[i]
		G[i] = gi
	}

	c := make([]byte, 0)
	for i := 0; i < mqdss.R; i++ {
		c = append(c, com0(r0[i*mqdss.N:(i+1)*mqdss.N], t0[i*mqdss.N:(i+1)*mqdss.N], e0[i*mqdss.M:(i+1)*mqdss.M])...)
		c = append(c, com1(r1[i*mqdss.N:(i+1)*mqdss.N], G[i*mqdss.M:(i+1)*mqdss.M])...)
	}
	sigma0 := H(c)
	h0 := append(D[:], sigma0[:]...)

	alphas := Nrand256(mqdss.R, h0)
	for i := 0; i < mqdss.R; i++ {
		for j := 0; j < int(mqdss.N); j++ {
			t1ij := math.Mul(alphas[i], r0[i*mqdss.N+j]) ^ t0[i*mqdss.N+j]
			t1[i*mqdss.N+j] = t1ij
		}
		Fr0 := math.MQ(sk.Pk.P1, sk.Pk.P2, sk.Pk.P3, sk.Pk.R,
			r0[i*int(mqdss.N):(i+1)*int(mqdss.N)],
			mqdss.M, mqdss.N-mqdss.M)
		for j := 0; j < mqdss.M; j++ {
			e1ij := math.Mul(alphas[i], Fr0[j]) ^ e0[i*mqdss.M+j]
			e1[i*mqdss.M+j] = e1ij
		}
	}
	sigma1 := append(t1, e1...)
	h1 := sha3.NewShake256()
	tohash := append(h0, sigma1...)
	h1.Write(tohash)
	shakeBlock := make([]byte, h1.BlockSize())
	sigma2 := make([]byte, 0)
	for i := 0; i < mqdss.R; {
		h1.Read(shakeBlock)
		for _, v := range shakeBlock {
			b := v & 1
			if b == 0 {
				sigma2 = append(sigma2, r0[i*int(mqdss.N):(i+1)*int(mqdss.N)]...)
				sigma2 = append(sigma2, c[constants.HASH_BYTES*(2*i+1):constants.HASH_BYTES*(2*(i+1))]...)
			} else {
				sigma2 = append(sigma2, r1[i*int(mqdss.N):(i+1)*int(mqdss.N)]...)
				sigma2 = append(sigma2, c[constants.HASH_BYTES*(2*i):constants.HASH_BYTES*(2*i+1)]...)
			}
			i++
			if i >= int(mqdss.R) {
				break
			}
		}
	}
	sig := append(C[:], sigma0[:]...)
	sig = append(sig, sigma1...)
	sig = append(sig, sigma2...)
	return sig
}

func (mqdss *MQDSS) Verify(message []uint8, sig []byte, pk *MQDSSPublicKey) bool {
	C := bytes.Clone(sig[:constants.HASH_BYTES])
	tohash := append(C, message...)
	D := H(tohash)

	sigma0 := bytes.Clone(sig[constants.HASH_BYTES : 2*constants.HASH_BYTES])
	offset := 2*constants.HASH_BYTES + mqdss.R*(mqdss.M+mqdss.N)
	sigma1 := bytes.Clone(sig[2*constants.HASH_BYTES : offset])
	sigma2 := bytes.Clone(sig[offset:])

	h0 := append(D[:], sigma0...)
	alphas := Nrand256(mqdss.R, h0)
	h1 := sha3.NewShake256()
	tohash = append(h0, sigma1...)
	h1.Write(tohash)
	shakeBlock := make([]byte, h1.BlockSize())
	c := make([]byte, 0)
	for i := 0; i < mqdss.R; {
		h1.Read(shakeBlock)
		for _, v := range shakeBlock {
			r_offset := i * (mqdss.N + constants.HASH_BYTES)
			c_offset := r_offset + mqdss.N
			r_ch := bytes.Clone(sigma2[r_offset:c_offset])
			c_ch := bytes.Clone(sigma2[c_offset : c_offset+constants.HASH_BYTES])
			t_offset := i * mqdss.N
			t1 := sigma1[t_offset : t_offset+mqdss.N]
			e_offset := mqdss.R*mqdss.N + i*mqdss.M
			e1 := sigma1[e_offset : e_offset+mqdss.M]

			b := v & 1
			if b == 0 {
				x := make([]uint8, mqdss.N)
				for j := 0; j < mqdss.N; j++ {
					xj := math.Mul(alphas[i], uint8(r_ch[j])) ^ uint8(t1[j])
					x[j] = xj
				}
				y := math.MQ(pk.P1, pk.P2, pk.P3, pk.R, r_ch, mqdss.M, mqdss.N-mqdss.M)
				for j := 0; j < int(mqdss.M); j++ {
					yj := math.Mul(alphas[i], y[j]) ^ uint8(e1[j])
					y[j] = yj
				}
				c0 := com0(r_ch, x, y)
				c = append(c, c0...)
				c = append(c, c_ch...)
			} else {
				y := math.MQ(pk.P1, pk.P2, pk.P3, pk.R, r_ch, mqdss.M, mqdss.N-mqdss.M)
				z := math.G(pk.P1, pk.P2, pk.P3, pk.R, r_ch, t1, mqdss.M, mqdss.N-mqdss.M)
				for j := 0; j < int(mqdss.M); j++ {
					yj := math.Mul(alphas[i], pk.V[j]^y[j]) ^ z[j] ^ uint8(e1[j])
					y[j] = yj
				}
				c = append(c, c_ch...)
				c1 := com1(r_ch, y)
				c = append(c, c1...)
			}
			i++
			if i >= int(mqdss.R) {
				break
			}
		}
	}
	sigma0_prime := H(c)
	return bytes.Equal(sigma0, sigma0_prime[:])
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

func com0(r0, t0, e0 []uint8) []byte {
	tmp := append(bytes.Clone(t0), bytes.Clone(e0)...)
	m := append(bytes.Clone(r0), tmp...)
	digest := sha3.Sum256(bytes.Clone(m))
	return digest[:]
}

func com1(r1, gx []uint8) []byte {
	m := append(bytes.Clone(r1), bytes.Clone(gx)...)
	digest := sha3.Sum256(bytes.Clone(m))
	return digest[:]
}

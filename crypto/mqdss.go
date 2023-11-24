package crypto

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/math"
)

type MQDSS struct {
	N, M uint8
	R    uint16
	flen uint
}

func NewMQDSS(m, n uint8, r uint16) *MQDSS {
	if m > n {
		return nil
	}
	mqdss := new(MQDSS)
	mqdss.M = m
	mqdss.N = n
	mqdss.R = r //TODO: See what we can do better with this.
	mqdss.flen = (uint(n)*uint((n+1))/2 + uint(n)) * uint(m)
	return mqdss
}

// TODO: handling errors better
func (mqdss *MQDSS) KeyPair() *KeyPair {
	kp := new(KeyPair)
	sk_sf := make([]byte, 2*constants.SEED_BYTES)
	_, err := rand.Read(sk_sf)
	if err != nil {
		return nil
	}
	kp.S.sk = sk_sf[len(sk_sf)/2:]
	kp.S.seed = sk_sf[:len(sk_sf)/2]
	kp.P.seed = sk_sf[:len(sk_sf)/2]
	F := math.Gf31_nrand_signed(mqdss.flen, kp.P.seed)
	if F == nil {
		return nil
	}
	sk_gf31 := math.Gf31_nrand(uint(mqdss.N), kp.S.sk)
	if sk_gf31 == nil {
		return nil
	}
	pk_gf31 := math.MQ(F, sk_gf31, mqdss.M)
	if pk_gf31 == nil {
		return nil
	}
	kp.P.v = pk_gf31
	return kp
}

func (mqdss *MQDSS) Sign(message Message, sk SecretKey) Signature {
	F := math.Gf31_nrand_signed(mqdss.flen, sk.seed)
	if F == nil {
		return nil
	}
	tohash := append(sk.sk, message...)
	C := h(tohash)
	tohash = append(C[:], message...)
	D := h(tohash)
	seed := append(sk.sk, D[:]...)
	r0t0e0 := math.Gf31_nrand((2*uint(mqdss.N)+uint(mqdss.M))*uint(mqdss.R), seed)
	r0 := r0t0e0[:uint(mqdss.R)*uint(mqdss.N)]
	r1 := make([]uint8, len(r0))
	t0 := r0t0e0[uint(mqdss.R)*uint(mqdss.N) : 2*uint(mqdss.R)*uint(mqdss.N)]
	t1 := make([]uint8, len(t0))
	e0 := r0t0e0[2*uint(mqdss.R)*uint(mqdss.N):]
	e1 := make([]uint8, len(e0))
	G := make([]uint8, 0)

	sk_gf31 := math.Gf31_nrand(uint(mqdss.N), sk.sk)
	for i := 0; i < int(mqdss.R); i++ {
		for j := 0; j < int(mqdss.N); j++ {
			r1ij := int(sk_gf31[j]) - int(r0[j+i*int(mqdss.N)])
			r1[j+i*int(mqdss.N)] = math.Mod31(uint16((r1ij >> 15) + (r1ij & 0x7FFF)))
		}
		G = append(G, math.G(F, t0[i*int(mqdss.N):(i+1)*int(mqdss.N)], r1[i*int(mqdss.N):(i+1)*int(mqdss.N)], mqdss.M)...)
	}
	for i := 0; i < int(mqdss.R)*int(mqdss.M); i++ {
		gi := int(G[i]) + int(e0[i])
		G[i] = math.Mod31(uint16((gi >> 15) + (gi & 0x7FFF)))
	}

	c := make([]byte, 0)
	for i := 0; i < int(mqdss.R); i++ {
		c = append(c, com0(r0[i*int(mqdss.N):(i+1)*int(mqdss.N)], t0[i*int(mqdss.N):(i+1)*int(mqdss.N)], e0[i*int(mqdss.M):(i+1)*int(mqdss.M)])...)
		c = append(c, com1(r1[i*int(mqdss.N):(i+1)*int(mqdss.N)], G[i*int(mqdss.M):(i+1)*int(mqdss.M)])...)
	}
	sigma0 := h(c)
	h0 := append(D[:], sigma0[:]...)

	alphas := math.Gf31_nrand(uint(mqdss.R), h0)
	for i := 0; i < int(mqdss.R); i++ {
		for j := 0; j < int(mqdss.N); j++ {
			t1ij := int(alphas[i])*int(r0[i*int(mqdss.N)+j]) - int(t0[i*int(mqdss.N)+j])
			t1[i*int(mqdss.N)+j] = math.Mod31(uint16((t1ij >> 15) + (t1ij & 0x7FFF)))
		}
		Fr0 := math.MQ(F, r0[i*int(mqdss.N):(i+1)*int(mqdss.N)], mqdss.M)
		for j := 0; j < int(mqdss.M); j++ {
			e1ij := int(alphas[i])*int(Fr0[j]) - int(e0[i*int(mqdss.M)+j])
			e1[i*int(mqdss.M)+j] = math.Mod31(uint16((e1ij >> 15) + (e1ij & 0x7FFF)))
		}
	}
	sigma1 := append(t1, e1...)
	h1 := sha3.NewShake128()
	tohash = append(h0, sigma1...)
	h1.Write(tohash)
	shakeBlock := make([]byte, h1.BlockSize())
	sigma2 := make([]byte, 0)
	for i := 0; i < int(mqdss.R); {
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

func (mqdss *MQDSS) Verify(message Message, sig Signature, pk PublicKey) bool {
	F := math.Gf31_nrand_signed(mqdss.flen, pk.seed)
	C := bytes.Clone(sig[:constants.HASH_BYTES])
	tohash := append(C, message...)
	D := h(tohash)

	sigma0 := bytes.Clone(sig[constants.HASH_BYTES : 2*constants.HASH_BYTES])
	offset := 2*constants.HASH_BYTES + uint(mqdss.R)*(uint(mqdss.M)+uint(mqdss.N))
	sigma1 := bytes.Clone(sig[2*constants.HASH_BYTES : offset])
	sigma2 := bytes.Clone(sig[offset:])

	h0 := append(D[:], sigma0...)
	alphas := math.Gf31_nrand(uint(mqdss.R), h0)
	h1 := sha3.NewShake128()
	tohash = append(h0, sigma1...)
	h1.Write(tohash)
	shakeBlock := make([]byte, h1.BlockSize())
	c := make([]byte, 0)
	for i := 0; i < int(mqdss.R); {
		h1.Read(shakeBlock)
		for _, v := range shakeBlock {
			r_offset := i * (int(mqdss.N) + constants.HASH_BYTES)
			c_offset := r_offset + int(mqdss.N)
			r_ch := bytes.Clone(sigma2[r_offset:c_offset])
			c_ch := bytes.Clone(sigma2[c_offset : c_offset+constants.HASH_BYTES])
			t_offset := i * int(mqdss.N)
			t1 := sigma1[t_offset : t_offset+int(mqdss.N)]
			e_offset := int(mqdss.R)*int(mqdss.N) + i*int(mqdss.M)
			e1 := sigma1[e_offset : e_offset+int(mqdss.M)]

			b := v & 1
			if b == 0 {
				x := make([]uint8, mqdss.N)
				for j := 0; j < int(mqdss.N); j++ {
					xj := int(alphas[i])*int(r_ch[j]) - int(t1[j])
					x[j] = math.Mod31(uint16((xj >> 15) + (xj & 0x7FFF)))
				}
				y := math.MQ(F, r_ch, mqdss.M)
				for j := 0; j < int(mqdss.M); j++ {
					yj := int(alphas[i])*int(y[j]) - int(e1[j])
					y[j] = math.Mod31(uint16((yj >> 15) + (yj & 0x7FFF)))
				}
				c0 := com0(r_ch, x, y)
				c = append(c, c0...)
				c = append(c, c_ch...)
			} else {
				y := math.MQ(F, r_ch, mqdss.M)
				z := math.G(F, r_ch, t1, mqdss.M)
				for j := 0; j < int(mqdss.M); j++ {
					yj := int(alphas[i])*(int(pk.v[j])-int(y[j])) - int(z[j]) - int(e1[j])
					y[j] = math.Mod31(uint16((yj >> 15) + (yj & 0x7FFF)))
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
	sigma0_prime := h(c)
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

func h(data []byte) [constants.HASH_BYTES]byte {
	return sha3.Sum256(bytes.Clone(data))
}

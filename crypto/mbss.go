package crypto

import (
	"crypto/rand"
	"encoding/json"

	"golang.org/x/crypto/sha3"
	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/math"
)

type MBSS struct {
	n, m uint8
	r    uint16
	flen uint
}

func NewMBSS(m, n uint8) *MBSS {
	if m > n {
		return nil
	}
	mqt := new(MBSS)
	mqt.m = m
	mqt.n = n
	mqt.r = 269 //TODO: See what we can do better with this.
	mqt.flen = (uint(n)*uint((n+1))/2 + uint(n)) * uint(m)
	return mqt
}

// TODO: handling errors better
func (mbss *MBSS) KeyPair() *KeyPair {
	kp := new(KeyPair)
	sk_sf := make([]byte, 2*constants.SEED_BYTES)
	_, err := rand.Read(sk_sf)
	if err != nil {
		return nil
	}
	kp.S.sk = sk_sf[len(sk_sf)/2:]
	kp.S.seed = sk_sf[:len(sk_sf)/2]
	kp.P.seed = sk_sf[:len(sk_sf)/2]
	F := math.Gf31_nrand_signed(mbss.flen, kp.P.seed)
	if F == nil {
		return nil
	}
	sk_gf31 := math.Gf31_nrand(uint(mbss.n), kp.S.sk)
	if sk_gf31 == nil {
		return nil
	}
	pk_gf31 := math.MQ(F, sk_gf31, mbss.m)
	if pk_gf31 == nil {
		return nil
	}
	kp.P.v = pk_gf31
	return kp
}

func (mbss *MBSS) Sign(message Message, sk SecretKey) Signature {
	F := math.Gf31_nrand_signed(mbss.flen, sk.seed)
	if F == nil {
		return nil
	}
	C := h(append(sk.sk, message...))
	D := h(append(C[:], message...))

	r0t0e0 := math.Gf31_nrand((2*uint(mbss.n)+uint(mbss.m))*uint(mbss.r), append(sk.sk, D[:]...))
	r0 := r0t0e0[:uint(mbss.r)*uint(mbss.n)]
	r1 := make([]math.Gf31, len(r0))
	t0 := r0t0e0[uint(mbss.r)*uint(mbss.n) : 2*uint(mbss.r)*uint(mbss.n)]
	t1 := make([]math.Gf31, len(t0))
	e0 := r0t0e0[2*uint(mbss.r)*uint(mbss.n):]
	e1 := make([]math.Gf31, len(e0))
	G := make([]math.Gf31, uint(mbss.m)*uint(mbss.r))
	sk_gf31 := math.Gf31_nrand(uint(mbss.n), sk.sk)
	for i := 0; i < int(mbss.r); i++ {
		for j := 0; j < int(mbss.n); j++ {
			r1[j+i*int(mbss.n)] = math.Mod31(sk_gf31[j] - r0[j+i*int(mbss.n)])
		}
		G = append(G, math.G(F, t0[i*int(mbss.n):(i+1)*int(mbss.n)], r1[i*int(mbss.n):(i+1)*int(mbss.n)], mbss.m)...)
	}
	for i := 0; i < int(mbss.r)*int(mbss.m); i++ {
		G[i] = math.Mod31(G[i] + e0[i])
	}

	c := make([]byte, 2*constants.HASH_BYTES*mbss.r)
	for i := 0; i < int(mbss.r); i++ {
		c = append(c, com0(r0[i*int(mbss.n):(i+1)*int(mbss.n)], t0[i*int(mbss.n):(i+1)*int(mbss.n)], e0[i*int(mbss.m):(i+1)*int(mbss.m)])...)
		c = append(c, com1(r1[i*int(mbss.n):(i+1)*int(mbss.n)], G[i*int(mbss.m):(i+1)*int(mbss.m)])...)
	}
	sigma0 := h(c)
	h0 := append(D[:], sigma0[:]...)

	alphas := math.Gf31_nrand(uint(mbss.r), h0)
	for i := 0; i < int(mbss.r); i++ {
		for j := 0; j < int(mbss.n); j++ {
			t1ij := int(alphas[i])*int(r0[i*int(mbss.n)+j]) - int(t0[i*int(mbss.n)+j])
			t1[i*int(mbss.n)+j] = math.Mod31(math.Gf31((t1ij >> 15) + (t1ij & 0x7FFF)))
		}
		e1 = append(e1, math.MQ(F, r0[i*int(mbss.n):(i+1)*int(mbss.n)], mbss.m)...)
		for j := 0; j < int(mbss.m); j++ {
			e1ij := int(alphas[i]) * int(e1[i*int(mbss.m)+j])
			e1ij -= int(e0[i*int(mbss.m)+j])
			e1[i*int(mbss.m)+j] = math.Mod31(math.Gf31((e1ij >> 15) + (e1ij & 0x7FFF)))
		}
	}
	sigma1 := append(t1, e1...)
	sigma1_bytes, err := json.Marshal(sigma1)
	if err != nil {
		return nil
	}
	h1 := sha3.NewShake128()
	h1.Write(append(h0, sigma1_bytes...))
	shakeBlock := make([]byte, h1.BlockSize())
	sigma2 := make([]byte, uint(mbss.r)*(uint(mbss.n)+constants.HASH_BYTES))
	for i := 0; i < int(mbss.r); i++ {
		h1.Read(shakeBlock)
		for _, v := range shakeBlock {
			b := v & 1
			if b == 0 {
				r0_bytes, err := json.Marshal(r0[i*int(mbss.n) : (i+1)*int(mbss.n)])
				if err != nil {
					return nil
				}
				sigma2 = append(sigma2, r0_bytes...)
				sigma2 = append(sigma2, c[constants.HASH_BYTES*(2*i+1)])
			} else {
				r1_bytes, err := json.Marshal(r0[i*int(mbss.n) : (i+1)*int(mbss.n)])
				if err != nil {
					return nil
				}
				sigma2 = append(sigma2, r1_bytes...)
				sigma2 = append(sigma2, c[constants.HASH_BYTES*(2*i)])
			}
			i++
			if i >= int(mbss.r) {
				break
			}
		}
	}

	sig := append(C[:], append(sigma0[:], append(sigma1_bytes, sigma2...)...)...)
	return sig
}

func (mbss *MBSS) Verify(message Message, sig Signature, pk PublicKey) bool {

	return true
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

func com0(r0, t0, e0 []math.Gf31) []byte {
	m, err := json.Marshal(append(r0, append(t0, e0...)...))
	if err != nil {
		return nil
	}
	digest := sha3.Sum256(m)
	return digest[:]
}

func com1(r1, gx []math.Gf31) []byte {
	m, err := json.Marshal(append(r1, gx...))
	if err != nil {
		return nil
	}
	digest := sha3.Sum256(m)
	return digest[:]
}

func h(data []byte) [constants.HASH_BYTES]byte {
	return sha3.Sum256(data)
}

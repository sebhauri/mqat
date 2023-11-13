package crypto

import (
	"crypto/rand"

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
	sk_sf := make([]byte, 2*constants.LAMBDA/8)
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
	sk_gf31 := math.Gf31_nrand(mbss.n, kp.S.sk)
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

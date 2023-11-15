package math

import (
	"golang.org/x/crypto/sha3"
	constants "sebastienhauri.ch/mqt/const"
)

type Gf31 uint16
type Gf31s int16

func Mod31(x Gf31) Gf31 {
	var t Gf31

	t = x & constants.Q
	x >>= 5
	t += x & constants.Q
	x >>= 5
	t += x & constants.Q
	x >>= 5
	t += x & constants.Q
	x >>= 5
	t = (t >> 5) + (t & constants.Q)
	t = (t >> 5) + (t & constants.Q)
	if t != constants.Q {
		return t
	}
	return 0
}

func Gf31_nrand(n uint, seed []byte) []Gf31 {
	out := make([]Gf31, n)
	shake128 := sha3.NewShake128()
	shakeBlock := make([]byte, shake128.BlockSize())
	shake128.Write(seed)
	var i uint
	for i = 0; i < n; {
		_, err := shake128.Read(shakeBlock)
		if err != nil {
			return nil
		}
		for _, v := range shakeBlock {
			if (v & constants.Q) != constants.Q {
				out[i] = Gf31(v & constants.Q)
				i++
				if i >= n {
					break
				}
			}
		}
	}
	return out
}

func Gf31_nrand_signed(n uint, seed []byte) []Gf31s {
	out := make([]Gf31s, n)
	shake128 := sha3.NewShake128()
	shakeBlock := make([]byte, shake128.BlockSize()/8)
	shake128.Write(seed)
	var i uint
	for i = 0; i < n; {
		_, err := shake128.Read(shakeBlock)
		if err != nil {
			return nil
		}
		for _, v := range shakeBlock {
			if (v & constants.Q) != constants.Q {
				out[i] = Gf31s((v & constants.Q)) - 15
				i++
				if i >= n {
					break
				}
			}
		}
	}
	return out
}

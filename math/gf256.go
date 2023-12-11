package math

import (
	"bytes"

	"golang.org/x/crypto/sha3"
)

type Gf256 uint8

// type Gf256s int8

func IsNonZero(a Gf256) bool {
	a8 := a
	r := 0 - a8
	r >>= 8
	return (r & 1) == 1
}

func Mul(a, b Gf256) Gf256 {
	r := a * (b & 1)

	a = (a << 1) ^ ((a >> 7) * 0x1b)
	r ^= a * ((b >> 1) & 1)
	a = (a << 1) ^ ((a >> 7) * 0x1b)
	r ^= a * ((b >> 2) & 1)
	a = (a << 1) ^ ((a >> 7) * 0x1b)
	r ^= a * ((b >> 3) & 1)
	a = (a << 1) ^ ((a >> 7) * 0x1b)
	r ^= a * ((b >> 4) & 1)
	a = (a << 1) ^ ((a >> 7) * 0x1b)
	r ^= a * ((b >> 5) & 1)
	a = (a << 1) ^ ((a >> 7) * 0x1b)
	r ^= a * ((b >> 6) & 1)
	a = (a << 1) ^ ((a >> 7) * 0x1b)
	r ^= a * ((b >> 7) & 1)
	return r
}

func Square(a Gf256) Gf256 {
	r8 := a & 1
	r8 ^= (a << 1) & 4
	r8 ^= (a << 2) & (1 << 4)
	r8 ^= (a << 3) & (1 << 6)

	r8 ^= ((a >> 4) & 1) * 0x1b
	r8 ^= ((a >> 5) & 1) * (0x1b << 2)
	r8 ^= ((a >> 6) & 1) * (0xab)
	r8 ^= ((a >> 7) & 1) * (0x9a)

	return r8
}

func Inv(a Gf256) Gf256 {
	a2 := Square(a)
	a4 := Square(a2)
	a8 := Square(a4)
	a4_2 := Mul(a4, a2)
	a8_4_2 := Mul(a4_2, a8)
	a64_ := Square(a8_4_2)
	a64_ = Square(a64_)
	a64_ = Square(a64_)
	a64_2 := Mul(a64_, a8_4_2)
	a128_ := Square(a64_2)
	return Mul(a2, a128_)
}

func Nrand(n int, seed []byte) []Gf256 {
	if n <= 0 {
		return nil
	}
	out := make([]Gf256, n)
	shake128 := sha3.NewShake128()
	shakeBlock := make([]uint8, shake128.BlockSize())
	shake128.Write(bytes.Clone(seed))
	for i := 0; i < n; {
		_, err := shake128.Read(shakeBlock)
		if err != nil {
			return nil
		}
		for _, v := range shakeBlock {
			out[i] = Gf256(v)
			i++
			if i >= n {
				break
			}

		}
	}
	return out
}

// func NrandSigned(n int, seed []byte) []Gf256s {
// 	if n <= 0 {
// 		return nil
// 	}
// 	out := make([]Gf256s, n)
// 	shake128 := sha3.NewShake128()
// 	shakeBlock := make([]uint8, shake128.BlockSize()/8)
// 	shake128.Write(bytes.Clone(seed))
// 	for i := 0; i < n; {
// 		_, err := shake128.Read(shakeBlock)
// 		if err != nil {
// 			return nil
// 		}
// 		for _, v := range shakeBlock {
// 			out[i] = Gf256s(v)
// 			i++
// 			if i >= n {
// 				break
// 			}
// 		}
// 	}
// 	return out
// }

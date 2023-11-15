package main

import (
	"fmt"
	"time"

	"sebastienhauri.ch/mqt/crypto"
)

const MEASURE_ROUNDS = 200
const M = 64
const N = 64

func main() {
	fmt.Printf("Initialising an MBSS with m=%d and n=%d ..\n", M, N)
	mbss := crypto.NewMBSS(M, N)
	fmt.Printf("The number of measure rounds is set to %d.\n\n", MEASURE_ROUNDS)

	var kp *crypto.KeyPair
	println("Benchmarking key generation..")
	start := time.Now()
	for i := 0; i < MEASURE_ROUNDS; i++ {
		kp = mbss.KeyPair()
		if kp == nil {
			println("\t New key pair is nil at iteration", i)
		}
	}
	end := time.Since(start)
	fmt.Printf("\t Time elapsed: %dms\n", end.Milliseconds())
	fmt.Printf("\t Mean time per key generation: %.3fms\n", float64(end.Milliseconds())/200)

	println("Benchmarking signature..")
	start = time.Now()
	for i := 0; i < MEASURE_ROUNDS; i++ {
		sig := mbss.Sign("Hey, this is my message to sign...", kp.S)
		if sig == nil {
			println("\t Signature is nil at iteration", i)
		}
	}
	end = time.Since(start)
	fmt.Printf("\t Time elapsed: %.3fs\n", end.Seconds())
	fmt.Printf("\t Mean time per signature %.3fms\n", float64(end.Milliseconds())/200)
}

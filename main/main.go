package main

import (
	"fmt"
	"time"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/crypto"
)

func main() {
	fmt.Printf("Initialising an MBSS with m=%d and n=%d ..\n", constants.M, constants.N)
	mbss := crypto.NewMBSS(constants.M, constants.N)
	fmt.Printf("The number of measure rounds is set to %d.\n\n", constants.MEASURE_ROUNDS)

	var kp *crypto.KeyPair
	println("Benchmarking key generation..")
	start := time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		kp = mbss.KeyPair()
		if kp == nil {
			println("\t New key pair is nil at iteration", i)
		}
	}
	end := time.Since(start)
	fmt.Printf("\t Time elapsed: %d milliseconds.\n", end.Milliseconds())
	fmt.Printf("\t Mean time per key generation: %.3f milliseconds.\n\n", float64(end.Milliseconds())/200)

	println("Benchmarking signature..")
	sig := make([]byte, 2*constants.HASH_BYTES+int(mbss.R)*(constants.M+2*constants.N*constants.HASH_BYTES))
	start = time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		sig = mbss.Sign([]byte("Hey, this is my message to sign..."), kp.S)
		if sig == nil {
			println("\t Signature is nil at iteration", i)
		}
	}
	end = time.Since(start)
	fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	fmt.Printf("\t Mean time per signature %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	println("Benchmarking verification..")
	start = time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		bool := mbss.Verify([]byte("Hey, this is my message to sign..."), sig, kp.P)
		if !bool {
			println("\t Verification failed at iteration", i)
		}
	}
	end = time.Since(start)
	fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	fmt.Printf("\t Mean time per verification %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	println("Signature size:", len(sig), "bytes.")
}

package main

import (
	"fmt"
	"time"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/crypto"
)

func main() {
	fmt.Printf("Initialising an MBSS with m=%d and n=%d ..\n", constants.M, constants.N)
	mqdss := crypto.NewMQDSS(constants.M, constants.N, constants.MQDSS_ROUNDS)
	fmt.Printf("The number of measure rounds is set to %d.\n\n", constants.MEASURE_ROUNDS)

	var mqdss_sk *crypto.MQDSSSecretKey
	var mqdss_pk *crypto.MQDSSPublicKey
	println("Benchmarking key generation..")
	start := time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		mqdss_sk, mqdss_pk = mqdss.KeyPair()
		if mqdss_sk == nil || mqdss_pk == nil {
			println("\t New key pair is nil at iteration", i)
		}
	}
	end := time.Since(start)
	fmt.Printf("\t Time elapsed: %d milliseconds.\n", end.Milliseconds())
	fmt.Printf("\t Mean time per key generation: %.3f milliseconds.\n\n", float64(end.Milliseconds())/200)

	println("Benchmarking signature..")
	sig := make([]byte, 2*constants.HASH_BYTES+int(mqdss.R)*(constants.M+2*constants.N*constants.HASH_BYTES))
	start = time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		sig = mqdss.Sign([]byte("Hey, this is my message to sign..."), mqdss_sk)
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
		bool := mqdss.Verify([]byte("Hey, this is my message to sign..."), sig, mqdss_pk)
		if !bool {
			println("\t Verification failed at iteration", i)
		}
	}
	end = time.Since(start)
	fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	fmt.Printf("\t Mean time per verification %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	println("Signature size:", len(sig), "bytes.")
}

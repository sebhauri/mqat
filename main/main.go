package main

import (
	"fmt"
	"time"

	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/crypto"
)

func main() {
	fmt.Printf("The number of measure rounds is set to %d.\n\n", constants.MEASURE_ROUNDS)

	println("===== MQAT =====")
	mqat := crypto.NewMQAT(
		constants.N, constants.M,
		constants.SALT_LEN,
		constants.UOV_PK_SEED_LEN, constants.UOV_SK_SEED_LEN,
		constants.RANDOM_SYS_SEED_LEN,
		constants.MQDSS_ROUNDS, constants.MQDSS_PK_SEED_LEN, constants.MQDSS_SK_SEED_LEN,
	)
	fmt.Printf("Initialising an MQAT with m=%d, n=%d ..\n", mqat.M, mqat.N)
	var mqat_sk *crypto.MQATSecretKey
	var mqat_pk *crypto.MQATPublicKey
	println("Benchmarking key generation..")
	start := time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		mqat_sk, mqat_pk = mqat.KeyGen()
		if mqat_sk == nil || mqat_pk == nil {
			println("\t New key pair is nil at iteration", i)
		}
	}
	end := time.Since(start)
	fmt.Printf("\t Time elapsed: %d milliseconds.\n", end.Milliseconds())
	fmt.Printf("\t Mean time per key generation: %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	var token *crypto.MQATToken
	var t, salt []byte
	var z_star, query, resp []uint8
	println("Benchmarking interactive issuance..")
	start = time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		t, salt, z_star, query = mqat.User0(mqat_pk)
		if query == nil {
			println("\t Query is nil at iteration", i)
			continue
		}
		resp = mqat.Sign0(mqat_sk, query)
		if resp == nil {
			println("\t Response is nil at iteration", i)
			continue
		}
		token = mqat.User1(mqat_pk, t, salt, z_star, resp)
		if token == nil {
			println("\t Token is nil at iteration", i)
		}
	}
	end = time.Since(start)
	fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	fmt.Printf("\t Mean time per signature %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	println("Benchmarking verification..")
	start = time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		bool := mqat.Verify(mqat_sk, token)
		if !bool {
			println("\t Verification failed at iteration", i)
		}
	}
	end = time.Since(start)
	fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	fmt.Printf("\t Mean time per verification %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	println("===== MQAT =====")

	// println()

	// println("===== UOV =====")
	// uov := crypto.NewUOV(constants.M, constants.N, constants.UOV_PK_SEED_LEN, constants.UOV_SK_SEED_LEN)
	// fmt.Printf("Initialising an UOV with m=%d and n=%d ..\n", uov.M, uov.N)
	// var uov_sk *crypto.UOVSecretKey
	// var uov_pk *crypto.UOVPublicKey
	// println("Benchmarking key generation..")
	// start := time.Now()
	// for i := 0; i < constants.MEASURE_ROUNDS; i++ {
	// 	uov_sk, uov_pk = uov.KeyGen()
	// 	if uov_pk == nil || uov_sk == nil {
	// 		println("\t New key pair is nil at iteration", i)
	// 	}
	// }
	// end := time.Since(start)
	// fmt.Printf("\t Time elapsed: %d milliseconds.\n", end.Milliseconds())
	// fmt.Printf("\t Mean time per key generation: %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	// println("Benchmarking signature..")
	// var sig []uint8
	// message := crypto.Nrand128(constants.M, []byte{0})
	// start = time.Now()
	// for i := 0; i < constants.MEASURE_ROUNDS; i++ {
	// 	sig = uov.Sign(message, uov_sk)
	// 	if sig == nil {
	// 		println("\t Signature is nil at iteration", i)
	// 	}
	// }
	// end = time.Since(start)
	// fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	// fmt.Printf("\t Mean time per signature %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	// println("Benchmarking verification..")
	// start = time.Now()
	// for i := 0; i < constants.MEASURE_ROUNDS; i++ {
	// 	bool := uov.Verify(message, sig, uov_pk)
	// 	if !bool {
	// 		println("\t Verification failed at iteration", i)
	// 	}
	// }
	// end = time.Since(start)
	// fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	// fmt.Printf("\t Mean time per verification %.3f milliseconds.\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)
	// println("===== UOV =====")

	// println()

	// println("===== MQDSS =====")
	// mqdss := crypto.NewMQDSS(uov.M, uov.N+uov.M, constants.MQDSS_ROUNDS, constants.MQDSS_PK_SEED_LEN, constants.MQDSS_SK_SEED_LEN)
	// fmt.Printf("Initialising an MQDSS with m=%d, n=%d, r=%d ..\n", mqdss.M, mqdss.N, mqdss.R)
	// var mqdss_sk *crypto.MQDSSSecretKey
	// var mqdss_pk *crypto.MQDSSPublicKey
	// println("Benchmarking key generation..")
	// start = time.Now()
	// for i := 0; i < constants.MEASURE_ROUNDS; i++ {
	// 	mqdss_sk, mqdss_pk = mqdss.KeyGen()
	// 	if mqdss_sk == nil || mqdss_pk == nil {
	// 		println("\t New key pair is nil at iteration", i)
	// 	}
	// }
	// end = time.Since(start)
	// fmt.Printf("\t Time elapsed: %d milliseconds.\n", end.Milliseconds())
	// fmt.Printf("\t Mean time per key generation: %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	// println("Benchmarking signature..")
	// sig = make([]byte, 2*constants.HASH_BYTES+int(mqdss.R)*(constants.M+2*constants.N*constants.HASH_BYTES))
	// start = time.Now()
	// for i := 0; i < constants.MEASURE_ROUNDS; i++ {
	// 	sig = mqdss.Sign([]byte("Hey, this is my message to sign..."), mqdss_sk)
	// 	if sig == nil {
	// 		println("\t Signature is nil at iteration", i)
	// 	}
	// }
	// end = time.Since(start)
	// fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	// fmt.Printf("\t Mean time per signature %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	// println("Benchmarking verification..")
	// start = time.Now()
	// for i := 0; i < constants.MEASURE_ROUNDS; i++ {
	// 	bool := mqdss.Verify([]byte("Hey, this is my message to sign..."), sig, mqdss_pk)
	// 	if !bool {
	// 		println("\t Verification failed at iteration", i)
	// 	}
	// }
	// end = time.Since(start)
	// fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	// fmt.Printf("\t Mean time per verification %.3f milliseconds.\n\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	// println("Signature size:", len(sig), "bytes.")
	// println("===== MQDSS =====")
}

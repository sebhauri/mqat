package main

import (
	"fmt"
	"time"

	constants "mqat/const"
	"mqat/crypto"
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
	var t []byte
	var z_star, query, resp []uint8
	println("Benchmarking interactive issuance..")

	var user0_time time.Duration = 0
	var issuer_time time.Duration = 0
	var user1_time time.Duration = 0
	start = time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		// User0
		start_user0 := time.Now()
		t, z_star, query = mqat.User0(mqat_pk)
		end_user0 := time.Since(start_user0)
		user0_time += end_user0
		if query == nil {
			println("\t Query is nil at iteration", i)
			continue
		}

		// Sign0
		start_issuer := time.Now()
		resp = mqat.Sign0(mqat_sk, query)
		end_issuer := time.Since(start_issuer)
		issuer_time += end_issuer
		if resp == nil {
			println("\t Response is nil at iteration", i)
			continue
		}

		// User1
		start_user1 := time.Now()
		token = mqat.User1(mqat_pk, t, z_star, resp)
		end_user1 := time.Since(start_user1)
		user1_time += end_user1
		if token == nil {
			println("\t Token is nil at iteration", i)
		}
	}
	end = time.Since(start)
	user_time := user0_time + user1_time
	fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	fmt.Printf("\t Mean time per issuance %.3f milliseconds.\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)
	fmt.Printf("\t\t Total time User: %.3f seconds.\n", user_time.Seconds())
	fmt.Printf("\t\t Mean time User: %.3f milliseconds.\n", float64(user_time.Milliseconds())/constants.MEASURE_ROUNDS)
	fmt.Printf("\t\t Total time Issuer: %.3f seconds.\n", issuer_time.Seconds())
	fmt.Printf("\t\t Mean time per Issuer %.3f milliseconds.\n\n", float64(issuer_time.Milliseconds())/constants.MEASURE_ROUNDS)

	println("Benchmarking verification..")
	start = time.Now()
	for i := 0; i < constants.MEASURE_ROUNDS; i++ {
		bool := mqat.Verify(mqat_pk, token)
		if !bool {
			println("\t Verification failed at iteration", i)
		}
	}
	end = time.Since(start)
	fmt.Printf("\t Time elapsed: %.3f seconds.\n", end.Seconds())
	fmt.Printf("\t Mean time per verification: %.3f milliseconds.\n", float64(end.Milliseconds())/constants.MEASURE_ROUNDS)

	println("===== MQAT =====")
}

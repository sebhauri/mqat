package constants

// General
const LAMBDA = 128
const MEASURE_ROUNDS = 100
const Q = 256
const M = 44
const N = 112
const RANDOM_SYS_SEED_LEN = LAMBDA
const SALT_LEN = LAMBDA
const HASH_BYTES = 32

// UOV
const UOV_PK_SEED_LEN = 128
const UOV_SK_SEED_LEN = 256

// MQDSS
const MQDSS_PK_SEED_LEN = 128
const MQDSS_SK_SEED_LEN = 256
const MQDSS_ROUNDS = 156
const FLEN = M * (N * (N + 1) / 2)

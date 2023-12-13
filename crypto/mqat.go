package crypto

import (
	"crypto/rand"

	"github.com/sirupsen/logrus"
	constants "sebastienhauri.ch/mqt/const"
	"sebastienhauri.ch/mqt/math"
)

func NewMQAT(
	n, m int,
	salt_len int,
	uov_pk_seed_len int,
	uov_sk_seed_len int,
	random_sys_seed_len int,
	mqdss_rounds int,
) *MQAT {
	if m <= 0 || n <= 0 || m > n || salt_len <= 0 ||
		uov_pk_seed_len <= 0 || uov_sk_seed_len <= 0 ||
		mqdss_rounds <= 0 {
		return nil
	}
	mqat := new(MQAT)
	mqat.m = m
	mqat.n = n
	mqat.salt_len = salt_len
	mqat.random_sys_seed_len = random_sys_seed_len
	mqat.uov = NewUOV(m, n, uov_pk_seed_len, uov_sk_seed_len)
	mqat.mqdss = NewMQDSS(m, m+n, mqdss_rounds)
	return mqat
}

func (mqat *MQAT) KeyGen() (*MQATSecretKey, *MQATPublicKey) {
	sk := new(MQATSecretKey)
	pk := new(MQATPublicKey)

	uov_sk, uov_pk := mqat.uov.KeyGen(mqat.m, mqat.n)
	if uov_sk == nil || uov_pk == nil {
		logrus.Error("Could not generate UOV public key")
		return nil, nil
	}

	random_sys_seed := make([]byte, mqat.random_sys_seed_len/8)
	_, err := rand.Read(random_sys_seed)
	if err != nil {
		logrus.Error("Could not sample random system seed")
		return nil, nil
	}

	sk.uov_sk = uov_sk
	sk.seed_random_sys = random_sys_seed
	pk.seed_random_sys = random_sys_seed
	pk.uov_pk = uov_pk

	return sk, pk
}

func (mqat *MQAT) User0(pk *MQATPublicKey) ([]byte, []byte, []uint8, []uint8) {
	salt := make([]byte, mqat.salt_len/8)
	_, err := rand.Read(salt)
	if err != nil {
		logrus.Error("Could not sample salt")
		return nil, nil, nil, nil
	}
	t := make([]byte, constants.LAMBDA/8)
	w_seed := append(t, salt...)
	w := Nrand256(mqat.m, w_seed)

	z_star_seed := make([]byte, 2*constants.LAMBDA)
	_, err = rand.Read(salt)
	if err != nil {
		logrus.Error("Could not sample z* randomness")
		return nil, nil, nil, nil
	}
	z_star := Nrand256(mqat.m, z_star_seed)
	if z_star == nil {
		logrus.Error("Could not sample z*")
	}
	R := Nrand128(math.Flen(mqat.m, mqat.m), pk.seed_random_sys)
	w_star := math.MQ(R, z_star, mqat.m)

	w_tilde := make([]uint8, mqat.m)
	for i := 0; i < len(w_tilde); i++ {
		w_tilde[i] = w[i] ^ w_star[i]
	}

	return t, salt, z_star, w_tilde
}

func (mqat *MQAT) Sign0(sk *MQATSecretKey, query []byte) []uint8 {
	return mqat.uov.Sign(query, sk.uov_sk)
}

func (mqat *MQAT) User1(
	t []byte,
	salt []byte,
	z_star []uint8,
	resp []uint8,
) *MQATToken {
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

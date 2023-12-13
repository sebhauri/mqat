package crypto

import (
	"crypto/rand"

	"github.com/sirupsen/logrus"
	constants "sebastienhauri.ch/mqt/const"
)

func NewMQAT(
	n, m int,
	salt_len int,
	uov_pk_seed_len int,
	uov_sk_seed_len int,
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
	mqat.uov = NewUOV(m, n, uov_pk_seed_len, uov_sk_seed_len)
	mqat.mqdss = NewMQDSS(m, m+n, mqdss_rounds)
	return mqat
}

func (mqat *MQAT) KeyGen() (*MQATSecretKey, *MQATPublicKey) {
	sk := new(MQATSecretKey)
	pk := new(MQATPublicKey)

	uov_csk, uov_cpk := mqat.uov.KeyGen(mqat.m, mqat.n)
	if uov_csk == nil || uov_cpk == nil {
		logrus.Error("Could not generate UOV public key")
		return nil, nil
	}

	random_sys_seed := make([]byte, constants.RANDOM_SYS_SEED_LEN/8)
	_, err := rand.Read(random_sys_seed)
	if err != nil {
		logrus.Error("Could not sample random system seed")
		return nil, nil
	}

	sk.uov_csk = uov_csk
	sk.seedR = random_sys_seed
	pk.seedR = random_sys_seed
	pk.uov_cpk = uov_cpk

	return sk, pk
}

func (mqat *MQAT) User0(pk *MQATPublicKey) []uint8 {
	salt := make([]byte, mqat.salt_len)
	_, err := rand.Read(salt)
	if err != nil {
		logrus.Error("Could not sample salt")
		return nil
	}
	t := make([]byte, constants.LAMBDA/8)
	seed := append(t, salt...)
	w := Nrand256(mqat.m, seed)

	_, err = rand.Read(salt)
	if err != nil {
		logrus.Error("Could not sample salt")
		return nil
	}
	z_star := Nrand256(mqat.m, salt)
	if z_star == nil {
		logrus.Error("Could not sample z*")
	}

	return w
}

func (mqat *MQAT) Sign0(sk *MQATSecretKey, query []byte) []uint8 {
	return nil
}

func (mqat *MQAT) User1(resp []uint8) *MQATToken {
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

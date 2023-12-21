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
	mqdss_sk_seed_len int,
	mqdss_pk_seed_len int,
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
	mqat.mqdss = NewMQDSS(m, m+n, mqdss_rounds, mqdss_pk_seed_len, mqdss_sk_seed_len)
	return mqat
}

func (mqat *MQAT) KeyGen() (*MQATSecretKey, *MQATPublicKey) {
	sk := new(MQATSecretKey)
	pk := new(MQATPublicKey)

	uov_sk, uov_pk := mqat.uov.KeyGen()
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
	w_star := math.MQR(R, z_star, mqat.m)

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
	pk *MQATPublicKey,
	t []byte,
	salt []byte,
	z_star []uint8,
	resp []uint8,
) *MQATToken {
	w_seed := append(t, salt...)
	w := Nrand256(mqat.m, w_seed)

	P1i := pk.uov_pk.P1i
	P2i := pk.uov_pk.P2i
	P3i := pk.uov_pk.P3i
	R := Nrand128(math.Flen(mqat.m, mqat.m), pk.seed_random_sys)
	x := append(resp, z_star...)
	if len(x) != mqat.n+mqat.n {
		return nil
	}

	w_prime := math.MQ(P1i, P2i, P3i, R, x, mqat.m, mqat.n)
	for i := 0; i < mqat.m; i++ {
		if w[i] != w_prime[i] {
			return nil
		}
	}

	mqdss_sk, _ := mqat.mqdss.KeyPair(P1i, P2i, P3i, R, x, w_prime)
	sig := mqat.mqdss.Sign(w, mqdss_sk)

	mqat_token := new(MQATToken)
	mqat_token.token = t
	mqat_token.salt = salt
	mqat_token.mqdss_signature = sig

	return mqat_token
}

func (mqat *MQAT) Verify(sk *MQATSecretKey, token *MQATToken) bool {
	w_seed := append(token.token, token.salt...)
	w := Nrand256(mqat.m, w_seed)
	R := Nrand128(math.Flen(mqat.m, mqat.m), sk.seed_random_sys)
	_, mqdss_pk := mqat.mqdss.KeyPair(sk.uov_sk.Pk.P1i, sk.uov_sk.Pk.P2i, sk.uov_sk.Pk.P3i, R, nil, w)
	return mqat.mqdss.Verify(w, token.mqdss_signature, mqdss_pk)
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

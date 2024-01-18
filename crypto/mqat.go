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
	mqat.M = m
	mqat.N = n
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
	_, err = rand.Read(t)
	if err != nil {
		logrus.Error("Could not sample t")
		return nil, nil, nil, nil
	}

	w_seed := append(t, salt...)
	w := Nrand256(mqat.M, w_seed)

	z_star_seed := make([]byte, 2*constants.LAMBDA/8)
	_, err = rand.Read(z_star_seed)
	if err != nil {
		logrus.Error("Could not sample z* randomness")
		return nil, nil, nil, nil
	}
	z_star := Nrand256(mqat.M, z_star_seed)
	if z_star == nil {
		logrus.Error("Could not sample z*")
	}
	R := Nrand128(math.Flen(mqat.M, mqat.M), pk.seed_random_sys)
	w_star := math.MQR(R, z_star, mqat.M)

	w_tilde := make([]uint8, mqat.M)
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
	w := Nrand256(mqat.M, w_seed)

	P1i := pk.uov_pk.P1i
	P2i := pk.uov_pk.P2i
	P3i := pk.uov_pk.P3i
	R := Nrand128(math.Flen(mqat.M, mqat.M), pk.seed_random_sys)
	x := append(resp, z_star...)
	if len(x) != mqat.N+mqat.M {
		return nil
	}

	w_prime := math.MQ(P1i, P2i, P3i, R, x, mqat.M, mqat.N)
	for i := 0; i < mqat.M; i++ {
		if w[i] != w_prime[i] {
			return nil
		}
	}

	mqdss_sk, _ := mqat.mqdss.KeyPair(P1i, P2i, P3i, R, x, w_prime)
	sig := mqat.mqdss.Sign(w, mqdss_sk)

	mqat_token := new(MQATToken)
	mqat_token.Token = t
	mqat_token.Salt = salt
	mqat_token.MQDSSSignature = sig

	return mqat_token
}

func (mqat *MQAT) Verify(pk *MQATPublicKey, token *MQATToken) bool {
	w_seed := append(token.Token, token.Salt...)
	w := Nrand256(mqat.M, w_seed)
	R := Nrand128(math.Flen(mqat.M, mqat.M), pk.seed_random_sys)
	_, mqdss_pk := mqat.mqdss.KeyPair(pk.uov_pk.P1i, pk.uov_pk.P2i, pk.uov_pk.P3i, R, nil, w)
	return mqat.mqdss.Verify(w, token.MQDSSSignature, mqdss_pk)
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

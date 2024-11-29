package keyutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"gitee.com/cryptolab/crypto_cn/sm2"
	"gitee.com/cryptolab/crypto_cn/sm3"
)

func verifyKeyPair(priv, pub interface{}) error {
	s, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("type %T is not a crypto.Signer", priv)
	}

	sum := sm3.New().Sum([]byte("a message"))
	sig, err := s.Sign(rand.Reader, sum, nil)
	if err != nil {
		return fmt.Errorf("%T.Sign() error = %w", s, err)
	}

	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(p, sum, sig) {
			return fmt.Errorf("ecdsa.VerifyASN1 failed")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(p, sum, sig) {
			return fmt.Errorf("ed25519.Verify failed")
		}
	case *sm2.PublicKey:
		if !p.Verify(sum, sig) {
			return fmt.Errorf("sm2.Verify failed")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}

	return nil
}
func verifyPrivateKey(priv interface{}) error {
	s, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("type %T is not a crypto.Signer", priv)
	}

	return verifyKeyPair(priv, s.Public())
}

func TestGenerateDefaultSigner(t *testing.T) {
	got, err := GenerateDefaultSigner()
	if err != nil {
		t.Errorf("GenerateDefaultSigner() error = %v, wantErr %v", err, false)
		return
	}
	if err := verifyPrivateKey(got); err != nil {
		t.Errorf("GenerateDefaultSigner() error = %v", err)
	}
}

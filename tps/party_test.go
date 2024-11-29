package tps

import (
	"crypto/rand"
	"testing"

	"gitee.com/cryptolab/crypto_cn/sm2"
)

func TestParty(t *testing.T) {

	msg := []byte("hello world")

	keyOne, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keyTwo, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	partyOne := NewPartyOne(keyOne, msg)

	partyTwo := NewPartyTwo(keyTwo)

	partyOne.InitParty(&keyTwo.PublicKey)
	partyTwo.InitParty(&keyOne.PublicKey)

	oneRound1Msg, err := partyOne.SignRound1()
	if err != nil {
		t.Fatal(err)
	}
	oneRound2Msg, err := partyTwo.SignRound1(oneRound1Msg)
	if err != nil {
		t.Fatal(err)
	}
	oneRound3Msg, err := partyOne.SignRound2(oneRound2Msg)
	if err != nil {
		t.Fatal(err)
	}
	oneRound4Msg, err := partyTwo.SignRound2(oneRound3Msg)
	if err != nil {
		t.Fatal(err)
	}
	signBytes, err := partyOne.SignFinish(oneRound4Msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := partyTwo.Verify(msg, signBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verify failed")
	}

	t.Log("party sign/verify ok")
}

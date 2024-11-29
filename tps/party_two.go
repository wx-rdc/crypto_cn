package tps

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/wx-rdc/crypto_cn/sm2"
)

type PartyTwo interface {
	InitParty(opk *sm2.PublicKey) (err error)
	SignRound1(roundMsg *OneRound1) (ret *TwoRound1, err error)
	SignRound2(roundMsg *OneRound2) (ret *TwoRound2, err error)
	Verify(msg, signBytes []byte) (ok bool, err error)
}

type partyTwo struct {
	params *Parameters
}

func NewPartyTwo(priv *sm2.PrivateKey) PartyTwo {
	params := &Parameters{
		ec:     priv.Curve,
		D:      priv.D,
		dInver: new(big.Int).ModInverse(priv.D, priv.Curve.Params().N),
		N:      priv.Curve.Params().N,
		pk:     &priv.PublicKey,
		Ra:     &point{},
		RaQuo:  &point{},
		Rb:     &point{},
		RbQuo:  &point{},
	}
	return &partyTwo{
		params: params,
	}
}

func (o *partyTwo) InitParty(opk *sm2.PublicKey) (err error) {
	params := o.params
	oneNeg := new(big.Int).Sub(params.N, one)
	GxNeg, GyNeg := params.ec.ScalarBaseMult(oneNeg.Bytes())

	// calculate public key
	pkx, pky := params.ec.ScalarMult(opk.X, opk.Y, params.D.Bytes())
	pkx, pky = params.ec.Add(pkx, pky, GxNeg, GyNeg)

	params.cpk = &sm2.PublicKey{
		Curve: params.ec,
		X:     pkx,
		Y:     pky,
	}

	return nil
}

func (o *partyTwo) SignRound1(roundMsg *OneRound1) (ret *TwoRound1, err error) {
	params := o.params
	// verify Ra, RaQuo
	raxC, rayC := params.ec.ScalarMult(roundMsg.RaQuo.x, roundMsg.RaQuo.y, params.dInver.Bytes())
	if raxC.Cmp(roundMsg.Ra.x) != 0 ||
		rayC.Cmp(roundMsg.Ra.y) != 0 {
		err = errors.New("ra check failed")
		return
	}

	// generate Rb, RbQuo
	kb, _ := randFieldElement(params.ec, rand.Reader)
	params.Rb.x, params.Rb.y = params.ec.ScalarMult(roundMsg.X, roundMsg.Y, kb.Bytes())
	params.RbQuo.x, params.RbQuo.y = params.ec.ScalarBaseMult(kb.Bytes())
	params.kb = kb

	ret = &TwoRound1{
		Rb:    params.Rb,
		RbQuo: params.RbQuo,
	}

	return
}

func (o *partyTwo) SignRound2(roundMsg *OneRound2) (ret *TwoRound2, err error) {
	params := o.params

	// generate t
	t := new(big.Int).Add(params.kb, roundMsg.sQuo)
	t.Mul(t, params.dInver)
	t.Mod(t, params.N)

	params.t = t

	ret = &TwoRound2{
		t: params.t,
	}

	return
}

func (o *partyTwo) Verify(msg, signBytes []byte) (ok bool, err error) {
	return o.params.cpk.Verify(msg, signBytes), nil
}

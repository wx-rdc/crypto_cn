package tps

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/wx-rdc/crypto_cn/sm2"
)

var one = new(big.Int).SetInt64(1)
var default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

type PartyOne interface {
	InitParty(opk *sm2.PublicKey) (err error)
	SignRound1() (ret *OneRound1, err error)
	SignRound2(roundMsg *TwoRound1) (ret *OneRound2, err error)
	SignFinish(roundMsg *TwoRound2) (signBytes []byte, err error)
}

type sm2Signature struct {
	R, S *big.Int
}

type partyOne struct {
	params *Parameters
	msg    []byte
}

func NewPartyOne(priv *sm2.PrivateKey, msg []byte) PartyOne {
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
	return &partyOne{
		params: params,
		msg:    msg,
	}
}

func (o *partyOne) InitParty(opk *sm2.PublicKey) (err error) {
	params := o.params
	oneNeg := new(big.Int).Sub(params.N, one)
	GxNeg, GyNeg := params.ec.ScalarBaseMult(oneNeg.Bytes())

	// calculate public key
	pkx, pky := params.ec.ScalarMult(opk.X, opk.Y, params.D.Bytes())
	pkx, pky = params.ec.Add(pkx, pky, GxNeg, GyNeg)

	params.opk = opk
	params.cpk = &sm2.PublicKey{
		Curve: params.ec,
		X:     pkx,
		Y:     pky,
	}

	return nil
}

func (o *partyOne) SignRound1() (ret *OneRound1, err error) {
	params := o.params

	// generate Ra, RaQuo
	ka, _ := randFieldElement(params.ec, rand.Reader)
	params.Ra.x, params.Ra.y = params.ec.ScalarBaseMult(ka.Bytes())
	params.RaQuo.x, params.RaQuo.y = params.ec.ScalarMult(params.opk.X, params.opk.Y, ka.Bytes())
	params.ka = ka

	ret = &OneRound1{
		X:     params.pk.X,
		Y:     params.pk.Y,
		Ra:    params.Ra,
		RaQuo: params.RaQuo,
	}

	return
}

func (o *partyOne) SignRound2(roundMsg *TwoRound1) (ret *OneRound2, err error) {
	params := o.params

	// verify Rb, RbQuo
	rbxC, rbyC := params.ec.ScalarMult(roundMsg.RbQuo.x, roundMsg.RbQuo.y, params.D.Bytes())
	if rbxC.Cmp(roundMsg.Rb.x) != 0 ||
		rbyC.Cmp(roundMsg.Rb.y) != 0 {
		err = errors.New("rb check failed")
		return
	}

	// generate r, sQuo
	digest, err := params.cpk.Sm3Digest(o.msg, default_uid)
	if err != nil {
		return
	}
	e := new(big.Int).SetBytes(digest)

	rx, _ := params.ec.Add(params.Ra.x, params.Ra.y, roundMsg.Rb.x, roundMsg.Rb.y)
	r := new(big.Int).Add(rx, e)
	r.Mod(r, params.N)

	ss := new(big.Int).Add(params.ka, r)
	ss.Mul(ss, params.dInver)
	ss.Mod(ss, params.N)

	params.sQuo = ss
	params.R = r

	ret = &OneRound2{
		sQuo: params.sQuo,
	}

	return
}

func (o *partyOne) SignFinish(roundMsg *TwoRound2) (signBytes []byte, err error) {
	params := o.params
	r := params.R

	// generate s
	s := new(big.Int).Sub(roundMsg.t, params.R)
	s.Mod(s, params.N)

	params.S = s

	return asn1.Marshal(sm2Signature{r, s})
}

package tps

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/wx-rdc/crypto_cn/sm2"
)

type point struct {
	x, y *big.Int
}

type Parameters struct {
	ec        elliptic.Curve
	D, dInver *big.Int
	N         *big.Int
	pk        *sm2.PublicKey
	opk       *sm2.PublicKey // other party's public key
	cpk       *sm2.PublicKey // common public key
	ka, kb    *big.Int
	Ra, RaQuo *point
	Rb, RbQuo *point
	sQuo, t   *big.Int
	R, S      *big.Int
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

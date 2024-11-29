package tps

import "math/big"

type KeyExchange struct {
	X, Y *big.Int
}

type OneRound1 struct {
	X, Y      *big.Int
	Ra, RaQuo *point
}

type OneRound2 struct {
	sQuo *big.Int
}

type TwoRound1 struct {
	Rb, RbQuo *point
}

type TwoRound2 struct {
	t *big.Int
}

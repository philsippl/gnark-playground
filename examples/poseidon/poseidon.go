package poseidon

import (
	"github.com/consensys/gnark/frontend"
)

type Poseidon struct {
	nTotalRounds int
	nFullRounds  int
	data         []frontend.Variable
	api          frontend.API
}

func sbox(api frontend.API, v frontend.Variable) frontend.Variable {
	v2 := api.Mul(v, v)
	v4 := api.Mul(v2, v2)
	return api.Mul(v, v4)
}

func applyMDS(api frontend.API, state []frontend.Variable) []frontend.Variable {
	if len(state) != len(MDS) {
		panic("state and MDS size do not match")
	}

	var mds []frontend.Variable
	for i := 0; i < len(MDS); i += 1 {
		var sum frontend.Variable = 0
		for j := 0; j < len(MDS[i]); j += 1 {
			sum = api.Add(sum, api.Mul(state[j], MDS[i][j]))
		}
		mds = append(mds, sum)
	}
	return mds
}

func halfRound(api frontend.API, round int, state []frontend.Variable) []frontend.Variable {
	if len(state) != len(CONSTANTS[round]) {
		panic("state and round constants size do not match")
	}

	for i := 0; i < len(state); i += 1 {
		state[i] = api.Add(state[i], CONSTANTS[round][i])
	}

	state[0] = sbox(api, state[0])

	return applyMDS(api, state)
}

func fullRound(api frontend.API, round int, state []frontend.Variable) []frontend.Variable {
	if len(state) != len(CONSTANTS[round]) {
		panic("state and round constants size do not match")
	}

	for i := 0; i < len(state); i += 1 {
		state[i] = api.Add(state[i], CONSTANTS[round][i])
	}

	for i := 0; i < len(state); i += 1 {
		state[i] = sbox(api, state[i])
	}

	return applyMDS(api, state)
}

func NewPoseidon(api frontend.API) Poseidon {
	return Poseidon{
		nFullRounds:  4,
		nTotalRounds: 64,
		data:         []frontend.Variable{0},
		api:          api,
	}
}

func (h *Poseidon) Write(data ...frontend.Variable) {
	h.data = append(h.data, data...)
}

func (h *Poseidon) Reset() {
	h.data = []frontend.Variable{0}
}

func (h *Poseidon) Sum() frontend.Variable {
	state := h.data
	for i := 0; i < h.nTotalRounds+1; i += 1 {
		if i < h.nFullRounds || i > (h.nTotalRounds-h.nFullRounds) {
			state = fullRound(h.api, i, state)
		} else {
			state = halfRound(h.api, i, state)
		}
	}
	return state[0]
}

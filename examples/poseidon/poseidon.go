package poseidon

import "github.com/consensys/gnark/frontend"

func sbox(api frontend.API, v frontend.Variable) frontend.Variable {
	v2 := api.Mul(v, v)
	v4 := api.Mul(v2, v2)
	return api.Mul(v, v4)
}

func applyMDS(api frontend.API, state [3]frontend.Variable) [3]frontend.Variable {
	return [3]frontend.Variable{
		api.Add(api.Mul(state[0], MDS[0][0]), api.Mul(state[1], MDS[0][1]), api.Mul(state[2], MDS[0][2])),
		api.Add(api.Mul(state[0], MDS[1][0]), api.Mul(state[1], MDS[1][1]), api.Mul(state[2], MDS[1][2])),
		api.Add(api.Mul(state[0], MDS[2][0]), api.Mul(state[1], MDS[2][1]), api.Mul(state[2], MDS[2][2])),
	}
}

func halfRound(api frontend.API, round int, state [3]frontend.Variable) [3]frontend.Variable {
	// constant
	constant := CONSTANTS[round]
	state = [3]frontend.Variable{
		api.Add(state[0], constant[0]),
		api.Add(state[1], constant[1]),
		api.Add(state[2], constant[2]),
	}

	// sbox
	state = [3]frontend.Variable{
		sbox(api, state[0]),
		state[1],
		state[2],
	}

	// mds
	return applyMDS(api, state)
}

func fullRound(api frontend.API, round int, state [3]frontend.Variable) [3]frontend.Variable {
	// constant
	constant := CONSTANTS[round]
	state = [3]frontend.Variable{
		api.Add(state[0], constant[0]),
		api.Add(state[1], constant[1]),
		api.Add(state[2], constant[2]),
	}

	// sbox
	state = [3]frontend.Variable{
		sbox(api, state[0]),
		sbox(api, state[1]),
		sbox(api, state[2]),
	}

	// mds
	return applyMDS(api, state)
}

type PoseidonCircuit struct {
	Left  frontend.Variable `gnark:"left"`
	Right frontend.Variable `gnark:"right"`
	Out   frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *PoseidonCircuit) Define(api frontend.API) error {
	state := [3]frontend.Variable{
		0,
		circuit.Left,
		circuit.Right,
	}

	nTotalRounds := 64
	nFullRounds := 4

	for i := 0; i < nFullRounds; i += 1 {
		state = fullRound(api, i, state)
	}

	for i := 4; i < (nTotalRounds - nFullRounds + 1); i += 1 {
		state = halfRound(api, i, state)
	}

	for i := (nTotalRounds - nFullRounds + 1); i < nTotalRounds+1; i += 1 {
		state = fullRound(api, i, state)
	}

	api.AssertIsEqual(circuit.Out, state[0])
	return nil
}

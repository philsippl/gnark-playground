// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package poseidon

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestPoseidonCircuit1 struct {
	Input frontend.Variable `gnark:"input"`
	Hash  frontend.Variable `gnark:",public"`
}

type TestPoseidonCircuit2 struct {
	Left  frontend.Variable `gnark:"left"`
	Right frontend.Variable `gnark:"right"`
	Hash  frontend.Variable `gnark:",public"`
}

func (circuit *TestPoseidonCircuit1) Define(api frontend.API) error {
	poseidon := NewPoseidon1(api)
	poseidon.Write(circuit.Input)
	api.AssertIsEqual(circuit.Hash, poseidon.Sum())
	return nil
}

func (circuit *TestPoseidonCircuit2) Define(api frontend.API) error {
	poseidon := NewPoseidon2(api)
	poseidon.Write(circuit.Left, circuit.Right)
	api.AssertIsEqual(circuit.Hash, poseidon.Sum())
	return nil
}

func TestPoseidon(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit1 TestPoseidonCircuit1
	assert.ProverSucceeded(&circuit1, &TestPoseidonCircuit1{
		Input: 0,
		Hash:  hex("0x2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c"),
	}, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))

	var circuit2 TestPoseidonCircuit2

	assert.ProverSucceeded(&circuit2, &TestPoseidonCircuit2{
		Left:  0,
		Right: 0,
		Hash:  hex("0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"),
	}, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&circuit2, &TestPoseidonCircuit2{
		Left:  31213,
		Right: 132,
		Hash:  hex("0x303f59cd0831b5633bcda50514521b33776b5d4280eb5868ba1dbbe2e4d76ab5"),
	}, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

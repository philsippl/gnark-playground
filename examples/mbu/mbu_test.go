package mbu

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestMBU(t *testing.T) {
	assert := test.NewAssert(t)

	var mimcCircuit Circuit

	startIndex := 2
	idComms := [1]frontend.Variable{
		fromHex("0x0000000000000000000000000000000000000000000000000000000000000001"),
	}
	proofs := [1][2]frontend.Variable{
		{
			fromHex("0x0000000000000000000000000000000000000000000000000000000000000000"),
			fromHex("0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"),
		},
	}
	preRoot := fromHex("0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1")
	postRoot := fromHex("0x047fef74e928134b3ade72c2565c388d846ebc64dc0ee15d8ddcf10bb2f581d1")

	assert.ProverSucceeded(&mimcCircuit, &Circuit{
		// public
		StartIndex: startIndex,
		PreRoot:    preRoot,
		PostRoot:   postRoot,
		IdComms:    idComms,

		// private
		MerkleProofs: proofs,
	}, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))

}

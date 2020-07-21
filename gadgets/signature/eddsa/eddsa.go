/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package eddsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gnark/gadgets/hash/mimc"
)

// PublicKey stores an eddsa public key in a r1cs
type PublicKey struct {
	A     twistededwards.Point
	Curve twistededwards.EdCurve
}

// Signature stores a signature as a gadget
type Signature struct {
	R PublicKey
	S frontend.Variable
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(circuit *frontend.CS, sig Signature, msg frontend.Variable, pubKey PublicKey) error {

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []frontend.Variable{
		sig.R.A.X,
		sig.R.A.Y,
		pubKey.A.X,
		pubKey.A.Y,
		msg,
	}

	hash, err := mimc.NewMiMC("seed", pubKey.Curve.ID)
	if err != nil {
		return err
	}
	hramAllocated := hash.Hash(circuit, data...)

	// lhs = cofactor*SB
	cofactorAllocated := circuit.ALLOCATE(pubKey.Curve.Cofactor)
	lhs := twistededwards.NewPoint(circuit, nil, nil)

	lhs.ScalarMulFixedBase(circuit, pubKey.Curve.BaseX, pubKey.Curve.BaseY, sig.S, pubKey.Curve).
		ScalarMulNonFixedBase(circuit, &lhs, cofactorAllocated, pubKey.Curve)
	// TODO adding lhs.IsOnCurve(...) makes the r1cs bug

	// rhs = cofactor*(R+H(R,A,M)*A)
	rhs := twistededwards.NewPoint(circuit, nil, nil)
	rhs.ScalarMulNonFixedBase(circuit, &pubKey.A, hramAllocated, pubKey.Curve).
		AddGeneric(circuit, &rhs, &sig.R.A, pubKey.Curve).
		ScalarMulNonFixedBase(circuit, &rhs, cofactorAllocated, pubKey.Curve)
	// TODO adding rhs.IsOnCurve(...) makes the r1cs bug

	circuit.MUSTBE_EQ(lhs.X, rhs.X)
	circuit.MUSTBE_EQ(lhs.Y, rhs.Y)

	return nil
}
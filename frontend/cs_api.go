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

package frontend

import (
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs/r1c"
)

// PublicInput creates a new public input
func (c *CS) PublicInput(name string) Variable {
	idx := len(c.PublicInputs)
	res := Variable{false, PublicInput, idx, nil}

	// checks if the name is not already picked
	for _, v := range c.PublicInputsNames {
		if v == name {
			panic("duplicate input name (public)")
		}
	}

	c.PublicInputsNames = append(c.PublicInputsNames, name)
	c.PublicInputs = append(c.PublicInputs, res)
	return res
}

// SecretInput creates a new public input
func (c *CS) SecretInput(name string) Variable {
	idx := len(c.SecretInputs)
	res := Variable{false, SecretInput, idx, nil}

	// checks if the name is not already picked
	for _, v := range c.PublicInputsNames {
		if v == name {
			panic("duplicate input name (secret)")
		}
	}

	c.SecretInputsName = append(c.SecretInputsName, name)
	c.SecretInputs = append(c.SecretInputs, res)
	return res
}

// Add adds 2 wires
func (c *CS) Add(i1, i2 interface{}, in ...interface{}) Variable {

	res := c.newIntermediateVariable()

	one := big.NewInt(1)
	idxone := c.GetCoeffID(one)

	lleft := LinearCombination{}

	add := func(_i interface{}) {
		switch t := _i.(type) {
		case Variable:
			lleft = append(lleft, LinearTerm{t, idxone})
		default:
			n := backend.FromInterface(t)
			idxn := c.GetCoeffID(&n)
			lleft = append(lleft, LinearTerm{c.getOneVariable(), idxn})
		}
	}
	add(i1)
	add(i2)
	for i := 0; i < len(in); i++ {
		add(in[i])
	}

	lright := LinearCombination{
		LinearTerm{c.PublicInputs[0], idxone},
	}
	lo := LinearCombination{
		LinearTerm{res, idxone},
	}
	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Gates = append(c.Gates, g)

	return res
}

// Sub Adds two wires
func (c *CS) Sub(i1, i2 interface{}) Variable {

	res := c.newIntermediateVariable()

	one := big.NewInt(1)
	minusone := big.NewInt(-1)
	idxone := c.GetCoeffID(one)
	idxminusone := c.GetCoeffID(minusone)

	lleft := LinearCombination{}
	switch t := i1.(type) {
	case Variable:
		lleft = append(lleft, LinearTerm{t, idxone})
	default:
		n := backend.FromInterface(t)
		idxn := c.GetCoeffID(&n)
		lleft = append(lleft, LinearTerm{c.getOneVariable(), idxn})
	}

	switch t := i2.(type) {
	case Variable:
		lleft = append(lleft, LinearTerm{t, idxminusone})
	default:
		n := backend.FromInterface(t)
		n.Mul(&n, minusone)
		idxn := c.GetCoeffID(&n)
		lleft = append(lleft, LinearTerm{c.getOneVariable(), idxn})
	}

	lright := LinearCombination{
		LinearTerm{c.PublicInputs[0], idxone},
	}
	lo := LinearCombination{
		LinearTerm{res, idxone},
	}
	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Gates = append(c.Gates, g)

	return res
}

// Mul multiplies 2 wires
func (c *CS) Mul(i1, i2 interface{}, in ...interface{}) Variable {

	one := big.NewInt(1)
	idxone := c.GetCoeffID(one)

	mul := func(_i1, _i2 interface{}) Variable {

		_res := c.newIntermediateVariable()

		lleft := LinearCombination{}
		lright := LinearCombination{}

		// left
		switch t1 := _i1.(type) {
		case LinearCombination:
			lleft = make([]LinearTerm, len(t1))
			copy(lleft, t1)
		case Variable:
			lleft = append(lleft, LinearTerm{t1, idxone})
		default:
			n1 := backend.FromInterface(t1)
			idxn1 := c.GetCoeffID(&n1)
			lleft = append(lleft, LinearTerm{c.getOneVariable(), idxn1})
		}

		// right
		switch t2 := _i2.(type) {
		case LinearCombination:
			lright = make([]LinearTerm, len(t2))
			copy(lright, t2)
		case Variable:
			lright = append(lright, LinearTerm{t2, idxone})
		default:
			n2 := backend.FromInterface(t2)
			idxn2 := c.GetCoeffID(&n2)
			lright = append(lright, LinearTerm{c.getOneVariable(), idxn2})
		}

		lo := LinearCombination{
			LinearTerm{_res, idxone},
		}
		g := Gate{lleft, lright, lo, r1c.SingleOutput}
		c.Gates = append(c.Gates, g)
		return _res
	}

	res := mul(i1, i2)
	for i := 0; i < len(in); i++ {
		res = mul(res, in[i])
	}

	return res
}

// Inverse inverses a variable
func (c *CS) Inverse(v Variable) Variable {

	res := c.newIntermediateVariable()

	// find the entry in c.Coeffs corresponding to 1
	one := big.NewInt(1)
	idxone := c.GetCoeffID(one)

	lleft := LinearCombination{LinearTerm{res, idxone}}
	lright := LinearCombination{LinearTerm{v, idxone}}
	lo := LinearCombination{LinearTerm{c.getOneVariable(), idxone}}
	g := Gate{lleft, lright, lo, r1c.SingleOutput}
	c.Gates = append(c.Gates, g)

	return res
}

// Div divides two constraints (i1/i2)
func (c *CS) Div(i1, i2 interface{}) Variable {

	res := c.newIntermediateVariable()

	// find the entry in c.Coeffs corresponding to 1
	one := big.NewInt(1)
	idxone := c.GetCoeffID(one)

	// lo
	lo := LinearCombination{}
	switch t1 := i1.(type) {
	case LinearCombination:
		lo = make([]LinearTerm, len(t1))
		copy(lo, t1)
	case Variable:
		lo = append(lo, LinearTerm{t1, idxone})
	default:
		n1 := backend.FromInterface(t1)
		idxn1 := c.GetCoeffID(&n1)
		lo = append(lo, LinearTerm{c.getOneVariable(), idxn1})
	}

	// left
	lleft := LinearCombination{}
	switch t2 := i2.(type) {
	case LinearCombination:
		lleft = make([]LinearTerm, len(t2))
		copy(lleft, t2)
	case Variable:
		lleft = append(lleft, LinearTerm{t2, idxone})
	default:
		n2 := backend.FromInterface(t2)
		idxn2 := c.GetCoeffID(&n2)
		lleft = append(lleft, LinearTerm{c.getOneVariable(), idxn2})
	}

	lright := LinearCombination{LinearTerm{res, idxone}}

	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Gates = append(c.Gates, g)

	return res
}

// Xor compute the xor between two constraints
func (c *CS) Xor(a, b Variable) Variable {

	c.MustBeBoolean(a)
	c.MustBeBoolean(b)

	two := big.NewInt(2)
	one := big.NewInt(1)
	minusone := big.NewInt(-1)

	idxtwo := c.GetCoeffID(two)
	idxone := c.GetCoeffID(one)
	idxminusone := c.GetCoeffID(minusone)

	res := c.newIntermediateVariable()
	lleft := LinearCombination{
		LinearTerm{a, idxtwo},
	}
	lright := LinearCombination{
		LinearTerm{b, idxone},
	}
	lo := LinearCombination{
		LinearTerm{a, idxone},
		LinearTerm{b, idxone},
		LinearTerm{res, idxminusone},
	}
	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Gates = append(c.Gates, g)

	return res
}

// ToBinary unpacks a variable in binary, n is the number of bits of the variable
// The result in in little endian (first bit= lsb)
func (c *CS) ToBinary(a Variable, nbBits int) []Variable {

	var tmp big.Int

	idx := make([]int, nbBits)
	one := big.NewInt(1)
	two := big.NewInt(2)
	tmp.Set(two)

	idx[0] = c.GetCoeffID(one)
	idx[1] = c.GetCoeffID(two)

	for i := 2; i < nbBits; i++ {
		tmp.Mul(&tmp, two)
		idx[i] = c.GetCoeffID(&tmp)
	}

	res := make([]Variable, nbBits)
	lleft := make([]LinearTerm, nbBits)
	for i := 0; i < nbBits; i++ {
		res[i] = c.newIntermediateVariable()
		c.MustBeBoolean(res[i])
		lleft[i].Variable = res[i]
		lleft[i].Coeff = idx[i]
	}
	lright := LinearCombination{
		LinearTerm{c.getOneVariable(), idx[0]},
	}
	lo := LinearCombination{
		LinearTerm{a, idx[0]},
	}
	g := Gate{lleft, lright, lo, r1c.BinaryDec}

	c.Gates = append(c.Gates, g)

	return res

}

// FromBinary packs b, seen as a fr.Element in little endian
func (c *CS) FromBinary(b ...Variable) Variable {

	res := c.newIntermediateVariable()

	l := len(b)

	idx := make([]int, l)
	one := big.NewInt(1)
	two := big.NewInt(2)
	var tmp big.Int
	tmp.Set(two)

	idx[0] = c.GetCoeffID(one)
	idx[1] = c.GetCoeffID(two)

	for i := 2; i < l; i++ {
		tmp.Mul(&tmp, two)
		idx[i] = c.GetCoeffID(&tmp)
	}

	lleft := make([]LinearTerm, l)
	for i := 0; i < l; i++ {
		lleft[i].Variable = b[i]
		lleft[i].Coeff = idx[i]
	}
	lright := LinearCombination{
		LinearTerm{c.getOneVariable(), idx[0]},
	}
	lo := LinearCombination{
		LinearTerm{res, idx[0]},
	}
	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Gates = append(c.Gates, g)

	return res
}

// Select if b is true, yields c1 else yields c2
func (c *CS) Select(b Variable, i1, i2 interface{}) Variable {

	res := c.newIntermediateVariable()

	one := big.NewInt(1)
	minusone := big.NewInt(-1)
	idxone := c.GetCoeffID(one)
	idxminusone := c.GetCoeffID(minusone)

	lleft := LinearCombination{
		LinearTerm{b, idxone},
	}

	// lright, first part
	lright := LinearCombination{}
	switch t1 := i1.(type) {
	case LinearCombination:
		lright = make([]LinearTerm, len(t1))
		copy(lright, t1)
	case Variable:
		lright = append(lright, LinearTerm{t1, idxone})
	default:
		n1 := backend.FromInterface(t1)
		idx1 := c.GetCoeffID(&n1)
		lright = append(lright, LinearTerm{c.getOneVariable(), idx1})
	}

	// lright, second part
	toAppend := LinearCombination{}
	switch t2 := i2.(type) {
	case LinearCombination:
		for _, e := range t2 {
			coef := c.Coeffs[e.Coeff]
			coef.Mul(&coef, minusone)
			idcoef := c.GetCoeffID(&coef)
			toAppend = append(toAppend, LinearTerm{e.Variable, idcoef})
		}
	case Variable:
		toAppend = append(toAppend, LinearTerm{t2, idxminusone})
	default:
		n2 := backend.FromInterface(t2)
		idx2 := c.GetCoeffID(&n2)
		toAppend = append(toAppend, LinearTerm{c.getOneVariable(), idx2})
	}
	lright = append(lright, toAppend...)

	lo := LinearCombination{
		LinearTerm{res, idxone},
	}
	lo = append(lo, toAppend...)

	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Gates = append(c.Gates, g)

	return res
}

// Allocate will return an allocated Variable from input {Constraint, element, uint64, int, ...}
func (c *CS) Allocate(input interface{}) Variable {

	res := c.newIntermediateVariable()

	one := big.NewInt(1)
	idxone := c.GetCoeffID(one)

	//lleft
	lleft := LinearCombination{}
	switch t := input.(type) {
	case Variable:
		lleft = append(lleft, LinearTerm{t, idxone})
	default:
		n := backend.FromInterface(t)
		if n.Cmp(one) == 0 {
			return c.getOneVariable()
		}
		idxn := c.GetCoeffID(&n)
		lleft = append(lleft, LinearTerm{c.getOneVariable(), idxn})
	}

	lright := LinearCombination{LinearTerm{c.getOneVariable(), idxone}}
	lo := LinearCombination{LinearTerm{res, idxone}}

	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Gates = append(c.Gates, g)

	return res

}

// MustBeEqual equalizes two variables
func (c *CS) MustBeEqual(i1, i2 interface{}) {

	one := big.NewInt(1)
	idxone := c.GetCoeffID(one)

	//left
	lleft := LinearCombination{}
	switch t1 := i1.(type) {
	case LinearCombination:
		lleft = make([]LinearTerm, len(t1))
		copy(lleft, t1)
	case Variable:
		lleft = append(lleft, LinearTerm{t1, idxone})
	default:
		n1 := backend.FromInterface(t1)
		idxn1 := c.GetCoeffID(&n1)
		lleft = append(lleft, LinearTerm{c.getOneVariable(), idxn1})
	}

	// lo
	lo := LinearCombination{}
	switch t2 := i2.(type) {
	case LinearCombination:
		lo = make([]LinearTerm, len(t2))
		copy(lo, t2)
	case Variable:
		lo = append(lo, LinearTerm{t2, idxone})
	default:
		n2 := backend.FromInterface(t2)
		idxn2 := c.GetCoeffID(&n2)
		lo = append(lo, LinearTerm{c.getOneVariable(), idxn2})
	}

	// right
	lright := LinearCombination{LinearTerm{c.getOneVariable(), idxone}}

	g := Gate{lleft, lright, lo, r1c.SingleOutput}

	c.Constraints = append(c.Constraints, g)
}

// MustBeBoolean boolean constrains a variable
func (c *CS) MustBeBoolean(a Variable) {
	if a.IsBoolean {
		return
	}

	zero := big.NewInt(0)
	one := big.NewInt(1)
	minusone := big.NewInt(-1)
	idxone := c.GetCoeffID(one)
	idxminusone := c.GetCoeffID(minusone)
	idxzero := c.GetCoeffID(zero)

	lleft := LinearCombination{
		LinearTerm{a, idxone},
	}
	lright := LinearCombination{
		LinearTerm{c.getOneVariable(), idxone},
		LinearTerm{a, idxminusone},
	}
	lo := LinearCombination{
		LinearTerm{c.getOneVariable(), idxzero},
	}
	g := Gate{lleft, lright, lo, r1c.SingleOutput}
	c.Constraints = append(c.Constraints, g)
	a.IsBoolean = true
}

// MustBeLessOrEqual constrains w to be less or equal than e (taken as lifted Integer values from Fr)
// https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
func (c *CS) MustBeLessOrEqual(w Variable, bound interface{}) {

	switch b := bound.(type) {
	case Variable:
		c.mustBeLessOrEqVar(w, b)
	default:
		_bound := backend.FromInterface(b)
		c.mustBeLessOrEqCst(w, _bound)
	}

}

func (c *CS) mustBeLessOrEqVar(w, bound Variable) {

	nbBits := 256

	binw := c.ToBinary(w, nbBits)
	binbound := c.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = c.Allocate(1)

	zero := big.NewInt(0)
	one := big.NewInt(1)
	minusone := big.NewInt(-1)
	idxzero := c.GetCoeffID(zero)
	idxone := c.GetCoeffID(one)
	idxminusone := c.GetCoeffID(minusone)

	for i := nbBits - 1; i >= 0; i-- {
		p1 := c.Mul(p[i+1], binw[i])
		p[i] = c.Select(binbound[i], p1, p[i+1])

		zero := c.Allocate(0)
		t := c.Select(binbound[i], zero, p[i+1])
		lleft := LinearCombination{
			LinearTerm{c.getOneVariable(), idxone},
			LinearTerm{t, idxminusone},
			LinearTerm{binw[i], idxminusone},
		}
		lright := LinearCombination{
			LinearTerm{binw[i], idxone},
		}
		lo := LinearCombination{
			LinearTerm{c.getOneVariable(), idxzero},
		}
		g := Gate{lleft, lright, lo, r1c.SingleOutput}
		c.Constraints = append(c.Constraints, g)
	}

}

func (c *CS) mustBeLessOrEqCst(w Variable, bound big.Int) {

	nbBits := 256
	nbWords := 4
	wordSize := 64

	binw := c.ToBinary(w, nbBits)
	binbound := bound.Bits()
	l := len(binbound)
	if len(binbound) < nbWords {
		for i := 0; i < nbWords-l; i++ {
			binbound = append(binbound, big.Word(0))
		}
	}
	p := make([]Variable, nbBits+1)

	var zero big.Int
	idxzero := c.GetCoeffID(&zero)
	one := big.NewInt(1)
	idxone := c.GetCoeffID(one)
	minusone := big.NewInt(-1)
	idxminusone := c.GetCoeffID(minusone)
	p[nbBits] = c.Allocate(1)
	for i := nbWords - 1; i >= 0; i-- {
		for j := 0; j < wordSize; j++ {
			b := (binbound[i] >> (wordSize - 1 - j)) & 1
			if b == 0 {
				p[(i+1)*wordSize-1-j] = p[(i+1)*wordSize-j]
				lleft := LinearCombination{
					LinearTerm{c.getOneVariable(), idxone},
					LinearTerm{p[(i+1)*wordSize-j], idxminusone},
					LinearTerm{binw[(i+1)*wordSize-1-j], idxminusone},
				}
				lright := LinearCombination{LinearTerm{binw[(i+1)*wordSize-1-j], idxone}}
				lo := LinearCombination{LinearTerm{c.getOneVariable(), idxzero}}
				g := Gate{lleft, lright, lo, r1c.SingleOutput}
				c.Constraints = append(c.Constraints, g)

			} else {
				p[(i+1)*wordSize-1-j] = c.Mul(p[(i+1)*wordSize-j], binw[(i+1)*wordSize-1-j])
			}
		}
	}
}

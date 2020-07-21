package algorithms

const FFT = `

import (
	"math/bits"
	"runtime"
	"sync"

	{{ template "import_curve" . }}
)

// TODO this should not be in fft.go
{{if eq .Curve "BLS377"}}
const RootOfUnityStr = "8065159656716812877374967518403273466521432693661810619979959746626482506078"
const MaxOrder = 47
{{else if eq .Curve "BLS381"}}
const RootOfUnityStr = "10238227357739495823651030575849232062558860180284477541189508159991286009131"
const MaxOrder = 32
{{else if eq .Curve "BN256"}}
const RootOfUnityStr = "19103219067921713944291392827692070036145651957329286315305642004821462161904"
const MaxOrder = 28
{{else if eq .Curve "BW761"}}
const RootOfUnityStr = "32863578547254505029601261939868325669770508939375122462904745766352256812585773382134936404344547323199885654433"
const MaxOrder = 46
{{end}}

// FFT computes the discrete Fourier transform of a and stores the result in a.
// The result is in bit-reversed order.
// len(a) must be a power of 2, and w must be a len(a)th root of unity in field F.
// The algorithm is recursive, decimation-in-frequency. [cite]
func FFT(a []fr.Element, w fr.Element) {
	var wg sync.WaitGroup
	asyncFFT(a, w, &wg, 1)
	wg.Wait()
	bitReverse(a)
}

func asyncFFT(a []fr.Element, w fr.Element, wg *sync.WaitGroup, splits uint) {
	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1

	// wPow == w^1
	wPow := w

	// i == 0
	t := a[0]
	a[0].AddAssign(&a[m])
	a[m].Sub(&t, &a[m])

	for i := 1; i < m; i++ {
		t = a[i]
		a[i].AddAssign(&a[i+m])

		a[i+m].
			Sub(&t, &a[i+m]).
			MulAssign(&wPow)

		wPow.MulAssign(&w)
	}

	// if m == 1, then next iteration ends, no need to call 2 extra functions for that
	if m == 1 {
		return
	}

	// note: w is passed by value
	w.Square(&w)

	const parallelThreshold = 64
	serial := splits > uint(runtime.NumCPU()) || m <= parallelThreshold

	if serial {
		asyncFFT(a[0:m], w, nil, splits)
		asyncFFT(a[m:n], w, nil, splits)
	} else {
		splits <<= 1
		wg.Add(1)
		go func() {
			asyncFFT(a[m:n], w, wg, splits)
			wg.Done()
		}()
		asyncFFT(a[0:m], w, wg, splits)
	}
}

// bitReverse applies the bit-reversal permutation to a.
// len(a) must be a power of 2 (as in every single function in this file)
func bitReverse(a []fr.Element) {
	n := uint(len(a))
	nn := uint(bits.UintSize - bits.TrailingZeros(n))

	var tReverse fr.Element
	for i := uint(0); i < n; i++ {
		irev := bits.Reverse(i) >> nn
		if irev > i {
			tReverse = a[i]
			a[i] = a[irev]
			a[irev] = tReverse
		}
	}
}

// Domain with a power of 2 cardinality
// compute a field element of order 2x and store it in GeneratorSqRt
// all other values can be derived from x, GeneratorSqrt
type Domain struct {
	Generator        fr.Element
	GeneratorInv     fr.Element
	GeneratorSqRt    fr.Element // generator of 2 adic subgroup of order 2*nb_constraints
	GeneratorSqRtInv fr.Element
	Cardinality      int
	CardinalityInv   fr.Element
}

// NewDomain returns a subgroup with a power of 2 cardinality
// cardinality >= m
// compute a field element of order 2x and store it in GeneratorSqRt
// all other values can be derived from x, GeneratorSqrt
func NewDomain(rootOfUnity fr.Element, maxOrderRoot uint, m int) *Domain {
	subGroup := &Domain{}
	x := nextPowerOfTwo(uint(m))

	// maxOderRoot is the largest power-of-two order for any element in the field
	// set subGroup.GeneratorSqRt = rootOfUnity^(2^(maxOrderRoot-log(x)-1))
	// to this end, compute expo = 2^(maxOrderRoot-log(x)-1)
	logx := uint(bits.TrailingZeros(x))
	if logx > maxOrderRoot-1 {
		panic("m is too big: the required root of unity does not exist")
	}
	expo := uint64(1 << (maxOrderRoot - logx - 1))
	subGroup.GeneratorSqRt.Exp(rootOfUnity, expo)

	// Generator = GeneratorSqRt^2 has order x
	subGroup.Generator.Mul(&subGroup.GeneratorSqRt, &subGroup.GeneratorSqRt) // order x
	subGroup.Cardinality = int(x)
	subGroup.GeneratorSqRtInv.Inverse(&subGroup.GeneratorSqRt)
	subGroup.GeneratorInv.Inverse(&subGroup.Generator)
	subGroup.CardinalityInv.SetUint64(uint64(x)).Inverse(&subGroup.CardinalityInv)

	return subGroup
}

func nextPowerOfTwo(n uint) uint {
	p := uint(1)
	if (n & (n - 1)) == 0 {
		return n
	}
	for p < n {
		p <<= 1
	}
	return p
}


`
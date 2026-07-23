package curvecheck

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
)

func referenceDecode(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	_, err := new(edwards25519.Point).SetBytes(b)
	return err == nil
}

// sut is a named decoder implementation under test. Every sut is checked
// differentially against the reference oracle on every input.
type sut struct {
	name   string
	decode func(b []byte) bool
}

// suts is the set of implementations under test. For now both entries just
// mirror the oracle so the differential machinery is exercised end-to-end.
// Swap these for real implementations (e.g. batched subprocess calls) later.
var suts = []sut{
	{name: "TypeScript", decode: referenceDecode},
	{name: "Python", decode: referenceDecode},
}

// ---------------------------------------------------------------------------
// Field constants
// ---------------------------------------------------------------------------

var (
	// p = 2^255 - 19
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// 2^255
	two255 = new(big.Int).Lsh(big.NewInt(1), 255)
	// d = -121665 / 121666 mod p
	edwardsD = computeD()
)

func computeD() *big.Int {
	num := new(big.Int).Mod(big.NewInt(-121665), fieldP)
	den := big.NewInt(121666)
	denInv := new(big.Int).ModInverse(den, fieldP)
	d := new(big.Int).Mul(num, denInv)
	return d.Mod(d, fieldP)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

// encodeY produces a 32-byte little-endian encoding of y (masked to 255 bits)
// with the sign bit (bit 255) set according to signBit.
func encodeY(y *big.Int, signBit bool) []byte {
	out := make([]byte, 32)
	// take low 255 bits of y
	masked := new(big.Int).And(y, new(big.Int).Sub(two255, big.NewInt(1)))
	tmp := masked.Bytes() // big-endian
	// write little-endian
	for i := range tmp {
		out[i] = tmp[len(tmp)-1-i]
	}
	if signBit {
		out[31] |= 0x80
	} else {
		out[31] &= 0x7f
	}
	return out
}

// rawEncode writes an arbitrary big.Int as 32-byte little-endian WITHOUT
// masking, so values >= 2^255 exercise the raw byte pattern including bit 255.
// Used for the p .. 2^255 band where we want the exact bytes.
func rawEncode(v *big.Int) []byte {
	out := make([]byte, 32)
	tmp := v.Bytes()
	if len(tmp) > 32 {
		tmp = tmp[len(tmp)-32:] // truncate high bytes; shouldn't happen for our inputs
	}
	for i := 0; i < len(tmp); i++ {
		out[i] = tmp[len(tmp)-1-i]
	}
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Quadratic-residue classification, so we can bucket y values by which decode
// branch they exercise: nonzero-QR, second-root (needs *I), non-residue,
// u==0 (x==0), v==0 (no inverse).
// x^2 = (y^2 - 1) / (d*y^2 + 1)
// ---------------------------------------------------------------------------

type branch int

const (
	branchNonResidue branch = iota // no x exists -> decode fails
	branchQR                       // x^2 is a nonzero square -> decodes
	branchXZero                    // u == 0 -> x = 0 -> decodes
	branchVZero                    // v == 0 -> no inverse -> decode fails
)

func classifyY(y *big.Int) branch {
	y = new(big.Int).Mod(y, fieldP)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, fieldP)

	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, fieldP)

	v := new(big.Int).Mul(edwardsD, y2)
	v.Add(v, big.NewInt(1))
	v.Mod(v, fieldP)

	if v.Sign() == 0 {
		return branchVZero
	}
	if u.Sign() == 0 {
		return branchXZero
	}
	vInv := new(big.Int).ModInverse(v, fieldP)
	x2 := new(big.Int).Mul(u, vInv)
	x2.Mod(x2, fieldP)

	// Legendre symbol: x2^((p-1)/2) mod p
	exp := new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 1)
	leg := new(big.Int).Exp(x2, exp, fieldP)
	if leg.Cmp(big.NewInt(1)) == 0 {
		return branchQR
	}
	return branchNonResidue
}

// findVZeroY solves y^2 = -1/d mod p, returning the roots if -1/d is a QR.
// These are the values where the decode's denominator vanishes.
func findVZeroY() []*big.Int {
	dInv := new(big.Int).ModInverse(edwardsD, fieldP)
	rhs := new(big.Int).Neg(dInv)
	rhs.Mod(rhs, fieldP)
	root := modSqrt(rhs, fieldP)
	if root == nil {
		return nil
	}
	other := new(big.Int).Sub(fieldP, root)
	return []*big.Int{root, other}
}

// modSqrt via Tonelli-Shanks specialized for p ≡ 5 (mod 8) (true for 2^255-19).
// For such p, sqrt candidate = a^((p+3)/8); fix up with sqrt(-1) if needed.
func modSqrt(a, p *big.Int) *big.Int {
	a = new(big.Int).Mod(a, p)
	if a.Sign() == 0 {
		return big.NewInt(0)
	}
	exp := new(big.Int).Add(p, big.NewInt(3))
	exp.Rsh(exp, 3) // (p+3)/8
	r := new(big.Int).Exp(a, exp, p)

	rr := new(big.Int).Mul(r, r)
	rr.Mod(rr, p)
	if rr.Cmp(a) == 0 {
		return r
	}
	// multiply by sqrt(-1) = 2^((p-1)/4)
	expI := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2)
	I := new(big.Int).Exp(big.NewInt(2), expI, p)
	r.Mul(r, I)
	r.Mod(r, p)
	rr.Mul(r, r)
	rr.Mod(rr, p)
	if rr.Cmp(a) == 0 {
		return r
	}
	return nil // a is not a QR
}

// ---------------------------------------------------------------------------
// Boundary value generation
// ---------------------------------------------------------------------------

// boundaryYValues returns the interesting y integers (before encoding) to sweep.
func boundaryYValues() []*big.Int {
	vals := map[string]*big.Int{}
	add := func(v *big.Int) { vals[v.String()] = new(big.Int).Set(v) }

	centers := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Set(fieldP),                // p
		new(big.Int).Sub(two255, big.NewInt(1)), // 2^255 - 1
	}
	for _, c := range centers {
		for delta := int64(-16); delta <= 16; delta++ {
			v := new(big.Int).Add(c, big.NewInt(delta))
			if v.Sign() < 0 {
				continue
			}
			add(v)
		}
	}
	// v==0 roots
	for _, v := range findVZeroY() {
		add(v)
		add(new(big.Int).Add(v, big.NewInt(1)))
		add(new(big.Int).Sub(v, big.NewInt(1)))
	}

	out := make([]*big.Int, 0, len(vals))
	for _, v := range vals {
		out = append(out, v)
	}
	return out
}

// bucketedYValues returns a handful of y values per decode branch, found by
// scanning upward from small y. Guarantees every branch is represented.
func bucketedYValues(perBucket int) map[branch][]*big.Int {
	buckets := map[branch][]*big.Int{}
	y := big.NewInt(2)
	one := big.NewInt(1)
	limit := 200000 // scan ceiling; all branches fill well before this
	for range limit {
		b := classifyY(y)
		if len(buckets[b]) < perBucket {
			buckets[b] = append(buckets[b], new(big.Int).Set(y))
		}
		done := true
		for _, br := range []branch{branchNonResidue, branchQR, branchXZero, branchVZero} {
			if len(buckets[br]) < perBucket {
				// vZero is rare; don't block completion on it (handled via findVZeroY)
				if br == branchVZero {
					continue
				}
				done = false
			}
		}
		if done {
			break
		}
		y = new(big.Int).Add(y, one)
	}
	// ensure vZero populated from the exact solver
	for _, v := range findVZeroY() {
		buckets[branchVZero] = append(buckets[branchVZero], v)
	}
	return buckets
}

// ---------------------------------------------------------------------------
// Known-answer seed corpus (KAT + low-order + real keys)
// ---------------------------------------------------------------------------

var katEncodings = []string{
	// edwards25519_decode_cases
	"5866666666666666666666666666666666666666666666666666666666666666", // base point
	"0100000000000000000000000000000000000000000000000000000000000000", // small-order identity
	"0100000000000000000000000000000000000000000000000000000000000080", // sign-bit non-canonical identity
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p
	"efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p+2 (non-decodable)
	// counter_cases addresses (hex)
	"3765d0000d9c8500bfe1285bb26e55eb5183ba25a5fb2574cddeca5a33f12e18", // counter 0 (on-curve)
	"a72b0156bc6f3edf5293c4dc330bbbb9e6444cbbd549e67edb7ddfda6a30dff1", // counter 1 (off-curve)
}

// Canonical low-order points (the 8 well-known Ed25519 small-order encodings).
var lowOrderEncodings = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
}

func seedCorpus() [][]byte {
	var out [][]byte
	for _, h := range katEncodings {
		out = append(out, mustHex(h))
	}
	for _, h := range lowOrderEncodings {
		out = append(out, mustHex(h))
	}
	return out
}

// ---------------------------------------------------------------------------
// Deterministic table tests for the boundary and bucketed classes.
// These are NOT left to the fuzz mutator — the exact values matter.
// ---------------------------------------------------------------------------

func TestBoundaryValues(t *testing.T) {
	for _, y := range boundaryYValues() {
		for _, sign := range []bool{false, true} {
			enc := encodeY(y, sign)
			assertAgree(t, enc, "boundary y="+y.String())
		}
		// also the raw (unmasked) encoding for values that fit in 32 bytes,
		// to catch bit-255 handling on the p..2^255 band
		if y.Cmp(two255) < 0 {
			assertAgree(t, rawEncode(y), "boundary-raw y="+y.String())
		}
	}
}

func TestBucketedBranches(t *testing.T) {
	buckets := bucketedYValues(8)
	names := map[branch]string{
		branchNonResidue: "non-residue",
		branchQR:         "nonzero-QR",
		branchXZero:      "x-zero",
		branchVZero:      "v-zero",
	}
	for br, ys := range buckets {
		for _, y := range ys {
			for _, sign := range []bool{false, true} {
				enc := encodeY(y, sign)
				assertAgree(t, enc, "branch="+names[br]+" y="+y.String())
			}
		}
	}
}

func TestKnownAnswers(t *testing.T) {
	for _, enc := range seedCorpus() {
		assertAgree(t, enc, "kat "+hex.EncodeToString(enc))
	}
}

func assertAgree(t *testing.T, enc []byte, label string) {
	t.Helper()
	want := referenceDecode(enc)
	for _, s := range suts {
		got := s.decode(enc)
		if want != got {
			t.Errorf("divergence [%s] sut=%s: enc=%x reference=%v sut=%v", label, s.name, enc, want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Non-canonical y band.
//
// The reference decoder (filippo edwards25519) masks off bit 255 and does NOT
// reduce y mod p, so it accepts encodings with y in [p, 2^255) as long as the
// reduced value is curve-valid. Since 2^255-1 - p == 18, the ENTIRE band is
// exactly 19 integers (p .. p+18 == p .. 2^255-1) — small enough to enumerate.
//
// A canonical / RFC-8032 decoder (libsodium, noble, tweetnacl) rejects these.
// We also assert the oracle property that encode(k) and encode(p+k) decode
// identically, and that this is the complete set of canonical/non-canonical
// pairs (y+p < 2^255 only holds for k <= 18).
// ---------------------------------------------------------------------------

func TestNonCanonicalYBand(t *testing.T) {
	maxK := new(big.Int).Sub(two255, big.NewInt(1)) // 2^255 - 1
	maxK.Sub(maxK, fieldP)                          // == 18
	if maxK.Cmp(big.NewInt(18)) != 0 {
		t.Fatalf("expected band width 18, got %s (curve constants wrong?)", maxK)
	}

	for k := int64(0); k <= 18; k++ {
		kk := big.NewInt(k)
		nonCanon := new(big.Int).Add(fieldP, kk) // p + k, in [p, 2^255)
		for _, sign := range []bool{false, true} {
			canonEnc := encodeY(kk, sign)
			nonCanonEnc := encodeY(nonCanon, sign)

			// Both encodings must agree with the reference on the SUT side.
			assertAgree(t, canonEnc, "band-canon k="+kk.String())
			assertAgree(t, nonCanonEnc, "band-noncanon y=p+"+kk.String())
			// And the raw (unmasked) encoding of the non-canonical value.
			assertAgree(t, rawEncode(nonCanon), "band-noncanon-raw y=p+"+kk.String())

			// Oracle property: reducing y mod p must not change the verdict.
			if referenceDecode(canonEnc) != referenceDecode(nonCanonEnc) {
				t.Errorf("reference treats y=%s and y=p+%s differently (sign=%v)", kk, kk, sign)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Negative zero: x == 0 with the sign bit set.
//
// x == 0 happens iff y^2 == 1, i.e. y == 1 or y == p-1. Setting the sign bit
// on a zero x is non-canonical; the reference accepts it (documented in
// SetBytes), a canonical decoder rejects it. Tested in isolation so a failure
// names the rule rather than hiding inside a bucket.
// ---------------------------------------------------------------------------

func TestNegativeZero(t *testing.T) {
	xZeroYs := []*big.Int{
		big.NewInt(1),
		new(big.Int).Sub(fieldP, big.NewInt(1)), // p - 1
	}
	for _, y := range xZeroYs {
		if classifyY(y) != branchXZero {
			t.Fatalf("expected y=%s to be an x==0 point", y)
		}
		for _, sign := range []bool{false, true} {
			assertAgree(t, encodeY(y, sign), "neg-zero y="+y.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Invalid lengths.
//
// The reference rejects anything that isn't exactly 32 bytes. The fuzz body and
// every table test normalize to 32 bytes, so this rejection path is otherwise
// never differentially checked — important once the SUT is a real subprocess
// whose length guard could be wrong.
// ---------------------------------------------------------------------------

func TestInvalidLengths(t *testing.T) {
	basePoint := mustHex(katEncodings[0])
	for _, n := range []int{0, 1, 16, 31, 33, 63, 64, 128} {
		buf := make([]byte, n)
		copy(buf, basePoint) // seed with valid-looking prefix so it isn't trivially all-zero
		assertAgree(t, buf, "invalid-length n="+itoa(n))
	}
}

// ---------------------------------------------------------------------------
// Determinism and batch-order independence.
//
// Scaffolding for when systemUnderTest becomes a batched subprocess: the same
// input must always yield the same verdict, and evaluation order must not
// change any per-input result (catches state leaking across the IPC boundary).
// ---------------------------------------------------------------------------

func TestDeterminismAndOrderIndependence(t *testing.T) {
	// Assemble a representative input set.
	var inputs [][]byte
	inputs = append(inputs, seedCorpus()...)
	for _, y := range boundaryYValues() {
		inputs = append(inputs, encodeY(y, false), encodeY(y, true))
	}

	for _, s := range suts {
		// Determinism: evaluating the same input twice agrees.
		baseline := make(map[string]bool, len(inputs))
		for _, in := range inputs {
			key := hex.EncodeToString(in)
			v := s.decode(in)
			if prev, ok := baseline[key]; ok && prev != v {
				t.Errorf("non-deterministic verdict for %s (sut=%s): %v then %v", key, s.name, prev, v)
			}
			baseline[key] = v
		}

		// Order independence: shuffle and re-evaluate, compare against baseline.
		r := rand.New(rand.NewSource(0xC0FFEE))
		order := r.Perm(len(inputs))
		for _, idx := range order {
			in := inputs[idx]
			key := hex.EncodeToString(in)
			if got := s.decode(in); got != baseline[key] {
				t.Errorf("order-dependent verdict for %s (sut=%s): baseline=%v shuffled=%v", key, s.name, baseline[key], got)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Single-bit-flip sweep.
//
// All 256 one-bit mutations of the base point and of a real Ed25519 public key.
// Reproducible in plain `go test` and reliably hits near-boundary inputs the
// coverage-guided fuzzer only reaches probabilistically.
// ---------------------------------------------------------------------------

func TestSingleBitFlips(t *testing.T) {
	seeds := map[string][]byte{
		"base-point": mustHex(katEncodings[0]),
		"real-key":   realPublicKey(1),
	}
	for name, seed := range seeds {
		if len(seed) != 32 {
			t.Fatalf("%s seed is %d bytes", name, len(seed))
		}
		for i := range 32 {
			for bit := range 8 {
				flipped := make([]byte, 32)
				copy(flipped, seed)
				flipped[i] ^= 1 << uint(bit)
				assertAgree(t, flipped, "bitflip "+name+" byte="+itoa(i)+" bit="+itoa(bit))
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Sign-bit-only toggle on every KAT: isolates bit-255 (x-sign) handling.
// ---------------------------------------------------------------------------

func TestSignBitToggle(t *testing.T) {
	for _, h := range katEncodings {
		enc := mustHex(h)
		toggled := make([]byte, 32)
		copy(toggled, enc)
		toggled[31] ^= 0x80
		assertAgree(t, enc, "signbit-orig "+h)
		assertAgree(t, toggled, "signbit-toggled "+h)
	}
}

// ---------------------------------------------------------------------------
// Seeded random differential sweep. Gives CI volume without needing `-fuzz`.
// ---------------------------------------------------------------------------

func TestRandomDifferential(t *testing.T) {
	const n = 100_000
	r := rand.New(rand.NewSource(1))
	buf := make([]byte, 32)
	for i := range n {
		r.Read(buf)
		assertAgree(t, buf, "random i="+itoa(i))
	}
}

// ---------------------------------------------------------------------------
// Positive controls: real Ed25519 public keys are always on-curve and
// canonical, so a SUT that trivially returns false can't pass. The reversed
// base point is a cheap negative control for a byte-order bug.
// ---------------------------------------------------------------------------

func TestRealKeysPositiveControl(t *testing.T) {
	for seed := byte(1); seed <= 16; seed++ {
		pub := realPublicKey(seed)
		if !referenceDecode(pub) {
			t.Fatalf("real Ed25519 public key did not decode (seed=%d): %x", seed, pub)
		}
		assertAgree(t, pub, "real-key seed="+itoa(int(seed)))
	}

	// Reversed base point: almost certainly not the canonical base point, so
	// this catches an endianness bug where the SUT reads big-endian.
	base := mustHex(katEncodings[0])
	rev := make([]byte, 32)
	for i := range base {
		rev[i] = base[31-i]
	}
	assertAgree(t, rev, "reversed-base-point")
}

// realPublicKey returns a valid on-curve Ed25519 public key derived
// deterministically from a single-byte seed.
func realPublicKey(seed byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey)
}

// itoa is a tiny int->string helper so labels don't pull in strconv everywhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---------------------------------------------------------------------------
// Structured random generators for f.Add seeding + a plain randomized test.
// ---------------------------------------------------------------------------

func hashDistributionSamples(n int) [][]byte {
	var out [][]byte
	for i := range n {
		seed := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		s512 := sha512.Sum512_256(seed) // production address distribution
		out = append(out, s512[:])
		s256 := sha256.Sum256(seed)
		out = append(out, s256[:])
	}
	return out
}

// ---------------------------------------------------------------------------
// The fuzz entry point.
// ---------------------------------------------------------------------------

func FuzzCurveCheck(f *testing.F) {
	// Seed with KAT + low-order + real-distribution samples so the coverage-
	// guided mutator explores AROUND the dangerous encodings.
	for _, enc := range seedCorpus() {
		f.Add(enc)
	}
	for _, enc := range hashDistributionSamples(64) {
		f.Add(enc)
	}
	// Seed boundary encodings too.
	for _, y := range boundaryYValues() {
		f.Add(encodeY(y, false))
		f.Add(encodeY(y, true))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Normalize length deterministically: the decoder only accepts 32 bytes,
		// so anything else is a definite "false" on both sides — but we still
		// want to feed exactly-32 inputs to exercise decode logic.
		if len(raw) != 32 {
			// truncate or pad so the mutator's length changes still produce
			// meaningful 32-byte inputs rather than trivial rejects.
			fixed := make([]byte, 32)
			copy(fixed, raw)
			raw = fixed
		}
		want := referenceDecode(raw)
		for _, s := range suts {
			got := s.decode(raw)
			if want != got {
				t.Fatalf("divergence sut=%s: enc=%x reference=%v sut=%v", s.name, raw, want, got)
			}
		}
	})
}

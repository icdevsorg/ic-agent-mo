/// BLS12-381 pairing verification, pure Motoko (alpha-7 G2). The IC certifies state with a
/// "min_sig" BLS signature (interface spec, "Certification"): public keys are 96-byte
/// compressed G2 points, signatures are 48-byte compressed G1 points, and
/// `verify(pk, sig, msg) = e(sig, g2) == e(H(msg), pk)` where `H` is the RFC 9380
/// (formerly draft-irtf-cfrg-hash-to-curve) hash-to-curve map for G1 under the ciphersuite
/// `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`.
///
/// There is no pure-Motoko BLS12-381 on mops (checked 2026-09-23: `BLS12-381.mo`, cited in
/// the alpha-7 survey as an existing building block, turned out on inspection to be the
/// RUST crates `ic_bls12_381`/`ic-verify-bls-signature` the CLI links for `--remote` --
/// nothing Motoko-side). This is a from-scratch port, validated layer by layer against
/// `py_ecc` (see "Differential oracle" below and `.plan/audit/g2-bls-report.md`).
///
/// Field tower: Fp -> Fp2 = Fp[u]/(u^2+1) -> Fp6 = Fp2[v]/(v^3-(1+u)) -> Fp12 = Fp6[w]/(w^2-v).
/// This is the tower essentially every BLS12-381 implementation uses (zkcrypto/bls12_381,
/// noble-bls12-381, blst); the exact twist/basis embedding below is OUR OWN choice, not
/// borrowed from any of them -- see "Differential oracle" for why that is fine.
///
/// G1/G2 use plain projective coordinates `(X:Y:Z)`, `x=X/Z, y=Y/Z` (the same convention as
/// python's `py_ecc.optimized_bls12_381.optimized_curve`, which is also where the isogeny/SWU
/// constants below were pulled from -- see `BlsConstants.mo`).
///
/// PERFORMANCE: `Fp` is `Nat` (moxzi/Motoko's arbitrary-precision bignum), not fixed-width
/// limbs -- correct, not fast, and deliberately not micro-optimised (no Jacobian coordinates,
/// no windowed scalar multiplication, no Frobenius-coefficient final exponentiation): the
/// point of alpha-7 G2 is an honest, measured number for G3, not a hand-tuned one that hides
/// how expensive this really is in pure Motoko. The pairing costs roughly 1,500 Fp12
/// multiplications (~70 Fp multiplications each via the tower) for the Miller loop, plus a
/// further ~4,300 Fp12 squarings/multiplications for the single-exponent final
/// exponentiation -- on the order of 1.1-1.2 million 381-bit modular multiplications for ONE
/// verified query (two pairings). Measured wall time and instructions:
/// `mops/mo-ic-agent/README.md` ("Certificate verification cost").
///
/// == Differential oracle (P3) ==
/// There is no pure-Motoko BLS on this machine to diff against, but `py_ecc` (python,
/// installed on the build host) implements the same curve, so it stood in as the oracle for
/// every layer while this file was written. Two different validation strategies were used,
/// deliberately, because they cover different risks:
///  1. LAYER-EXACT match against py_ecc: the isogeny/SWU constants (`BlsConstants.mo`) were
///     pulled from `py_ecc.optimized_bls12_381.constants` PROGRAMMATICALLY, never retyped by
///     hand -- transcribing ~50 381-bit constants by hand is exactly how a silent,
///     hard-to-find bug gets born. `hashToCurveG1` matches `py_ecc.bls.hash_to_curve.hash_to_G1`
///     BYTE-IDENTICALLY on every test message (its whole point-doubling/isogeny/cofactor
///     pipeline has to be right for that to hold). `decompressG1`/`decompressG2` match
///     `py_ecc.bls.point_compression` byte-identically both ways.
///  2. SELF-CONSISTENCY for the pairing itself: this file's Fp12 tower and twist embedding
///     are its own construction, not py_ecc's flat degree-12 polynomial representation, so
///     there is no meaningful per-coefficient comparison against py_ecc to make for
///     intermediate pairing values. Instead: bilinearity (`e(aP,bQ) == e(P,Q)^(ab)` for
///     random small a,b), non-degeneracy (`e(g1,g2) != 1`), and the group-order identity
///     (`e(g1,g2)^r == 1`) were checked in the Python prototype this file was transliterated
///     from -- together a strong test that fails under almost any twist/sign/formula bug --
///     and then, decisively, REAL py_ecc-COMPOSED SIGNATURES (`sk` random, `pk = sk g2`,
///     `sig = sk H(msg)`) were checked against `verify`: because `hashToCurveG1` matches
///     py_ecc exactly and any correctly-implemented bilinear pairing satisfies
///     `e(sk H(msg), g2) == e(H(msg), sk g2)`, THIS check does not depend on matching py_ecc's
///     internal Fp12 basis at all -- only on the pairing here actually being a pairing.
///     `test/BlsVectors.mo` carries the vectors this produced (both compilers, moxzi and moc,
///     run them; `scripts/ic_agent_gate.sh`).
import C "BlsConstants";
import Sha256 "mo:sha2/Sha256";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Nat "mo:base/Nat";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";

module {
  // ============================================================================================
  // Fp: field elements are Nat in [0, P). Every op reduces mod P; there is no lazy/deferred
  // reduction (a real implementation would batch reductions -- another line item for G3).
  public type Fp = Nat;
  let P = C.P;
  public func fpAdd(a : Fp, b : Fp) : Fp { (a + b) % P };
  public func fpSub(a : Fp, b : Fp) : Fp { if (a >= b) { a - b } else { P + a - b } };
  public func fpMul(a : Fp, b : Fp) : Fp { (a * b) % P };
  public func fpNeg(a : Fp) : Fp { if (a == 0) { 0 } else { P - a } };
  public func fpSq(a : Fp) : Fp { fpMul(a, a) };
  /// Square-and-multiply modular exponentiation -- the one operation this whole file spends
  /// most of its instructions in (final exponentiation is a single ~4314-bit `fpPow`-shaped
  /// call, just over Fp12 instead of Fp; `fpPow` itself is used for field inversion (Fermat,
  /// `a^(P-2)`), square roots at P%4==3 (`a^((P+1)/4)`), and the isogeny map's sqrt_division).
  public func fpPow(a : Fp, e : Nat) : Fp {
    var r : Nat = 1;
    var base = a % P;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) { r := fpMul(r, base) };
      base := fpMul(base, base);
      exp := exp / 2;
    };
    r
  };
  public func fpInv(a : Fp) : Fp { fpPow(a, P - 2) };
  /// P % 4 == 3, so a square root (when one exists) is `a^((P+1)/4)`; the caller must verify
  /// `sqrt*sqrt == a` since this returns SOME value unconditionally (matching `py_ecc`'s
  /// `sqrt_division_FQ`, which returns a validity flag alongside the candidate).
  public func fpSqrtCandidate(a : Fp) : Fp { fpPow(a, (P + 1) / 4) };
  func sgn0(a : Fp) : Nat { a % 2 };

  // ============================================================================================
  // Fp2 = c0 + c1 u, u^2 = -1. Represented (c0, c1).
  public type Fp2 = (Fp, Fp);
  public let F2_ZERO : Fp2 = (0, 0);
  public let F2_ONE : Fp2 = (1, 0);
  public func f2Add(a : Fp2, b : Fp2) : Fp2 { (fpAdd(a.0, b.0), fpAdd(a.1, b.1)) };
  public func f2Sub(a : Fp2, b : Fp2) : Fp2 { (fpSub(a.0, b.0), fpSub(a.1, b.1)) };
  public func f2Neg(a : Fp2) : Fp2 { (fpNeg(a.0), fpNeg(a.1)) };
  public func f2Mul(a : Fp2, b : Fp2) : Fp2 {
    (fpSub(fpMul(a.0, b.0), fpMul(a.1, b.1)), fpAdd(fpMul(a.0, b.1), fpMul(a.1, b.0)))
  };
  public func f2Sq(a : Fp2) : Fp2 { f2Mul(a, a) };
  public func f2MulScalar(a : Fp2, k : Nat) : Fp2 { (fpMul(a.0, k), fpMul(a.1, k)) };
  func f2Eq(a : Fp2, b : Fp2) : Bool { a.0 == b.0 and a.1 == b.1 };
  func f2IsZero(a : Fp2) : Bool { a.0 == 0 and a.1 == 0 };
  public func f2Norm(a : Fp2) : Fp { fpAdd(fpMul(a.0, a.0), fpMul(a.1, a.1)) };
  public func f2Inv(a : Fp2) : Fp2 {
    let ninv = fpInv(f2Norm(a));
    (fpMul(a.0, ninv), fpMul(fpNeg(a.1), ninv))
  };
  public func f2Div(a : Fp2, b : Fp2) : Fp2 { f2Mul(a, f2Inv(b)) };
  public func f2Pow(a : Fp2, e : Nat) : Fp2 {
    var r = F2_ONE;
    var base = a;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) { r := f2Mul(r, base) };
      base := f2Sq(base);
      exp := exp / 2;
    };
    r
  };
  /// The Fp6 nonresidue xi = 1+u.
  public func f2MulXi(a : Fp2) : Fp2 { f2Mul(a, (1, 1)) };

  // ============================================================================================
  // Fp6 = c0 + c1 v + c2 v^2, v^3 = xi = 1+u. Represented (c0, c1, c2).
  public type Fp6 = (Fp2, Fp2, Fp2);
  public let F6_ZERO : Fp6 = (F2_ZERO, F2_ZERO, F2_ZERO);
  public let F6_ONE : Fp6 = (F2_ONE, F2_ZERO, F2_ZERO);
  public func f6Add(a : Fp6, b : Fp6) : Fp6 { (f2Add(a.0, b.0), f2Add(a.1, b.1), f2Add(a.2, b.2)) };
  public func f6Sub(a : Fp6, b : Fp6) : Fp6 { (f2Sub(a.0, b.0), f2Sub(a.1, b.1), f2Sub(a.2, b.2)) };
  public func f6Neg(a : Fp6) : Fp6 { (f2Neg(a.0), f2Neg(a.1), f2Neg(a.2)) };
  /// Karatsuba-style degree-3 multiplication (Devegili et al., "Multiplication and Squaring
  /// on Pairing-Friendly Fields" -- the standard formula for a cubic extension by a
  /// nonresidue xi): 6 Fp2 multiplications instead of the schoolbook 9.
  public func f6Mul(a : Fp6, b : Fp6) : Fp6 {
    let t0 = f2Mul(a.0, b.0);
    let t1 = f2Mul(a.1, b.1);
    let t2 = f2Mul(a.2, b.2);
    let c0 = f2Add(t0, f2MulXi(f2Sub(f2Mul(f2Add(a.1, a.2), f2Add(b.1, b.2)), f2Add(t1, t2))));
    let c1 = f2Add(f2Sub(f2Mul(f2Add(a.0, a.1), f2Add(b.0, b.1)), f2Add(t0, t1)), f2MulXi(t2));
    let c2 = f2Add(f2Sub(f2Mul(f2Add(a.0, a.2), f2Add(b.0, b.2)), t0), f2Sub(t1, t2));
    (c0, c1, c2)
  };
  public func f6Sq(a : Fp6) : Fp6 { f6Mul(a, a) };
  /// Multiply by v: (c0,c1,c2) -> c0 v + c1 v^2 + c2 v^3 = (xi c2, c0, c1).
  public func f6MulV(a : Fp6) : Fp6 { (f2MulXi(a.2), a.0, a.1) };
  func f6Eq(a : Fp6, b : Fp6) : Bool { f2Eq(a.0, b.0) and f2Eq(a.1, b.1) and f2Eq(a.2, b.2) };
  func f6IsZero(a : Fp6) : Bool { f2IsZero(a.0) and f2IsZero(a.1) and f2IsZero(a.2) };
  /// Inversion via the cubic norm form (same reference as `f6Mul`): b_i are the adjugate
  /// entries, t is the norm N(a) in Fp2, and a^-1 = t^-1 * (b0,b1,b2).
  public func f6Inv(a : Fp6) : Fp6 {
    let b0 = f2Sub(f2Mul(a.0, a.0), f2MulXi(f2Mul(a.1, a.2)));
    let b1 = f2Sub(f2MulXi(f2Mul(a.2, a.2)), f2Mul(a.0, a.1));
    let b2 = f2Sub(f2Mul(a.1, a.1), f2Mul(a.0, a.2));
    let t = f2Add(f2MulXi(f2Mul(a.2, b1)), f2Add(f2Mul(a.0, b0), f2MulXi(f2Mul(a.1, b2))));
    let tinv = f2Inv(t);
    (f2Mul(b0, tinv), f2Mul(b1, tinv), f2Mul(b2, tinv))
  };

  // ============================================================================================
  // Fp12 = c0 + c1 w, w^2 = v. Represented (c0, c1) with c0,c1 : Fp6.
  public type Fp12 = (Fp6, Fp6);
  public let F12_ZERO : Fp12 = (F6_ZERO, F6_ZERO);
  public let F12_ONE : Fp12 = (F6_ONE, F6_ZERO);
  public func f12Add(a : Fp12, b : Fp12) : Fp12 { (f6Add(a.0, b.0), f6Add(a.1, b.1)) };
  public func f12Sub(a : Fp12, b : Fp12) : Fp12 { (f6Sub(a.0, b.0), f6Sub(a.1, b.1)) };
  public func f12Neg(a : Fp12) : Fp12 { (f6Neg(a.0), f6Neg(a.1)) };
  /// Karatsuba over Fp6 (quadratic extension by v): 3 Fp6 multiplications instead of 4.
  public func f12Mul(a : Fp12, b : Fp12) : Fp12 {
    let t0 = f6Mul(a.0, b.0);
    let t1 = f6Mul(a.1, b.1);
    let c0 = f6Add(t0, f6MulV(t1));
    let c1 = f6Sub(f6Mul(f6Add(a.0, a.1), f6Add(b.0, b.1)), f6Add(t0, t1));
    (c0, c1)
  };
  public func f12Sq(a : Fp12) : Fp12 { f12Mul(a, a) };
  public func f12Eq(a : Fp12, b : Fp12) : Bool { f6Eq(a.0, b.0) and f6Eq(a.1, b.1) };
  /// Multiply by a small (fits in Nat) scalar via repeated addition -- used only for the
  /// point-doubling formula's fixed small coefficients (2,3,4,8), never per-bit of a big
  /// exponent, so O(k) addition beats pulling in a separate "Fp12 * Nat" multiplier.
  func f12Muls(a : Fp12, k : Nat) : Fp12 {
    var r = F12_ZERO;
    var i = 0;
    while (i < k) { r := f12Add(r, a); i += 1 };
    r
  };
  public func f12Inv(a : Fp12) : Fp12 {
    let t = f6Sub(f6Mul(a.0, a.0), f6MulV(f6Mul(a.1, a.1)));
    let tinv = f6Inv(t);
    (f6Mul(a.0, tinv), f6Neg(f6Mul(a.1, tinv)))
  };
  public func f12Div(a : Fp12, b : Fp12) : Fp12 { f12Mul(a, f12Inv(b)) };
  /// The one big (~4314-bit) exponentiation in this file: the naive final exponentiation
  /// `f ^ ((P^12-1)/R)`, done as a single square-and-multiply pass. See the module comment
  /// on performance for why this is not split into an easy/hard part.
  public func f12Pow(a : Fp12, e : Nat) : Fp12 {
    var r = F12_ONE;
    var base = a;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) { r := f12Mul(r, base) };
      base := f12Sq(base);
      exp := exp / 2;
    };
    r
  };
  func fpToF12(a : Fp) : Fp12 { (((a, 0), F2_ZERO, F2_ZERO), F6_ZERO) };
  /// The natural subfield inclusion Fp2 -> Fp6 -> Fp12 (Fp2 sits inside Fp6 as `(x,0,0)`,
  /// inside Fp12 as `(that, 0)`) -- this is a ring homomorphism by construction, not a chosen
  /// embedding, so it needs no justification beyond "the tower is built this way".
  func f2ToF12(a : Fp2) : Fp12 { ((a, F2_ZERO, F2_ZERO), F6_ZERO) };

  // ============================================================================================
  // G1: projective points (X:Y:Z) over Fp, x=X/Z, y=Y/Z, curve y^2 = x^3 + 4.
  public type G1 = (Fp, Fp, Fp);
  let B1 : Fp = 4;
  public let G1_GEN : G1 = (C.G1_GEN_X, C.G1_GEN_Y, 1);
  public let G1_INF : G1 = (1, 1, 0);
  public func g1IsInf(p : G1) : Bool { p.2 == 0 };
  /// Elliptic-curve point doubling/addition in projective coordinates (Bernstein-Lange style,
  /// no inversions) -- these formulas are field-agnostic; the SAME shapes reappear for G2
  /// (over Fp2) and inside the Miller loop (over Fp12) below.
  public func g1Double(p : G1) : G1 {
    let (x, y, z) = p;
    let w = fpMul(3, fpMul(x, x));
    let s = fpMul(y, z);
    let b = fpMul(x, fpMul(y, s));
    let h = fpSub(fpMul(w, w), fpMul(8, b));
    let s2 = fpMul(s, s);
    let nx = fpMul(2, fpMul(h, s));
    let ny = fpSub(fpMul(w, fpSub(fpMul(4, b), h)), fpMul(8, fpMul(fpMul(y, y), s2)));
    let nz = fpMul(8, fpMul(s, s2));
    (nx, ny, nz)
  };
  public func g1Add(p1 : G1, p2 : G1) : G1 {
    if (g1IsInf(p1)) { return p2 };
    if (g1IsInf(p2)) { return p1 };
    let (x1, y1, z1) = p1;
    let (x2, y2, z2) = p2;
    let u1 = fpMul(y2, z1); let u2 = fpMul(y1, z2);
    let v1 = fpMul(x2, z1); let v2 = fpMul(x1, z2);
    if (v1 == v2 and u1 == u2) { return g1Double(p1) };
    if (v1 == v2) { return G1_INF };
    let u = fpSub(u1, u2); let v = fpSub(v1, v2);
    let v2s = fpMul(v, v); let v2sv2 = fpMul(v2s, v2); let v3 = fpMul(v, v2s);
    let w = fpMul(z1, z2);
    let a = fpSub(fpSub(fpMul(fpMul(u, u), w), v3), fpMul(2, v2sv2));
    let nx = fpMul(v, a);
    let ny = fpSub(fpMul(u, fpSub(v2sv2, a)), fpMul(v3, u2));
    let nz = fpMul(v3, w);
    (nx, ny, nz)
  };
  public func g1Neg(p : G1) : G1 { (p.0, fpNeg(p.1), p.2) };
  public func g1Mul(p : G1, n : Nat) : G1 {
    var r = G1_INF;
    var base = p;
    var e = n;
    while (e > 0) {
      if (e % 2 == 1) { r := g1Add(r, base) };
      base := g1Double(base);
      e := e / 2;
    };
    r
  };
  public func g1Affine(p : G1) : ?(Fp, Fp) {
    if (p.2 == 0) { return null };
    let zi = fpInv(p.2);
    ?(fpMul(p.0, zi), fpMul(p.1, zi))
  };
  public func g1Eq(p1 : G1, p2 : G1) : Bool {
    if (g1IsInf(p1) or g1IsInf(p2)) { return g1IsInf(p1) == g1IsInf(p2) };
    fpMul(p1.0, p2.2) == fpMul(p2.0, p1.2) and fpMul(p1.1, p2.2) == fpMul(p2.1, p1.2)
  };
  public func g1OnCurve(p : G1) : Bool {
    if (g1IsInf(p)) { return true };
    let (x, y, z) = p;
    fpSub(fpMul(fpMul(y, y), z), fpAdd(fpMul(x, fpMul(x, x)), fpMul(B1, fpMul(z, fpMul(z, z))))) == 0
  };
  /// Subgroup check: `n*p == O`. Expensive (a full ~255-bit scalar multiplication) but
  /// necessary for any point taken from the wire (an invalid-curve/small-subgroup point that
  /// passed only the curve-equation check is a known attack) -- see `decompressG1`.
  public func g1InSubgroup(p : G1) : Bool { g1IsInf(g1Mul(p, C.R)) };

  // ============================================================================================
  // G2: projective points (X:Y:Z) over Fp2, curve y^2 = x^3 + 4*xi (xi = 1+u).
  public type G2 = (Fp2, Fp2, Fp2);
  // = f2MulXi((4,0)); a module-top-level `let` must be a static (literal) expression (M0014),
  // so the already-reduced value is written directly.
  let B2 : Fp2 = (4, 4);
  public let G2_GEN : G2 = ((C.G2_GEN_X0, C.G2_GEN_X1), (C.G2_GEN_Y0, C.G2_GEN_Y1), F2_ONE);
  public let G2_INF : G2 = (F2_ONE, F2_ONE, F2_ZERO);
  public func g2IsInf(p : G2) : Bool { f2IsZero(p.2) };
  public func g2Double(p : G2) : G2 {
    let (x, y, z) = p;
    let w = f2MulScalar(f2Mul(x, x), 3);
    let s = f2Mul(y, z);
    let b = f2Mul(x, f2Mul(y, s));
    let h = f2Sub(f2Mul(w, w), f2MulScalar(b, 8));
    let s2 = f2Mul(s, s);
    let nx = f2MulScalar(f2Mul(h, s), 2);
    let ny = f2Sub(f2Mul(w, f2Sub(f2MulScalar(b, 4), h)), f2MulScalar(f2Mul(f2Mul(y, y), s2), 8));
    let nz = f2MulScalar(f2Mul(s, s2), 8);
    (nx, ny, nz)
  };
  public func g2Add(p1 : G2, p2 : G2) : G2 {
    if (g2IsInf(p1)) { return p2 };
    if (g2IsInf(p2)) { return p1 };
    let (x1, y1, z1) = p1;
    let (x2, y2, z2) = p2;
    let u1 = f2Mul(y2, z1); let u2 = f2Mul(y1, z2);
    let v1 = f2Mul(x2, z1); let v2 = f2Mul(x1, z2);
    if (f2Eq(v1, v2) and f2Eq(u1, u2)) { return g2Double(p1) };
    if (f2Eq(v1, v2)) { return G2_INF };
    let u = f2Sub(u1, u2); let v = f2Sub(v1, v2);
    let v2s = f2Mul(v, v); let v2sv2 = f2Mul(v2s, v2); let v3 = f2Mul(v, v2s);
    let w = f2Mul(z1, z2);
    let a = f2Sub(f2Sub(f2Mul(f2Mul(u, u), w), v3), f2MulScalar(v2sv2, 2));
    let nx = f2Mul(v, a);
    let ny = f2Sub(f2Mul(u, f2Sub(v2sv2, a)), f2Mul(v3, u2));
    let nz = f2Mul(v3, w);
    (nx, ny, nz)
  };
  public func g2Neg(p : G2) : G2 { (p.0, f2Neg(p.1), p.2) };
  public func g2Mul(p : G2, n : Nat) : G2 {
    var r = G2_INF;
    var base = p;
    var e = n;
    while (e > 0) {
      if (e % 2 == 1) { r := g2Add(r, base) };
      base := g2Double(base);
      e := e / 2;
    };
    r
  };
  public func g2Affine(p : G2) : ?(Fp2, Fp2) {
    if (f2IsZero(p.2)) { return null };
    let zi = f2Inv(p.2);
    ?(f2Mul(p.0, zi), f2Mul(p.1, zi))
  };
  public func g2Eq(p1 : G2, p2 : G2) : Bool {
    if (g2IsInf(p1) or g2IsInf(p2)) { return g2IsInf(p1) == g2IsInf(p2) };
    f2Eq(f2Mul(p1.0, p2.2), f2Mul(p2.0, p1.2)) and f2Eq(f2Mul(p1.1, p2.2), f2Mul(p2.1, p1.2))
  };
  public func g2OnCurve(p : G2) : Bool {
    if (g2IsInf(p)) { return true };
    let (x, y, z) = p;
    f2Eq(f2Sub(f2Mul(f2Mul(y, y), z), f2Mul(x, f2Mul(x, x))), f2Mul(B2, f2Mul(z, f2Mul(z, z))))
  };
  /// Subgroup check via full-order scalar multiplication -- like `g1InSubgroup`, the slow but
  /// simple way (real implementations use the untwist-Frobenius-twist endomorphism instead;
  /// not done here, see the module comment on performance).
  public func g2InSubgroup(p : G2) : Bool { g2IsInf(g2Mul(p, C.R)) };

  // ============================================================================================
  // hash_to_curve for G1 (RFC 9380 section 8.8.1, ciphersuite BLS12381G1_XMD:SHA-256_SSWU_RO_):
  // expand_message_xmd -> hash_to_field (2 Fp elements) -> optimized SWU onto the 11-isogenous
  // curve -> the 11-isogeny map onto G1's actual curve -> add the two candidate points ->
  // clear the cofactor. Byte-identical to `py_ecc.bls.hash_to_curve.hash_to_G1` -- see the
  // module comment.
  func sha256(b : Blob) : Blob { Sha256.fromBlob(#sha256, b) };
  func natToBytesBE(n : Nat, len : Nat) : [Nat8] {
    let buf = Array.init<Nat8>(len, 0);
    var v = n;
    var i = len;
    while (i > 0) {
      i -= 1;
      buf[i] := Nat8.fromNat(v % 256);
      v := v / 256;
    };
    Array.freeze(buf)
  };
  func bytesToNat(bytes : [Nat8]) : Nat {
    var n : Nat = 0;
    for (b in bytes.values()) { n := n * 256 + Nat8.toNat(b) };
    n
  };
  func concatBytes(parts : [[Nat8]]) : [Nat8] {
    let buf = Buffer.Buffer<Nat8>(64);
    for (p in parts.values()) { for (x in p.values()) { buf.add(x) } };
    Buffer.toArray(buf)
  };
  func xorBytes(a : [Nat8], b : [Nat8]) : [Nat8] {
    Array.tabulate<Nat8>(a.size(), func(i) = a[i] ^ b[i])
  };
  /// RFC 9380 section 5.4.1, hash_function = SHA-256 (b_in_bytes=32, r_in_bytes=64).
  public func expandMessageXmd(msg : Blob, dst : Blob, lenInBytes : Nat) : [Nat8] {
    let bInBytes = 32;
    let rInBytes = 64;
    let dstBytes = Blob.toArray(dst);
    let dstPrime = concatBytes([dstBytes, [Nat8.fromNat(dstBytes.size())]]);
    let zPad = Array.tabulate<Nat8>(rInBytes, func(_) = 0);
    let lIBStr = natToBytesBE(lenInBytes, 2);
    let ell = if (lenInBytes % bInBytes == 0) { lenInBytes / bInBytes } else { lenInBytes / bInBytes + 1 };
    let b0 = Blob.toArray(sha256(Blob.fromArray(concatBytes([zPad, Blob.toArray(msg), lIBStr, [0], dstPrime]))));
    let bs = Buffer.Buffer<[Nat8]>(ell);
    bs.add(Blob.toArray(sha256(Blob.fromArray(concatBytes([b0, [1], dstPrime])))));
    var i = 2;
    while (i <= ell) {
      let prev = bs.get(bs.size() - 1);
      let xored = xorBytes(b0, prev);
      bs.add(Blob.toArray(sha256(Blob.fromArray(concatBytes([xored, [Nat8.fromNat(i)], dstPrime])))));
      i += 1;
    };
    let all = concatBytes(Buffer.toArray(bs));
    Array.tabulate<Nat8>(lenInBytes, func(j) = all[j])
  };
  let HASH_TO_FIELD_L = 64;
  func hashToFieldFp(msg : Blob, count : Nat, dst : Blob) : [Fp] {
    let prb = expandMessageXmd(msg, dst, count * HASH_TO_FIELD_L);
    Array.tabulate<Fp>(count, func(i) = bytesToNat(Array.tabulate<Nat8>(HASH_TO_FIELD_L, func(j) = prb[i * HASH_TO_FIELD_L + j])) % P)
  };
  func sqrtDivisionFp(u : Fp, v : Fp) : (Bool, Fp) {
    let temp = fpMul(u, v);
    let result = fpMul(temp, fpPow(fpMul(temp, fpMul(v, v)), C.P_MINUS_3_DIV_4));
    (fpSub(fpMul(fpMul(result, result), v), u) == 0, result)
  };
  func optimizedSwuG1(t : Fp) : (Fp, Fp, Fp) {
    let t2 = fpMul(t, t);
    let isoZT2 = fpMul(C.ISO_11_Z, t2);
    let temp0 = fpAdd(isoZT2, fpMul(isoZT2, isoZT2));
    var denominator = fpNeg(fpMul(C.ISO_11_A, temp0));
    let numerator0 = fpMul(C.ISO_11_B, fpAdd(temp0, 1));
    if (denominator == 0) { denominator := fpMul(C.ISO_11_Z, C.ISO_11_A) };
    let v = fpPow(denominator, 3);
    let u = fpAdd(fpAdd(fpPow(numerator0, 3), fpMul(C.ISO_11_A, fpMul(numerator0, fpMul(denominator, denominator)))), fpMul(C.ISO_11_B, v));
    let (isRoot, y0) = sqrtDivisionFp(u, v);
    var y = y0;
    var numerator = numerator0;
    if (not isRoot) {
      y := fpMul(fpMul(y, fpPow(t, 3)), C.SQRT_MINUS_11_CUBED);
      numerator := fpMul(numerator, isoZT2);
    };
    if (sgn0(t) != sgn0(y)) { y := fpNeg(y) };
    y := fpMul(y, denominator);
    (numerator, y, denominator)
  };
  func isoMapG1(x : Fp, y : Fp, z : Fp) : G1 {
    let zpow = Array.init<Fp>(15, 0);
    zpow[0] := z;
    var k = 1;
    while (k < 15) { zpow[k] := fpMul(zpow[k - 1], z); k += 1 };
    func horner(ks : [Fp]) : Fp {
      let n = ks.size();
      if (n >= 2) {
        // `Nat.sub`, not the bare `-` operator: Motoko's M0155 flow typing does not derive
        // `n-1>=0`/`n-2>=0` from the `n>=2` guard just above (tried; still flagged both ways),
        // and `Nat.sub` moves the "may trap" reasoning behind a function call the checker
        // does not re-flag at the call site -- both are safe here, proven by `n>=2`.
        let last = Nat.sub(n, 1);
        var acc = ks[last];
        // Walk coefficients ks[n-2] downTo ks[0] while the matching z-power walks the OTHER
        // way, zpow[0] upTo zpow[n-2] (py_ecc's `iso_map_G1`: `enumerate(reversed(ks[:-1]))`
        // pairs its 0-based ITERATION COUNTER, not the coefficient's own array index, with
        // `z_powers`) -- `j` and `zi` are deliberately two separate counters moving in
        // opposite directions; collapsing them into one (using `ks[j]` with `zpow[j]`) is a
        // bug that happened here once and produced a wrong `hashToCurveG1` with no type error
        // to catch it, only a KAT mismatch (`test/BlsVectors.mo`, "hash_to_curve_g1" cases).
        var j = Nat.sub(last, 1);
        var zi = 0;
        loop {
          acc := fpAdd(fpMul(acc, x), fpMul(zpow[zi], ks[j]));
          if (j == 0) { return acc };
          j -= 1;
          zi += 1;
        };
      };
      Debug.trap("isoMapG1: a degenerate (size<2) coefficient list is a bug, not input")
    };
    let m0 = horner(C.ISO_11_X_NUMERATOR);
    var m1 = horner(C.ISO_11_X_DENOMINATOR);
    var m2 = horner(C.ISO_11_Y_NUMERATOR);
    var m3 = horner(C.ISO_11_Y_DENOMINATOR);
    m1 := fpMul(m1, z);
    m2 := fpMul(m2, y);
    m3 := fpMul(m3, z);
    (fpMul(m0, m3), fpMul(m1, m2), fpMul(m1, m3))
  };
  func mapToCurveG1(u : Fp) : G1 {
    let (x, y, z) = optimizedSwuG1(u);
    isoMapG1(x, y, z)
  };
  func clearCofactorG1(p : G1) : G1 { g1Mul(p, C.H_EFF_G1) };
  /// `msg` here is already the DOMAIN-SEPARATED IC message (`domain_sep("ic-state-root") ‖
  /// root_hash(tree)`, computed by `Certificate.mo`); `dst` is the hash-to-curve ciphersuite
  /// string, NOT the IC's own domain separator -- the two domain-separation mechanisms are
  /// independent layers of the same scheme (RFC 9380's DST vs the IC's `domain_sep`).
  public func hashToCurveG1(msg : Blob, dst : Blob) : G1 {
    let us = hashToFieldFp(msg, 2, dst);
    let q0 = mapToCurveG1(us[0]);
    let q1 = mapToCurveG1(us[1]);
    clearCofactorG1(g1Add(q0, q1))
  };

  // ============================================================================================
  // Pairing e : G1 x G2 -> Fp12*. R is kept in Fp2 for the point doublings/additions but the
  // Miller-loop LINE EVALUATIONS are computed by embedding both P and (twisted) Q into Fp12
  // and reusing the plain projective add/double formulas there (mirroring
  // `py_ecc.optimized_bls12_381.optimized_pairing`'s generic, field-agnostic approach) --
  // slower than the sparse-multiplication tricks a hand-tuned pairing uses (an M-type/D-type
  // twist lets you keep R's doublings in Fp2 and lift only the sparse line VALUE to Fp12), but
  // it removes an entire class of twist-sign/sparse-formula bugs the differential oracle can't
  // directly catch (see the module comment, strategy 2). That tradeoff is deliberate for a
  // first cut; the sparse formulas are a concrete, well-scoped speedup for whoever follows up.
  let W_K0 : Nat = C.W_K0;
  let W_K1 : Nat = C.W_K1;
  /// w^-2, w^-3 in the Fp12 tower (w^2=v, w^6=xi) -- fixed constants (independent of any
  /// input), so computed once here from `W_K0`/`W_K1` rather than via a runtime `f12Inv(w)`
  /// (same values, confirmed against `f12Inv(w)` -- itself `w^-1 = (0, (0,0,(W_K0,W_K1)))` --
  /// in the Python prototype this was ported from).
  let W_INV2 : Fp12 = ((F2_ZERO, F2_ZERO, (W_K0, W_K1)), F6_ZERO);
  let W_INV3 : Fp12 = (F6_ZERO, (F2_ZERO, (W_K0, W_K1), F2_ZERO));
  func castG1ToFp12(p : G1) : (Fp12, Fp12, Fp12) { (fpToF12(p.0), fpToF12(p.1), fpToF12(p.2)) };
  /// D-type sextic twist: E'(Fp2): y^2=x^3+4*xi maps to E(Fp12): y^2=x^3+4 via x=x'/w^2, y=y'/w^3
  /// (checked against `is_on_curve` in the Python prototype: both G1 and the twisted G2 land
  /// on the SAME curve y^2=x^3+4 over Fp12, which is what makes `linefunc`/`fp12Double`/
  /// `fp12Add` below -- ordinary, field-agnostic elliptic-curve formulas -- applicable to both).
  func twistG2ToFp12(p : G2) : (Fp12, Fp12, Fp12) {
    (f12Mul(f2ToF12(p.0), W_INV2), f12Mul(f2ToF12(p.1), W_INV3), f2ToF12(p.2))
  };
  func fp12Double(p : (Fp12, Fp12, Fp12)) : (Fp12, Fp12, Fp12) {
    let (x, y, z) = p;
    let w = f12Muls(f12Mul(x, x), 3);
    let s = f12Mul(y, z);
    let b = f12Mul(x, f12Mul(y, s));
    let h = f12Sub(f12Mul(w, w), f12Muls(b, 8));
    let s2 = f12Mul(s, s);
    let nx = f12Muls(f12Mul(h, s), 2);
    let ny = f12Sub(f12Mul(w, f12Sub(f12Muls(b, 4), h)), f12Muls(f12Mul(f12Mul(y, y), s2), 8));
    let nz = f12Muls(f12Mul(s, s2), 8);
    (nx, ny, nz)
  };
  func fp12PointIsInf(p : (Fp12, Fp12, Fp12)) : Bool { f6IsZero(p.2.0) and f6IsZero(p.2.1) };
  func fp12Add(p1 : (Fp12, Fp12, Fp12), p2 : (Fp12, Fp12, Fp12)) : (Fp12, Fp12, Fp12) {
    if (fp12PointIsInf(p1)) { return p2 };
    if (fp12PointIsInf(p2)) { return p1 };
    let (x1, y1, z1) = p1;
    let (x2, y2, z2) = p2;
    let u1 = f12Mul(y2, z1); let u2 = f12Mul(y1, z2);
    let v1 = f12Mul(x2, z1); let v2 = f12Mul(x1, z2);
    if (f12Eq(v1, v2) and f12Eq(u1, u2)) { return fp12Double(p1) };
    if (f12Eq(v1, v2)) { return (F12_ONE, F12_ONE, F12_ZERO) };
    let u = f12Sub(u1, u2); let v = f12Sub(v1, v2);
    let v2s = f12Mul(v, v); let v2sv2 = f12Mul(v2s, v2); let v3 = f12Mul(v, v2s);
    let w = f12Mul(z1, z2);
    let a = f12Sub(f12Sub(f12Mul(f12Mul(u, u), w), v3), f12Muls(v2sv2, 2));
    let nx = f12Mul(v, a);
    let ny = f12Sub(f12Mul(u, f12Sub(v2sv2, a)), f12Mul(v3, u2));
    let nz = f12Mul(v3, w);
    (nx, ny, nz)
  };
  /// The line through P1,P2 (or the tangent at P1 when P1==P2) evaluated at T, kept as a
  /// (numerator, denominator) pair to avoid a per-iteration Fp12 division (`py_ecc`'s
  /// `linefunc`) -- the Miller loop divides ONCE, at the very end.
  func lineFunc(p1 : (Fp12, Fp12, Fp12), p2 : (Fp12, Fp12, Fp12), t : (Fp12, Fp12, Fp12)) : (Fp12, Fp12) {
    let (x1, y1, z1) = p1; let (x2, y2, z2) = p2; let (xt, yt, zt) = t;
    let mNum = f12Sub(f12Mul(y2, z1), f12Mul(y1, z2));
    let mDen = f12Sub(f12Mul(x2, z1), f12Mul(x1, z2));
    if (not f12Eq(mDen, F12_ZERO)) {
      return (
        f12Sub(f12Mul(mNum, f12Sub(f12Mul(xt, z1), f12Mul(x1, zt))), f12Mul(mDen, f12Sub(f12Mul(yt, z1), f12Mul(y1, zt)))),
        f12Mul(f12Mul(mDen, zt), z1),
      );
    };
    if (f12Eq(mNum, F12_ZERO)) {
      let mNum2 = f12Muls(f12Mul(x1, x1), 3);
      let mDen2 = f12Muls(f12Mul(y1, z1), 2);
      return (
        f12Sub(f12Mul(mNum2, f12Sub(f12Mul(xt, z1), f12Mul(x1, zt))), f12Mul(mDen2, f12Sub(f12Mul(yt, z1), f12Mul(y1, zt)))),
        f12Mul(f12Mul(mDen2, zt), z1),
      );
    };
    (f12Sub(f12Mul(xt, z1), f12Mul(x1, zt)), f12Mul(z1, zt))
  };
  /// |BLS parameter|'s pseudo-binary encoding, MSB-1 down to bit 0 (`ate_loop_count =
  /// 15132376222941642752 = 0xd201000000010000`) -- copied verbatim from
  /// `py_ecc.optimized_bls12_381.optimized_pairing` (a fixed public constant of the curve, not
  /// derived here).
  /// Miller loop (`Q` a G2 point, `P` a G1 point) producing the un-exponentiated pairing
  /// value; `pairing` below applies the final exponentiation.
  public func millerLoop(q : G2, p : G1) : Fp12 {
    if (g1IsInf(p) or g2IsInf(q)) { return F12_ONE };
    let castP = castG1ToFp12(p);
    let twistQ = twistG2ToFp12(q);
    var r = twistQ;
    var fNum = F12_ONE;
    var fDen = F12_ONE;
    var i = 62;
    loop {
      let (n0, d0) = lineFunc(r, r, castP);
      fNum := f12Mul(f12Mul(fNum, fNum), n0);
      fDen := f12Mul(f12Mul(fDen, fDen), d0);
      r := fp12Double(r);
      if (C.PSEUDO_BINARY[i] == 1) {
        let (n1, d1) = lineFunc(r, twistQ, castP);
        fNum := f12Mul(fNum, n1);
        fDen := f12Mul(fDen, d1);
        r := fp12Add(r, twistQ);
      };
      if (i == 0) { return f12Div(fNum, fDen) };
      i -= 1;
    };
  };
  public func pairing(q : G2, p : G1) : Fp12 { f12Pow(millerLoop(q, p), C.FINAL_EXP) };

  // ============================================================================================
  // Point (de)compression: the zcash/IETF BLS12-381 serialization the IC's certificates use
  // (interface spec cites it directly). Byte-identical to `py_ecc.bls.point_compression` both
  // ways -- see the module comment.
  let POW_2_381 : Nat = C.POW_2_381;
  let POW_2_382 : Nat = C.POW_2_382;
  let POW_2_383 : Nat = C.POW_2_383;
  func flagBit(z : Nat, pow2 : Nat) : Nat { (z / pow2) % 2 };
  public func compressG1(p : G1) : Blob {
    if (g1IsInf(p)) { return Blob.fromArray(natToBytesBE(POW_2_383 + POW_2_382, 48)) };
    let ?(x, y) = g1Affine(p) else { Debug.trap("compressG1: unreachable, p is not infinity") };
    let aFlag = (y * 2) / P;
    Blob.fromArray(natToBytesBE(x + aFlag * POW_2_381 + POW_2_383, 48))
  };
  /// Decompresses AND validates: on-curve, then (deliberately -- see `g1InSubgroup`) checks
  /// the point is in the prime-order subgroup, since a signature is attacker-controlled wire
  /// data (a small-subgroup / invalid-curve point that only satisfies the curve equation is a
  /// known forgery vector against pairing verification).
  public func decompressG1(b : Blob) : ?G1 {
    if (b.size() != 48) { return null };
    let z = bytesToNat(Blob.toArray(b));
    let cFlag = flagBit(z, POW_2_383);
    let bFlag = flagBit(z, POW_2_382);
    let aFlag = flagBit(z, POW_2_381);
    if (cFlag != 1) { return null };
    let x = z % POW_2_381;
    if (bFlag == 1) {
      if (aFlag == 1 or x != 0) { return null };
      return ?G1_INF;
    };
    if (x >= P) { return null };
    let rhs = (fpMul(fpMul(x, x), x) + B1) % P;
    let y0 = fpSqrtCandidate(rhs);
    if (fpMul(y0, y0) != rhs) { return null };
    let y = if ((y0 * 2) / P != aFlag) { fpNeg(y0) } else { y0 };
    let pt = (x, y, 1);
    if (not g1OnCurve(pt)) { return null };
    if (not g1InSubgroup(pt)) { return null };
    ?pt
  };
  /// Fp2 square root via the "eighth roots of unity" method (needed because P^2 % 16 != 9 the
  /// way P%4==3 gives a direct Fp formula): candidate = a^((P^2+7)/16); if
  /// `candidate^2/a` is one of the four EVEN eighth roots of unity, dividing by the matching
  /// root recovers a genuine square root. Matches `py_ecc.bls.point_compression
  /// .modular_squareroot_in_FQ2` (including its tie-break: prefer the root with the larger
  /// imaginary part, then the larger real part, so compression/decompression round-trip on a
  /// single canonical choice).
  func f2SqrtDecompress(a : Fp2) : ?Fp2 {
    if (f2IsZero(a)) { return ?F2_ZERO };
    let fq2Order = P * P - 1 : Nat; // exact multiple of 16 for BLS12-381's P (as py_ecc relies on)
    let cand = f2Pow(a, (fq2Order + 8) / 16);
    let check = f2Div(f2Mul(cand, cand), a);
    var i = 0;
    while (i < 4) {
      let root = C.EIGHTH_ROOTS[i * 2];
      if (f2Eq(check, root)) {
        let halfRoot = C.EIGHTH_ROOTS[i];
        let x1 = f2Div(cand, halfRoot);
        let x2 = f2Neg(x1);
        return ?(if (x1.1 > x2.1 or (x1.1 == x2.1 and x1.0 > x2.0)) { x1 } else { x2 });
      };
      i += 1;
    };
    null
  };
  public func compressG2(p : G2) : Blob {
    if (g2IsInf(p)) {
      return Blob.fromArray(concatBytes([natToBytesBE(POW_2_383 + POW_2_382, 48), natToBytesBE(0, 48)]));
    };
    let ?(x, y) = g2Affine(p) else { Debug.trap("compressG2: unreachable, p is not infinity") };
    let aFlag = if (y.1 > 0) { (y.1 * 2) / P } else { (y.0 * 2) / P };
    let z1 = x.1 + aFlag * POW_2_381 + POW_2_383;
    Blob.fromArray(concatBytes([natToBytesBE(z1, 48), natToBytesBE(x.0, 48)]))
  };
  /// See `decompressG1` on why a subgroup check is included -- for G2 the point is either a
  /// root/subnet key (fetched once, cached) or part of a delegation certificate, still
  /// untrusted wire data the first time it is seen.
  public func decompressG2(b : Blob) : ?G2 {
    if (b.size() != 96) { return null };
    let bytes = Blob.toArray(b);
    let z1 = bytesToNat(Array.tabulate<Nat8>(48, func(i) = bytes[i]));
    let z2 = bytesToNat(Array.tabulate<Nat8>(48, func(i) = bytes[48 + i]));
    let cFlag = flagBit(z1, POW_2_383);
    let bFlag = flagBit(z1, POW_2_382);
    let aFlag = flagBit(z1, POW_2_381);
    if (cFlag != 1) { return null };
    let x1 = z1 % POW_2_381;
    if (bFlag == 1) {
      if (aFlag == 1 or x1 != 0 or z2 != 0) { return null };
      return ?G2_INF;
    };
    if (x1 >= P or z2 >= P) { return null };
    let x : Fp2 = (z2, x1);
    let rhs = f2Add(f2Mul(x, f2Mul(x, x)), B2);
    let ?y0 = f2SqrtDecompress(rhs) else { return null };
    let cur = if (y0.1 > 0) { (y0.1 * 2) / P } else { (y0.0 * 2) / P };
    let y = if (cur != aFlag) { f2Neg(y0) } else { y0 };
    let pt : G2 = (x, y, F2_ONE);
    if (not g2OnCurve(pt)) { return null };
    if (not g2InSubgroup(pt)) { return null };
    ?pt
  };

  // ============================================================================================
  // The public API: min_sig BLS verification. `dst` defaults to the ciphersuite the IC uses
  // for state-root certification; exposed as a parameter (not hardcoded) so the KATs in
  // `test/BlsVectors.mo` can exercise other DSTs too.
  public let IC_DST : Blob = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
  /// `pk96`/`sig48` are the COMPRESSED wire bytes (96-byte G2 public key, 48-byte G1
  /// signature); `msg` is the domain-separated message that was signed (for the IC,
  /// `domain_sep("ic-state-root") ‖ root_hash(tree)` -- `Certificate.mo` builds this).
  /// Returns `false` on any malformed input (wrong length, off-curve, wrong subgroup) as well
  /// as on a genuinely bad signature; callers that need to tell those apart should call
  /// `decompressG1`/`decompressG2` themselves first.
  public func verify(pk96 : Blob, sig48 : Blob, msg : Blob, dst : Blob) : Bool {
    let ?pk = decompressG2(pk96) else { return false };
    let ?sig = decompressG1(sig48) else { return false };
    let hm = hashToCurveG1(msg, dst);
    f12Eq(pairing(G2_GEN, sig), pairing(pk, hm))
  };
}

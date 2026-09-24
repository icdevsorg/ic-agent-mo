/// BLS12-381 signature verification for the IC's "min_sig" certification scheme (interface
/// spec, "Certification"): public keys are 96-byte compressed G2 points, signatures are
/// 48-byte compressed G1 points, and `verify(pk, sig, msg) = e(sig, g2) == e(H(msg), pk)`
/// where `H` is the RFC 9380 hash-to-curve map for G1, ciphersuite
/// `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`.
///
/// == The pivot (2026-09-24): delegate the curve/pairing to `mo:bls12-381` ==
/// alpha-7 G2 shipped a from-scratch pure-Motoko tower/pairing here (naive final
/// exponentiation, no sparse Miller loop): correct (validated against `py_ecc`) but ~55-61
/// billion wasm instructions per `verify` -- see the git history of this file and
/// `README.md`'s old "Certificate verification cost" table for exactly what that cost. ICDevs
/// already has a second, independently-built, EIP-2537-grade implementation --
/// `icdevsorg/bls12-381.mo` (mops name `bls12-381`; used by `evm.mo`'s precompiles) -- with an
/// optimal-ate Miller loop, NAF scalar recoding, sparse line evaluation, Granger-Scott
/// cyclotomic squaring in the final exponentiation, and the psi-endomorphism subgroup checks.
/// Maintaining two field-tower/pairing implementations in this monorepo for the same curve is
/// a liability (a fix to one silently leaves the other's bugs standing), so this file now
/// DELEGATES: `mo:bls12-381` supplies every field/curve/pairing primitive, and this file keeps
/// only the two pieces that library does not provide and that `Certificate.mo` needs --
/// RFC 9380 `expand_message_xmd`/hash-to-field (below) and 96-byte compressed G2 decompression
/// (`decompressG2`; the library only decodes G1's compressed and G1/G2's EIP-2537 uncompressed
/// formats, not the Zcash-format compressed G2 the IC's certificates carry).
/// Before/after cost, measured via `scripts/ic_agent_gate.sh`'s cost step (`MOXZI_FUEL=1`):
/// `README.md`, "Certificate verification cost".
///
/// == Differential oracle (P3), what changed and what didn't ==
/// `expandMessageXmd`/`hashToFieldFp`/`hashToCurveG1` are UNCHANGED from the from-scratch
/// version (still this file's own code): they matched `py_ecc.bls.hash_to_curve.hash_to_G1`
/// byte-identically before, and still do -- `hashToCurveG1` now composes
/// `BLS.map_fp_to_g1` (EIP-2537's `MAP_FP_TO_G1`: SWU + 11-isogeny + cofactor clearing) over
/// each of the two hash-to-field outputs and adds the results; cofactor clearing is scalar
/// multiplication, which distributes over group addition, so
/// `map_fp_to_g1(u0) + map_fp_to_g1(u1) == clear_cofactor(map(u0) + map(u1))` -- clearing per
/// term and then adding is the SAME point as RFC 9380's "add then clear once", not an
/// approximation of it. `decompressG2` is UNCHANGED in structure (same Zcash-format flag
/// parsing, same eighth-roots-adjacent sign fix-up) but now calls `BLS.fp2_sqrt` (a different
/// algorithm than the old `f2SqrtDecompress`) for the square root: this is safe because the
/// sign fix-up picks between `y0` and `-y0` itself afterwards, so it does not matter which of
/// the two square roots the library returns first. `verify`'s pairing equation is now the
/// library's own `pairing_check` (one shared final exponentiation over a two-term Miller
/// loop) instead of two separate `pairing` calls -- see `verify`'s comment for the exact
/// bilinearity rewrite. `test/BlsVectors.mo` carries the KATs (hash-to-curve against `py_ecc`,
/// G2 decompression round-trips and rejections, and full sign/verify against a
/// `py_ecc`-composed signature -- the library's own correctness is that package's concern,
/// covered by ITS OWN test/bench suite, not re-proven here).
import BLS "mo:bls12-381";
import C "BlsConstants";
import Sha256 "mo:sha2/Sha256";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";

module {
  let P : Nat = BLS.P;

  // ============================================================================================
  // hash_to_curve for G1 (RFC 9380 section 8.8.1, ciphersuite BLS12381G1_XMD:SHA-256_SSWU_RO_):
  // expand_message_xmd -> hash_to_field (2 Fp elements) -> `BLS.map_fp_to_g1` (SWU + 11-isogeny
  // + cofactor clearing, EIP-2537's MAP_FP_TO_G1) -> add the two mapped points. Byte-identical
  // to `py_ecc.bls.hash_to_curve.hash_to_G1` -- see the module comment.
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
  func hashToFieldFp(msg : Blob, count : Nat, dst : Blob) : [Nat] {
    let prb = expandMessageXmd(msg, dst, count * HASH_TO_FIELD_L);
    Array.tabulate<Nat>(count, func(i) = bytesToNat(Array.tabulate<Nat8>(HASH_TO_FIELD_L, func(j) = prb[i * HASH_TO_FIELD_L + j])) % P)
  };
  /// `msg` here is already the DOMAIN-SEPARATED IC message (`domain_sep("ic-state-root") ‖
  /// root_hash(tree)`, computed by `Certificate.mo`); `dst` is the hash-to-curve ciphersuite
  /// string, NOT the IC's own domain separator -- the two domain-separation mechanisms are
  /// independent layers of the same scheme (RFC 9380's DST vs the IC's `domain_sep`).
  public func hashToCurveG1(msg : Blob, dst : Blob) : BLS.G1Point {
    let us = hashToFieldFp(msg, 2, dst);
    BLS.g1_add(BLS.map_fp_to_g1(us[0]), BLS.map_fp_to_g1(us[1]))
  };

  // ============================================================================================
  // G2 point (de)compression: the Zcash/IETF BLS12-381 serialization the IC's certificates use
  // (interface spec cites it directly). `mo:bls12-381` decodes G1's compressed format
  // (`BLS.decompress_g1`, EIP-4844's KZG format -- same Zcash convention) and both curves'
  // EIP-2537 UNCOMPRESSED formats, but not compressed G2 (EIP-2537 has no compressed-G2
  // precompile input), so this file still owns it -- same flag layout/sign fix-up as the old
  // from-scratch version, now built on `BLS.fp2_sqrt`/`BLS.g2_from_affine` (which also runs the
  // on-curve check)/`BLS.g2_subgroup_check` instead of hand-rolled Fp2 arithmetic.
  let POW_2_381 : Nat = C.POW_2_381;
  let POW_2_382 : Nat = C.POW_2_382;
  let POW_2_383 : Nat = C.POW_2_383;
  func flagBit(z : Nat, pow2 : Nat) : Nat { (z / pow2) % 2 };
  // = fp2_mul_nr((4,0)); a module-top-level `let` must be a static (literal) expression
  // (M0014), so the already-reduced curve constant B2 = 4*(1+u) is written directly.
  let B2 : BLS.Fp2 = (4, 4);
  /// See `BLS.g1_subgroup_check`'s caller in `verify` for why a subgroup check is included --
  /// for G2 the point is either a root/subnet key (fetched once, cached) or part of a
  /// delegation certificate, still untrusted wire data the first time it is seen (a
  /// small-subgroup/invalid-curve point that only satisfies the curve equation is a known
  /// forgery vector against pairing verification).
  public func decompressG2(b : Blob) : ?BLS.G2Point {
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
      return ?BLS.G2_INF;
    };
    if (x1 >= P or z2 >= P) { return null };
    let x : BLS.Fp2 = (z2, x1);
    let rhs = BLS.fp2_add(BLS.fp2_mul(BLS.fp2_sq(x), x), B2);
    let ?y0 = BLS.fp2_sqrt(rhs) else { return null };
    let cur = if (y0.1 > 0) { (y0.1 * 2) / P } else { (y0.0 * 2) / P };
    let y = if (cur != aFlag) { BLS.fp2_neg(y0) } else { y0 };
    let ?pt = BLS.g2_from_affine(x, y) else { return null };
    if (not BLS.g2_subgroup_check(pt)) { return null };
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
  /// `decompressG2`/`BLS.decompress_g1` themselves first.
  ///
  /// The check is `e(sig, g2) == e(H(msg), pk)`. Rewritten as a single product with one shared
  /// final exponentiation: `e(sig, g2) * e(H(msg), pk)^-1 == 1`, and `e(P,-Q) == e(P,Q)^-1`
  /// (bilinearity), so `e(sig, -g2) * e(H(msg), pk) == 1` -- exactly
  /// `BLS.pairing_check([(sig, -g2), (H(msg), pk)])`. `BLS.pairing_check`'s pair order is
  /// `(G1Point, G2Point)` per term (EIP-2537's `PAIRING_CHECK` convention); the "iterated"
  /// argument the Miller loop doubles is the G2 element in both terms, matching the original
  /// `e(g2, sig) == e(pk, H(msg))` role assignment.
  public func verify(pk96 : Blob, sig48 : Blob, msg : Blob, dst : Blob) : Bool {
    let ?pk = decompressG2(pk96) else { return false };
    let ?sig = BLS.decompress_g1(Blob.toArray(sig48)) else { return false };
    if (not BLS.g1_subgroup_check(sig)) { return false };
    let hm = hashToCurveG1(msg, dst);
    BLS.pairing_check([(sig, BLS.g2_neg(BLS.G2_GEN)), (hm, pk)])
  };
}

/// Known-answer tests for `Bls12381.mo` after its 2026-09-24 pivot to delegate the field
/// tower/curve/pairing to `mo:bls12-381` (see `Bls12381.mo`'s module comment for why). What
/// this file still tests, and why:
///  - `hashToCurveG1`: still OUR code (RFC 9380 `expand_message_xmd`/hash-to-field, then
///    `BLS.map_fp_to_g1` + `g1_add`) -- byte-identical to `py_ecc.bls.hash_to_curve.hash_to_G1`,
///    same vectors as before the pivot.
///  - `decompressG2`: still OUR code (the library has no compressed-G2 decoder). A round trip
///    against a `py_ecc`-computed point, a structural rejection (truncated blob), and --
///    NEW -- a rejection of a point that is ON the curve but NOT in the order-r subgroup (an
///    `optimized_swu_G2`/`iso_map_G2` output taken straight from `py_ecc` before cofactor
///    clearing, confirmed off-subgroup there via `multiply(pt, curve_order) != infinity`,
///    then hand-compressed with the same Zcash flag/sign encoding `decompressG2` expects): this
///    is the attack `BLS.g2_subgroup_check` exists to stop, so it needs its own KAT, not just a
///    "some bytes are rejected" smoke test.
///  - `verify`: the decisive, library-and-our-code end-to-end check -- a real `py_ecc`-composed
///    signature (`sk` random, `pk = sk*g2`, `sig = sk*H(msg)`, py_ecc's own G1/G2 multiply, not
///    this package's) must verify, and four corruptions (bad signature, wrong key, wrong
///    message, malformed bytes) must not -- unchanged from before the pivot, and the check that
///    matters most: it fails if the `pairing_check` argument order/sign rewrite in `verify`'s
///    module comment is wrong in any way `hashToCurveG1`/`decompressG2` alone would not catch.
///  - one direct bilinearity check against `BLS.pairing_check` (`e(7G1,11G2) == e(G1,G2)^77`,
///    read off as `e(7G1,11G2) * e(G1,-77G2) == 1`): confirms THIS package's pair-order/sign
///    convention independent of `verify`'s specific rewrite, defense in depth for a wiring bug
///    swapping G1/G2 roles. Deeper pairing correctness (Miller loop, sparse lines, cyclotomic
///    final exponentiation) is the `bls12-381` package's own concern, covered by its own
///    test/bench suite (`.bench/bls12_381.bench.json` et al.) -- not re-proven here.
///
/// `check()` traps on the first failure (so a build that silently regresses one layer fails
/// loudly), and returns the count -- moxzi and moc must agree on it (`scripts/ic_agent_gate.sh`,
/// same pattern as `Vectors.mo`).
///
/// `costOneVerify()`/`costMillerLoopOnly()`/`costOnePairing()`/`costFpMul()` measure wasm
/// instructions via `ExperimentalInternetComputer.countInstructions` -- real counts only under
/// `MOXZI_FUEL=1` (`moxzi/runtime/src/machine.rs`'s `fuel_metering`); the gate records what it
/// saw (`README.md`, "Certificate verification cost").
import Bls "../src/Bls12381";
import BLS "mo:bls12-381";
import Hash "../src/Hash";
import IC "mo:base/ExperimentalInternetComputer";
import Debug "mo:base/Debug";
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";

persistent actor {
  var passed = 0;
  func expect(name : Text, ok : Bool) { if (ok) { passed += 1 } else { Debug.trap("FAIL: " # name) } };
  func hex(t : Text) : Blob = switch (Hash.fromHex(t)) { case (?b) b; case null Debug.trap("bad hex " # t) };
  /// A hex string parsed as a big-endian Nat (the KATs below carry field elements this way).
  func natHex(t : Text) : Nat {
    var n : Nat = 0;
    for (b in hex(t).values()) { n := n * 256 + Nat8.toNat(b) };
    n
  };

  public func check() : async Nat {
    passed := 0;

    // ---- hash_to_curve_g1, byte-identical to py_ecc's hash_to_G1 (RFC 9380) ----
    let (ax1, ay1) = BLS.g1_to_affine(Bls.hashToCurveG1("", Bls.IC_DST));
    expect("hash_to_curve_g1(\"\").x", ax1 == natHex("12e0e662181bd9f8cd8ef246071357cd07a23c4391e879b49e32084dcc1a2aede123c8e8bfcde92edac229e28b719142"));
    expect("hash_to_curve_g1(\"\").y", ay1 == natHex("0d568a0595f7e9620fd05bb0494fe782ab2bfb1c588edf404326a9d074c2a4b2d43ea2d4c8253eb1ce1ad7b70be521d8"));
    let (ax2, ay2) = BLS.g1_to_affine(Bls.hashToCurveG1("abc", Bls.IC_DST));
    expect("hash_to_curve_g1(\"abc\").x", ax2 == natHex("0ab1bfed57bef131b205541860254dd546a592eaa86da31f3128792be5e0a7a823cb6e7f5e4b82e2e0cfc84ef82f5cdb"));
    expect("hash_to_curve_g1(\"abc\").y", ay2 == natHex("063f4d009639ed31def6d3a5d8688b1bb9ebf75fc85ad41f4e22eda9730fdf84b2917e02b15e850e7536e938bb73d61c"));
    let icMsg = hex("69632d73746174652d726f6f742d746573742d6d657373616765");
    let (ax3, ay3) = BLS.g1_to_affine(Bls.hashToCurveG1(icMsg, Bls.IC_DST));
    expect("hash_to_curve_g1(ic-msg).x", ax3 == natHex("10f9d5fb92474fec1354fa173cbf4d3a96566afd74dfb46de7d2cc1b039b4082e054961d939f38972f31bc7f0785abed"));
    expect("hash_to_curve_g1(ic-msg).y", ay3 == natHex("186d4c2ec34aab38d8c0a5fb5a90fd9c5f729db63f753d6faa5a6c3912593e03e78988ba936a2ca192355dd4460ca695"));

    // ---- decompressG2: round trip against a py_ecc point (12345*G2, compressed by hand with
    // the same Zcash flag/sign encoding decompressG2 expects) ----
    let g2Compressed = hex("849d5b3d40fe475b145eebf53d97981bde5a64dea2964807f82561e709e804fee3ecfb5356631b2dedbe82d3d1dad0bb037ece3ecc512226a1e56fbe0b33aab2080ab467d14aadeff5dcd8adc6613b926bc97601a4a1f1287793757b10d68a93");
    let ?g2Pt = Bls.decompressG2(g2Compressed) else { Debug.trap("decompressG2: 12345*G2 rejected") };
    let (g2x, g2y) = BLS.g2_to_affine(g2Pt);
    expect("decompressG2(12345*g2).x0", g2x.0 == 537981225545542963425487820538681006031270350819931841776188481854991512710445805907224339759290391174516449905299);
    expect("decompressG2(12345*g2).x1", g2x.1 == 710263249623297945205677832422879367136859122336617013558836430937587842487752548203453568692909410481089040535739);
    expect("decompressG2(12345*g2).y0", g2y.0 == 711110997734620889999929504948450308326434586997819988962419007364906703059928021844346255898626197228750480567836);
    expect("decompressG2(12345*g2).y1", g2y.1 == 337049862749186367114588866279510224796235667392273765458486416725286123997827520576860003372467871782936277490523);
    expect("decompressG2 rejects a truncated blob", Bls.decompressG2("\00") == null);
    // On the curve E'(Fp2) (satisfies y^2=x^3+4(1+u)) but NOT in the order-r subgroup: an
    // optimized_swu_G2/iso_map_G2 output taken straight from py_ecc BEFORE cofactor clearing,
    // hand-compressed the same way -- this is exactly the forgery shape g2_subgroup_check
    // exists to reject (see the module comment).
    let g2OffSubgroup = hex("a9460979c8f35e05d799899f69a49b1824d955cbfebfb1a56981cc663da960315ba14ee82b358eadf29ce08b7309fc33078a6ed9b0efd85768585a49e33565282839dc89601b79e976fc10fadbb0a4cd75f78e8c0b51205ad51e8d15fd6fcc92");
    expect("decompressG2 rejects an on-curve, off-subgroup point", Bls.decompressG2(g2OffSubgroup) == null);

    // ---- one direct bilinearity check against BLS.pairing_check (defense in depth for this
    // package's own pair-order/sign wiring, independent of verify's specific rewrite -- see
    // the module comment) ----
    let p7 = BLS.g1_mul(BLS.G1_GEN, 7);
    let q11 = BLS.g2_mul(BLS.G2_GEN, 11);
    let q77neg = BLS.g2_neg(BLS.g2_mul(BLS.G2_GEN, 77));
    expect("bilinearity: e(7G1,11G2) * e(G1,-77G2) == 1", BLS.pairing_check([(p7, q11), (BLS.G1_GEN, q77neg)]));

    // ---- full sign/verify against a py_ecc-COMPOSED signature: sk random, pk=sk*g2,
    // sig=sk*H(msg) (py_ecc's own G1/G2 multiply, not this file's) -- the decisive
    // cross-library check (module comment).
    let pk96 = hex("b5672a8503e15bc484dfa1cb80ef32eb407a9026050c0a4cdf86ae603a0ebfefcd21de54754d6fda7f6f9b426878c50b17b06326396fe45dbcff339d26ebc05bae89a35b127d22e8fb7bcd327009ebf0aee1fec6a4ab4e61b5fa019fa9471bd4");
    let msg = hex("61206d65737361676520746f207369676e20666f7220746865204943206167656e7420424c53204b4154");
    let sig48 = hex("aa123d42b26261ae51a4e478611682fb7122756a477f7a863ef1ef3c9edfd59b4d242c2f41d122245e8aeb218f8110f3");
    let badSig48 = hex("a6eab16b354e5e85dc0965f267bd5c9416dbc7dc54a978b8bf53101f15cdb1b7db780ceccb1c0168bfb0b839491eadf1");
    let otherPk96 = hex("ac7fa63dfc38bbf3712e27a180391bca4ccabf609c5967a0592eff420b6235f3f2b323051cb099acc3969aca310f7ff4191b2d6db43fafc2c9592f7e5f73981107975d3d92b843891e724dbc9f05b5eee5a3b2b1fc782ede8149f30830b84444");
    expect("verify: a genuine py_ecc-composed signature", Bls.verify(pk96, sig48, msg, Bls.IC_DST));
    expect("verify: a corrupted signature is rejected", not Bls.verify(pk96, badSig48, msg, Bls.IC_DST));
    expect("verify: the wrong public key is rejected", not Bls.verify(otherPk96, sig48, msg, Bls.IC_DST));
    expect("verify: a mismatched message is rejected", not Bls.verify(pk96, sig48, "a different message entirely", Bls.IC_DST));
    expect("verify: a malformed (too short) signature is rejected, not trapped", not Bls.verify(pk96, "\00\01\02", msg, Bls.IC_DST));

    passed
  };

  /// One verified query's cost: `Bls.verify` on the `sign_verify` vector above, wasm
  /// instructions via `ExperimentalInternetComputer.countInstructions`. Real counts need
  /// `MOXZI_FUEL=1` on moxzid (`README.md`, "Certificate verification cost").
  public func costOneVerify() : async Nat64 {
    let pk96 = hex("b5672a8503e15bc484dfa1cb80ef32eb407a9026050c0a4cdf86ae603a0ebfefcd21de54754d6fda7f6f9b426878c50b17b06326396fe45dbcff339d26ebc05bae89a35b127d22e8fb7bcd327009ebf0aee1fec6a4ab4e61b5fa019fa9471bd4");
    let msg = hex("61206d65737361676520746f207369676e20666f7220746865204943206167656e7420424c53204b4154");
    let sig48 = hex("aa123d42b26261ae51a4e478611682fb7122756a477f7a863ef1ef3c9edfd59b4d242c2f41d122245e8aeb218f8110f3");
    IC.countInstructions(func() { ignore Bls.verify(pk96, sig48, msg, Bls.IC_DST) })
  };

  /// `BLS.miller_loop` alone (no final exponentiation), on the two generators -- so the cost
  /// table can show how the `mo:bls12-381` pairing splits between the (now sparse, NAF) Miller
  /// loop and the (now cyclotomic) final exponentiation.
  public func costMillerLoopOnly() : async Nat64 {
    IC.countInstructions(func() { ignore BLS.miller_loop(BLS.G1_GEN, BLS.G2_GEN) })
  };

  public func costOnePairing() : async Nat64 {
    IC.countInstructions(func() { ignore BLS.pairing(BLS.G1_GEN, BLS.G2_GEN) })
  };

  /// `BLS.final_exponentiation` alone, on a real Miller-loop output (not an arbitrary Fp12
  /// element -- the easy part's `fp12_inv` is cheap either way, but this is the actual input
  /// shape `pairing`/`verify` feed it).
  public func costFinalExponentiationOnly() : async Nat64 {
    let ml = BLS.miller_loop(BLS.G1_GEN, BLS.G2_GEN);
    IC.countInstructions(func() { ignore BLS.final_exponentiation(ml) })
  };

  /// One `Fp` multiplication (`mo:bls12-381`'s `fp_mul`) -- the base operation the module
  /// comment's whole cost story is denominated in.
  public func costFpMul() : async Nat64 {
    let a : Nat = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    let b : Nat = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;
    per(1000, IC.countInstructions(func() { var x = a; var i = 0; while (i < 1000) { x := BLS.fp_mul(x, b); i += 1 } }))
  };
  func per(n : Nat, c : Nat64) : Nat64 { c / Nat64.fromNat(n) };
}

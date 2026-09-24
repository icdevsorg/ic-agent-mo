/// Known-answer tests for `Bls12381.mo` (alpha-7 G2). Every vector here was produced by the
/// Python prototype in `.plan/audit/g2-bls-report.md`'s scratch directory, itself checked
/// spot-value-by-spot-value and byte-for-byte against `py_ecc` (field arithmetic, the
/// isogeny/SWU hash-to-curve output, point compression) -- see `Bls12381.mo`'s module
/// comment ("Differential oracle") for what is and is not cross-checked against py_ecc this
/// way, and why. `check()` traps on the first failure (so a build that silently regresses one
/// layer fails loudly), and returns the count -- moxzi and moc must agree on it
/// (`scripts/ic_agent_gate.sh`, same pattern as `Vectors.mo`).
///
/// `costOneVerify()` measures ONE `Bls12381.verify` call's wasm instructions via
/// `ExperimentalInternetComputer.countInstructions` -- real counts only under `MOXZI_FUEL=1`
/// (`moxzi/runtime/src/machine.rs`'s `fuel_metering`); the gate records what it saw.
import Bls "../src/Bls12381";
import Hash "../src/Hash";
import IC "mo:base/ExperimentalInternetComputer";
import Debug "mo:base/Debug";
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";
import Text "mo:base/Text";

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

    // ---- Fp ----
    let fpA = natHex("17b38cd6ad3c2d6d1a3d1fa7bc8960a923b8c1e9392456de3eb13b9046685257bdd640fb06671ad11c80317fa3b1799d");
    let fpB = natHex("1343bcc8815ef6d13b8faa1837f8a88b17fc695a07a0ca6e0822e8f36c031199972a846916419f828b9d2434e465e150");
    expect("fp add", Bls.fpAdd(fpA, fpB) == natHex("10f637b4f51b3da40ab12209b1365c5cd73ddfbe4d400e8cdfa351e2bbba6dcd3654c5656b54ba53ee1e55b48817b042"));
    expect("fp sub", Bls.fpSub(fpA, fpB) == natHex("046fd00e2bdd369bdead758f8490b81e0bbc588f31838c70368e529cda6540be26abbc91f0257b4e90e30d4abf4b984d"));
    expect("fp mul", Bls.fpMul(fpA, fpB) == natHex("0d6f019a27834e66fd5f8a689c08ba798cfaea019306d20a7efab8dc14712765fb9625df9440eec4967521c171c58dc9"));
    expect("fp inv", Bls.fpInv(fpA) == natHex("070ab3a5c20fe4b73cbf8150953156a9a981a587e4df9769f57cca8d824d196c4144d481c373a8b8ee51441fb639f4c4"));
    expect("fp inv round-trips", Bls.fpMul(fpA, Bls.fpInv(fpA)) == 1);

    // ---- Fp2 ----
    let fp2A : Bls.Fp2 = (
      natHex("08e6f03296da1dac72ff5d2a386ecbe06b65a6a48b8148f6b38a088ca65ed389b74d0fb132e706298fadc1a606cb0fb3"),
      natHex("06e3d9af27cd813047229389571aa8766c307511b2b9437a28df6ec4ce4a2bbdc241330b01a9e71fde8a774bcf36d58b"),
    );
    let fp2B : Bls.Fp2 = (
      natHex("0876f4749a8dca03580d7b71d8f564135be6128e18c267976142ea7d17be31111a2a73ed562b0f79c37459eef50bea63"),
      natHex("0961b7688d5288f1142c3fe860e7a113ec1b8ca1f91e1d4c1ff49b7889463e85759cde66bacfb3d00b1f9163ce9ff57f"),
    );
    let fp2Mul = Bls.f2Mul(fp2A, fp2B);
    expect("fp2 mul c0", fp2Mul.0 == natHex("18505103bda354f2c424b9b61255c2b514e7edff81482dbe47ef2f60b8881be07a3a32bb2e0cd86fef600ebf4f3736e6"));
    expect("fp2 mul c1", fp2Mul.1 == natHex("0d0691edf21995f6a07f7adb7c24911503c15986e50a0e55e9f86de4d1ed941328edfb46c4d5392257c13c5fa1127d19"));
    let fp2Inv = Bls.f2Inv(fp2A);
    expect("fp2 inv c0", fp2Inv.0 == natHex("035e3d7a75600ca7f1e97b70e4986d0265969971c78836a30f0b3caa13555837333bffa8b00fab831185a205856dcb13"));
    expect("fp2 inv c1", fp2Inv.1 == natHex("0285caf5b7c768edcf956e5162b5119f6dea2eece1fb558dfc45ba822b11a623d2a19c67e900e7f4e4706b75a67195f2"));

    // ---- Fp6/Fp12 self-consistency (no external oracle for the tower's own basis -- see the
    // module comment on why; associativity/inverse round trips are the check here) ----
    let f6x : Bls.Fp6 = (fp2A, fp2B, (1, 2));
    expect("fp6 inverse round-trips", Bls.f6Mul(f6x, Bls.f6Inv(f6x)) == Bls.F6_ONE);
    let f12x : Bls.Fp12 = (f6x, (fp2B, (3, 4), (5, 6)));
    expect("fp12 inverse round-trips", Bls.f12Eq(Bls.f12Mul(f12x, Bls.f12Inv(f12x)), Bls.F12_ONE));

    // ---- G1/G2 group law ----
    let g1Double = Bls.g1Double(Bls.G1_GEN);
    let ?(g1dx, g1dy) = Bls.g1Affine(g1Double) else { Debug.trap("g1 double: infinity") };
    expect("g1 double(gen).x", g1dx == natHex("0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e"));
    expect("g1 double(gen).y", g1dy == natHex("166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"));
    let g1Triple = Bls.g1Add(g1Double, Bls.G1_GEN);
    let ?(g1tx, g1ty) = Bls.g1Affine(g1Triple) else { Debug.trap("g1 triple: infinity") };
    expect("g1 add(2G,G).x", g1tx == natHex("09ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224"));
    expect("g1 add(2G,G).y", g1ty == natHex("032b80d3a6f5b09f8a84623389c5f80ca69a0cddabc3097f9d9c27310fd43be6e745256c634af45ca3473b0590ae30d1"));
    let skMul = natHex("018ee90ff6c373e0ee4e3f0ad2");
    let g1Mul = Bls.g1Mul(Bls.G1_GEN, skMul);
    let ?(g1mx, g1my) = Bls.g1Affine(g1Mul) else { Debug.trap("g1 mul: infinity") };
    expect("g1 scalar mul .x", g1mx == natHex("0184410302a6613d6d4f35757e0f12f9a592db0a9ba076ced4fff95149f336d9756d480896a749f844b892e288f6a6a6"));
    expect("g1 scalar mul .y", g1my == natHex("04ce222ee35178e63b93427629d49aa629baf1492c3f66c1e79ab2e210803fe40de2c0c8092bc4d208740b971218cc5e"));
    expect("g1 on curve (gen)", Bls.g1OnCurve(Bls.G1_GEN));
    expect("g1 infinity is on curve", Bls.g1OnCurve(Bls.G1_INF));

    let g2Double = Bls.g2Double(Bls.G2_GEN);
    let ?(g2dx, g2dy) = Bls.g2Affine(g2Double) else { Debug.trap("g2 double: infinity") };
    expect("g2 double(gen).x0", g2dx.0 == natHex("1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053"));
    expect("g2 double(gen).x1", g2dx.1 == natHex("0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"));
    expect("g2 double(gen).y0", g2dy.0 == natHex("0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899"));
    expect("g2 double(gen).y1", g2dy.1 == natHex("0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3"));
    expect("g2 on curve (gen)", Bls.g2OnCurve(Bls.G2_GEN));

    // ---- pairing self-consistency (bilinearity/non-degeneracy/order -- see the module
    // comment on why THIS, not a py_ecc coefficient match, is the pairing oracle) ----
    let pAB = Bls.g1Mul(Bls.G1_GEN, 7);
    let qAB = Bls.g2Mul(Bls.G2_GEN, 11);
    let lhsBilin = Bls.pairing(qAB, pAB);
    let e1 = Bls.pairing(Bls.G2_GEN, Bls.G1_GEN);
    let rhsBilin = Bls.f12Pow(e1, 77);
    expect("bilinearity e(7G1,11G2) == e(G1,G2)^77", Bls.f12Eq(lhsBilin, rhsBilin));
    expect("pairing is non-degenerate", not Bls.f12Eq(e1, Bls.F12_ONE));

    // ---- hash_to_curve_g1, byte-identical to py_ecc's hash_to_G1 (RFC 9380) ----
    let ?(hx1, hy1) = Bls.g1Affine(Bls.hashToCurveG1("", Bls.IC_DST)) else { Debug.trap("hash empty: infinity") };
    expect("hash_to_curve_g1(\"\").x", hx1 == natHex("12e0e662181bd9f8cd8ef246071357cd07a23c4391e879b49e32084dcc1a2aede123c8e8bfcde92edac229e28b719142"));
    expect("hash_to_curve_g1(\"\").y", hy1 == natHex("0d568a0595f7e9620fd05bb0494fe782ab2bfb1c588edf404326a9d074c2a4b2d43ea2d4c8253eb1ce1ad7b70be521d8"));
    let ?(hx2, hy2) = Bls.g1Affine(Bls.hashToCurveG1("abc", Bls.IC_DST)) else { Debug.trap("hash abc: infinity") };
    expect("hash_to_curve_g1(\"abc\").x", hx2 == natHex("0ab1bfed57bef131b205541860254dd546a592eaa86da31f3128792be5e0a7a823cb6e7f5e4b82e2e0cfc84ef82f5cdb"));
    expect("hash_to_curve_g1(\"abc\").y", hy2 == natHex("063f4d009639ed31def6d3a5d8688b1bb9ebf75fc85ad41f4e22eda9730fdf84b2917e02b15e850e7536e938bb73d61c"));
    let icMsg = hex("69632d73746174652d726f6f742d746573742d6d657373616765");
    let ?(hx3, hy3) = Bls.g1Affine(Bls.hashToCurveG1(icMsg, Bls.IC_DST)) else { Debug.trap("hash ic: infinity") };
    expect("hash_to_curve_g1(ic-msg).x", hx3 == natHex("10f9d5fb92474fec1354fa173cbf4d3a96566afd74dfb46de7d2cc1b039b4082e054961d939f38972f31bc7f0785abed"));
    expect("hash_to_curve_g1(ic-msg).y", hy3 == natHex("186d4c2ec34aab38d8c0a5fb5a90fd9c5f729db63f753d6faa5a6c3912593e03e78988ba936a2ca192355dd4460ca695"));

    // ---- compression, byte-identical to py_ecc.bls.point_compression ----
    expect("compressG1 matches py_ecc", Bls.compressG1(g1Mul) == hex("8184410302a6613d6d4f35757e0f12f9a592db0a9ba076ced4fff95149f336d9756d480896a749f844b892e288f6a6a6"));
    let ?g1Rt = Bls.decompressG1(Bls.compressG1(g1Mul)) else { Debug.trap("decompressG1 round trip") };
    expect("decompressG1 round trip", Bls.g1Eq(g1Rt, g1Mul));
    let g2Mul = Bls.g2Mul(Bls.G2_GEN, skMul);
    expect("compressG2 matches py_ecc", Bls.compressG2(g2Mul) == hex("86c82d2ad909e37c982a88185b2737724bf3b154dd7c59d9c349c4f3ab40d141d8fa945b20df40c2d69747d5bce4ef1c0dd9a02fe5074bafb07439e5047214ac520486026c5fe2c3a8019a9c73c7f6eef36f847062fcf72c35b9b4fd76ab0ad9"));
    let ?g2Rt = Bls.decompressG2(Bls.compressG2(g2Mul)) else { Debug.trap("decompressG2 round trip") };
    expect("decompressG2 round trip", Bls.g2Eq(g2Rt, g2Mul));
    expect("decompressG1 rejects a truncated blob", Bls.decompressG1("\00") == null);
    expect("decompressG2 rejects a truncated blob", Bls.decompressG2("\00") == null);

    // ---- full sign/verify against a py_ecc-COMPOSED signature: sk random, pk=sk*g2,
    // sig=sk*H(msg) (py_ecc's own G1/G2 multiply, not this file's) -- see the module comment,
    // strategy 2, for why this is the decisive cross-library check.
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
  /// `MOXZI_FUEL=1` on moxzid (`docs`/`README.md`, "Certificate verification cost").
  public func costOneVerify() : async Nat64 {
    let pk96 = hex("b5672a8503e15bc484dfa1cb80ef32eb407a9026050c0a4cdf86ae603a0ebfefcd21de54754d6fda7f6f9b426878c50b17b06326396fe45dbcff339d26ebc05bae89a35b127d22e8fb7bcd327009ebf0aee1fec6a4ab4e61b5fa019fa9471bd4");
    let msg = hex("61206d65737361676520746f207369676e20666f7220746865204943206167656e7420424c53204b4154");
    let sig48 = hex("aa123d42b26261ae51a4e478611682fb7122756a477f7a863ef1ef3c9edfd59b4d242c2f41d122245e8aeb218f8110f3");
    IC.countInstructions(func() { ignore Bls.verify(pk96, sig48, msg, Bls.IC_DST) })
  };

  /// The Miller loop alone (no final exponentiation) -- to see how the cost splits between
  /// the loop and the single big final-exponentiation `f12Pow` call.
  public func costMillerLoopOnly() : async Nat64 {
    IC.countInstructions(func() { ignore Bls.millerLoop(Bls.G2_GEN, Bls.G1_GEN) })
  };

  public func costOnePairing() : async Nat64 {
    IC.countInstructions(func() { ignore Bls.pairing(Bls.G2_GEN, Bls.G1_GEN) })
  };
}

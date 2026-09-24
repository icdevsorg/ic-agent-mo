/// Micro-costs of BLS12-381 field arithmetic. Real counts need moxzid with MOXZI_FUEL=1. Each
/// `*() : async Nat64` returns wasm instructions per operation (averaged over 1000 calls, to
/// amortise the per-call/loop overhead `loopOverhead` measures on its own).
///
/// After the 2026-09-24 pivot (`Bls12381.mo`'s module comment): `Bls12381.mo` no longer owns
/// field arithmetic at all (it delegates to `mo:bls12-381`), so `fpMul`/`fpAdd` below now
/// measure `BLS.fp_mul`/`BLS.fp_add` directly -- the actual operation `verify` bottoms out in,
/// not a copy of it. `fpMulBarrett`/`checkBarrett` are kept as-is: they show what a Barrett
/// reduction WOULD cost `fp_mul` (measured ~1.6x fewer instructions than the schoolbook
/// `(a*b) % P` both `BLS.fp_mul` and the old from-scratch `Bls12381.fpMul` used -- see
/// `README.md`, "Certificate verification cost"), a road not taken here: `fp_mul` is now
/// `mo:bls12-381`'s code, an external dependency, not this package's to change without
/// upstreaming the reduction algorithm there.
import BLS "mo:bls12-381";
import IC "mo:base/ExperimentalInternetComputer";
import Nat64 "mo:base/Nat64";
import Nat "mo:base/Nat";

persistent actor {
  transient let a : Nat = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
  transient let b : Nat = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;
  func per(n : Nat, c : Nat64) : Nat64 { c / Nat64.fromNat(n) };
  public func fpMul() : async Nat64 { per(1000, IC.countInstructions(func() { var x = a; var i = 0; while (i < 1000) { x := BLS.fp_mul(x, b); i += 1 } })) };
  public func fpAdd() : async Nat64 { per(1000, IC.countInstructions(func() { var x = a; var i = 0; while (i < 1000) { x := BLS.fp_add(x, b); i += 1 } })) };
  public func loopOverhead() : async Nat64 { per(1000, IC.countInstructions(func() { var x = a; var i = 0; while (i < 1000) { x := x; i += 1 } })) };
  public func natMulOnly() : async Nat64 { per(1000, IC.countInstructions(func() { var i = 0; while (i < 1000) { ignore a * b; i += 1 } })) };
  public func natModOnly() : async Nat64 { let ab = a * b; per(1000, IC.countInstructions(func() { var i = 0; while (i < 1000) { ignore ab % 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab; i += 1 } })) };

  // Barrett reduction: no division. q ~= floor(x * mu / 2^(2k)) with mu = floor(2^(2k)/p), k = 381.
  transient let P : Nat = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
  transient let MU : Nat = 6060872796126202341416486485954650311182547756064496405659909846341149209992573236889604617486802525004416140330728;
  func barrett(x : Nat) : Nat {
    let q = Nat.bitshiftRight(Nat.bitshiftRight(x, 380) * MU, 382);
    var r = x - q * P;
    while (r >= P) { r -= P };
    r
  };
  public func fpMulBarrett() : async Nat64 { per(1000, IC.countInstructions(func() { var x = a; var i = 0; while (i < 1000) { x := barrett(x * b); i += 1 } })) };
  public func checkBarrett() : async Bool { var x = a; var y = a; var i = 0; while (i < 200) { x := barrett(x * b); y := (y * b) % P; i += 1 }; x == y };
  public func shiftOnly() : async Nat64 { let ab = a * b; per(1000, IC.countInstructions(func() { var i = 0; while (i < 1000) { ignore Nat.bitshiftRight(ab, 380); i += 1 } })) };
};

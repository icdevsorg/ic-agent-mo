/// Constants `Bls12381.mo` still needs after the 2026-09-24 pivot to `mo:bls12-381` for the
/// field tower/curve/pairing (see `Bls12381.mo`'s module comment). Everything this file used
/// to carry for the from-scratch implementation -- the field modulus and group order (now
/// `BLS.P`/`BLS.R_`), the RFC 9380 11-isogeny map coefficients (now inside
/// `BLS.map_fp_to_g1`), the naive final-exponentiation exponent and the Miller loop's
/// pseudo-binary bit table (both now the library's own NAF/cyclotomic final exponentiation),
/// the `w^-2`/`w^-3` twist constants and the eighth-roots-of-unity table (the library's
/// `BLS.fp2_sqrt` uses a different, Frobenius-based algorithm that needs none of them) -- moved
/// with it or was superseded by it; kept here ONLY the three powers of two `decompressG2`'s
/// Zcash-format flag parsing needs, since that decoder (96-byte compressed G2; the library has
/// no compressed-G2 decoder -- EIP-2537 doesn't call for one) is still this package's own code.
module {
  public let POW_2_381 : Nat = 4925250774549309901534880012517951725634967408808180833493536675530715221437151326426783281860614455100828498788352;
  public let POW_2_382 : Nat = 9850501549098619803069760025035903451269934817616361666987073351061430442874302652853566563721228910201656997576704;
  public let POW_2_383 : Nat = 19701003098197239606139520050071806902539869635232723333974146702122860885748605305707133127442457820403313995153408;
}

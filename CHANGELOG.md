# Changelog

## Next

- **`Bls12381.mo` now delegates to `mo:bls12-381`** (`icdevsorg/bls12-381.mo`, the
  EIP-2537-grade implementation `evm.mo` already uses) instead of the from-scratch,
  deliberately-naive tower/pairing the previous entry below shipped. Public API unchanged
  (`Bls.verify(pk96, sig48, msg, dst)`, `Bls.IC_DST` — what `Certificate.mo` calls); this
  package keeps only RFC 9380 `expand_message_xmd`/hash-to-field and the IC's 96-byte
  compressed-G2 decoding (the library has neither), and hands everything else — the field
  tower, G1/G2 arithmetic, and the pairing (now an optimal-ate NAF Miller loop with sparse
  lines and a Granger-Scott-cyclotomic-squaring final exponentiation) — to the dependency.
  Measured (`moxzid`, `MOXZI_FUEL=1`, `scripts/ic_agent_gate.sh` step 1d): one `Bls.verify`
  call went from 61.07 billion wasm instructions (5.1-9 s) to 1.44 billion (0.16 s), ~42x;
  one pairing from 28.57 billion to 742 million, ~39x; the final exponentiation alone
  (`~93%` of the old pairing's cost) from ~25-27 billion to 412 million, ~61-66x — see
  `README.md`, "Certificate verification cost", for the full before/after table and
  `Bls12381.mo`'s module comment for exactly what moved. New dependency `bls12-381`
  (Apache-2.0); it is not yet on the mops registry, so `mops.toml` pulls it by GitHub ref —
  **publishing `ic-agent` to mops requires `bls12-381` to be published there first.**
  `test/BlsVectors.mo`'s KATs were rewritten for the new split (hash-to-curve and G2
  decompression/subgroup-rejection are still this package's to prove; the library's own
  pairing correctness is its own test/bench suite's concern).

- **Certificate verification (BLS12-381).** `Certificate.verify` checks the signature
  over `domain_sep("ic-state-root") ‖ root_hash(tree)` against a root/subnet key,
  including one level of delegation and a `canister_ranges` check; `poll`/`readState`/
  `call` all verify before trusting a certificate. New `Config.verify : { #required;
  #skip }`, default `#required`; `#skip` prints a loud `Debug.print` line on every
  certificate it bypasses. Backed by a new from-scratch pure-Motoko BLS12-381
  (`Bls12381.mo` — there was no pure-Motoko implementation on mops), validated against
  `py_ecc` and measured: roughly 28-56 billion wasm instructions and several seconds per
  verified certificate off-chain (`README.md`, "Certificate verification cost" — the
  honest cost, not hidden, is G3's input on whether this is viable in a hot path or
  on-chain at all). `test/BlsVectors.mo` carries the KATs.

## 0.1.0-alpha.7

First release. Query, submit, poll, call, read_state and status against the IC's HTTP
interface from Motoko; identities: anonymous, ed25519, secp256k1, a host-supplied signer,
Internet Identity delegation chains; certificates decoded (hash trees, spec `lookup`,
request status) but not yet verified against the root key; `Agent.call` uses the
synchronous v3 endpoint and polls only when it must. Known-answer tests against the
interface spec, agent-js and node's crypto; end-to-end under moxzid against PocketIC and
mainnet (`scripts/ic_agent_gate.sh` in the moxzi repository).

# Changelog

## Next

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

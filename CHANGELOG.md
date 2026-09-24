# Changelog

## 0.2.0 — 2026-09-24

The agent now covers the IC interface specification's HTTPS interface, and **verifies
everything it receives**. 0.1.0 verified certificates but trusted query responses; that was a
gap, and it is closed.

- **Query responses are verified.** Every reply and every rejection is checked against its
  node signatures (Ed25519 over `"\x0Bic-response" · hash_of_map(response)`), using node keys
  from a verified `/subnet` certificate of the subnet that hosts the canister, with fresh
  timestamps. Keys are cached per subnet while their certificate is fresh. Node signatures
  are checked by a new `Ed25519` module (RFC 8032 over `Nat` arithmetic, 155 million
  instructions per query, never traps, small-order keys refused): `mo:ed25519`'s `verify`
  traps on malformed input, took over 2 seconds per call, and rejected a genuine PocketIC node
  signature in one gate run. New error
  `#querySignature`. Pure halves for callers with their own transport:
  `subnetKeysFromCertificate`, `checkNodeSignatures`.
- **Ed25519 signing fixed.** `Identity.ed25519` signed with `mo:ed25519`, which produces an
  INVALID signature whenever the nonce has a zero top byte, about 1 message in 24; the replica
  rejects those requests ("Invalid signature"). A 100-message differential against OpenSSL
  found 3, identically under moc and moxzi. Signing now uses the new `Ed25519` module, checked
  byte for byte against OpenSSL on 64 keys and on the 3 failing messages; the `ed25519`
  dependency is gone.
- **Current endpoints.** v3 query, v3 read_state and v4 synchronous call, each downgrading once
  per agent (to v2, v2, and v3 then v2 + polling) when a gateway answers 404/405;
  `apiVersions()` reports what is in use.
- **Delegations are scoped as the spec requires.** v3/v4 delegations carry only the sharded
  `/canister_ranges/<subnet>/…`; 0.1.0 read only `/subnet/<subnet>/canister_ranges` and would
  have refused them. Both encodings are read now. Subnet-scoped requests check the delegation's
  subnet.
- **Certificate freshness and well-formedness.** `/time` must be within
  `Config.maxCertificateAgeNs` (5 minutes); a delegation's within `maxDelegationAgeNs`
  (30 days). Trees must be well formed before any lookup. `Certificate.verifyScoped` with a
  `Policy`; the 0.1.0 `Certificate.verify` is kept.
- **Effective canister ids.** Calls to `aaaaa-aa` are routed to the canister in their Candid
  argument (`canister_id`, or `target_canister` for `install_chunked_code`);
  `Options.effectiveCanisterId` for canister creation and `list_canisters`. New `Candid` module.
- **More of the spec:** `readSubnetState`, `subnetQuery`, `subnetCall`, `pollSubnet`;
  `moduleHash`, `controllers`, `metadata`; `Options.senderInfo` (`sender_info`); `queryWith`,
  `submitWith`, `callWith`; `Certificate.certifiedData`, `Certificate.verifyCanisterSignature`,
  `lookupAll`, `wellFormed`, `rootSubnetId`, `nodeKeys`; `RejectCode.#sysUnknown` (6).
- **Breaking:** `Config` has two new fields (`maxCertificateAgeNs`, `maxDelegationAgeNs`) —
  build configs with `{ Agent.defaults(host, id) with … }`; `Envelope.Call` has `senderInfo`;
  `poll`'s first argument is the request's effective canister id (the same as before for any
  target but `aaaaa-aa`).
- **Tests:** `test/SpecVectors.mo`, 121 checks against real mainnet query responses and
  certificates (root and delegated subnets, a signed rejection) and 64 OpenSSL Ed25519
  keys and signatures (signing byte for byte, verification, alteration), both compilers; the live
  PocketIC gate now runs an NNS + application topology so answers come under a real
  delegation, and adds rejections, canister info, subnet endpoints, management routing,
  canister signatures and certified data; mainnet steps fail instead of skipping when
  mainnet is reachable.

## 0.1.0 — 2026-09-24

First registry release.

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
  (Apache-2.0), `bls12-381 = "0.1.0"` from the mops registry.
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

### Earlier in this release (before the BLS switch)

First release. Query, submit, poll, call, read_state and status against the IC's HTTP
interface from Motoko; identities: anonymous, ed25519, secp256k1, a host-supplied signer,
Internet Identity delegation chains; certificates decoded (hash trees, spec `lookup`,
request status) but not yet verified against the root key; `Agent.call` uses the
synchronous v3 endpoint and polls only when it must. Known-answer tests against the
interface spec, agent-js and node's crypto; end-to-end under moxzid against PocketIC and
mainnet (`scripts/ic_agent_gate.sh` in the moxzi repository).

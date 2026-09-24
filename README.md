# mo:ic-agent — an Internet Computer agent in Motoko

Query, submit, poll and read canisters over the IC's HTTP interface, signed by an
identity, **from Motoko** — a moxzid actor, a moxzi game, a browser tab, or anywhere
HTTPS outcalls exist.

```motoko
import Agent "mo:ic-agent";
import Identity "mo:ic-agent/Identity";

let agent = Agent.Agent(Agent.defaults("https://icp-api.io", #anonymous));
let ledger = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai");
switch (await* agent.queryCall(ledger, "icrc1_name", to_candid())) {
  case (#ok reply) { let ?name : ?Text = from_candid(reply) };
  case (#err e) { … };
};
```

## Keep ticking: an update call is two operations

`submit` sends the signed envelope and returns the **request id** at once; `poll` is
one `read_state` round trip that reports `#pending`, `#replied`, `#rejected`, `#done` or
`#unknown`. A game courier submits on one tick and polls on later ticks, so its own
message never blocks on the network. `call` composes the two for code that can wait.

```motoko
let id = Identity.secp256k1(secret);            // or Identity.ed25519(seed), #anonymous,
let agent = Agent.Agent(Agent.defaults(host, id)); // Identity.delegated(root, chain, session)
let #ok rid = await* agent.submit(canister, "inc", to_candid()) else …;
// later:
switch (await* agent.poll(canister, rid)) { case (#ok(#replied bytes)) …; case (#ok(#pending _)) …; … }
```

## Typed façades: never touch Candid

```sh
moxzi agent-bindings ledger.did --name Ledger -o Ledger.mo
```

```motoko
import Ledger "Ledger";
let ledger = Ledger.connectText(agent, "ryjl3-tyaaa-aaaaa-aaaba-cai");
switch (await* ledger.icrc1_balance_of({ owner; subaccount = null })) { case (#ok n) …; case (#err e) … };
let #ok rid = await* ledger.icrc1_transfer_submit(args) else …;   // keeps ticking
// later: await* ledger.icrc1_transfer_poll(rid)
```

The module declares every type of the interface and a `Facade` class — a **proxy object**,
not an actor reference — whose methods `to_candid` their arguments, go out as queries or
calls as the interface says, and `from_candid` the reply. `call`-style methods use the
synchronous v3 endpoint and poll only if the gateway answers 202.

## What is here

| Module | Does |
|---|---|
| `Agent` (`lib.mo`) | `queryCall`, `submit`, `poll`, `call`, `readState`, `status`; `Config`, `defaults`, `MAINNET_ROOT_KEY`, typed `RejectCode` |
| `Identity` | anonymous, ed25519, secp256k1, any `Signer` a host supplies, delegation chains (Internet Identity); self-authenticating principals |
| `Envelope` | the content maps, request ids (representation-independent hashing), the signed CBOR envelope, delegation hashing |
| `Certificate` | certificate decoding, hash trees, `lookup` (found / absent / unknown per the spec), `rootHash`, request status, and `verify` — the BLS signature, including one level of subnet delegation |
| `Bls12381` | the min_sig BLS12-381 `verify` `Certificate` needs — RFC 9380 hash-to-curve and IC-format G2 decompression here, field/curve/pairing delegated to `mo:bls12-381`; see "Certificate verification cost" below |
| `Transport` | `Http` — HTTPS outcalls through the management canister by default; a host can plug its own |
| `Hash`, `Cbor` | sha256/sha224, LEB128, hex; the CBOR the interface needs over `mo:cbor` |

**Not yet:** a browser transport (G5). Signing with secp256k1 builds the generator
table once per identity — keep the identity.

## Certificate verification (alpha-7 G2)

Every certificate this agent decodes is now BLS-verified before `poll`/`readState`/`call`
trust it: the signature over `domain_sep("ic-state-root") ‖ root_hash(tree)` is checked
against the root key (`Config.rootKey`, mainnet's by default), following one level of
subnet delegation and checking the target canister falls in the delegation's
`canister_ranges`. `Config.verify` controls this:

```motoko
public type Verify = { #required; #skip };
```

`#required` (the default) fails closed: a bad signature, an out-of-range canister, or two
levels of delegation is `#err(#certificate e)`, never a silent pass. `#skip` bypasses
verification entirely and prints a **loud** `Debug.print` line on every certificate it
skips — read "Certificate verification cost" below before reaching for it; it exists for
a caller who has already weighed that cost against their own trust model (a moxzid host
pinned to a subnet it trusts some other way, say), not as a quiet default.

### Certificate verification cost

**2026-09-24: `Bls12381.mo` now delegates to `mo:bls12-381`** (`icdevsorg/bls12-381.mo`,
used by `evm.mo`'s EIP-2537 precompiles) instead of the from-scratch, deliberately-naive
tower/pairing alpha-7 G2 shipped with (naive single-exponent final exponentiation, no
sparse Miller loop). This package now keeps only what that library does not provide —
RFC 9380 `expand_message_xmd`/hash-to-field and the IC's 96-byte compressed-G2 decoding —
and hands the field tower, curve arithmetic and pairing to it: an optimal-ate Miller loop
over a NAF-recoded BLS parameter, sparse line evaluation, Granger-Scott cyclotomic squaring
in the final exponentiation, and the psi-endomorphism subgroup checks. See `Bls12381.mo`'s
module comment for exactly what moved and what stayed, and why maintaining two field-tower
implementations for the same curve in one monorepo was the actual problem being fixed.
`Fp` is still `Nat` (moxzi/Motoko's arbitrary-precision bignum, not fixed-width limbs) —
`mo:bls12-381`'s own `.bench/montgomery_vs_nat.bench.json` measured a fixed-limb Montgomery
`fp_mul` at ~80x SLOWER than the schoolbook `Nat` one in pure Motoko (1.86M vs 23k
instructions), so that road is closed here too, not just untaken.

Measured on `moxzid` (`MOXZI_FUEL=1`, real wasmtime-fuel instruction counts, this build
host, `scripts/ic_agent_gate.sh` step 1d for `verify`/`pairing`/`miller loop`;
`test/BlsVectors.mo`'s `costFinalExponentiationOnly`/`costFpMul` for the other two rows,
same host and flag, a direct call rather than through the gate script — wall time is a
single measured run, not the multi-sample range the pre-pivot table below used):

| Operation | Before (from-scratch) | After (`mo:bls12-381`) | Speedup |
|---|--:|--:|--:|
| One `Bls.verify` call | 61.07 billion instr, 5.1-9 s | 1.44 billion instr, 0.16 s | ~42x |
| One pairing (Miller loop + final exponentiation) | 28.57 billion instr, 2.6-3 s | 742 million instr, 0.10 s | ~39x |
| — of which, the Miller loop alone | 1.91 billion instr, 0.2-1 s | 331 million instr, 0.05 s | ~5.8x |
| — of which, the final exponentiation alone | ~25-27 billion instr (~93% of a pairing), ~2.4-2.8 s | 412 million instr (~55% of a pairing), 0.08 s | ~61-66x |
| One `fp_mul` (base field multiply) | 40,932 instr | 40,932 instr | 1x (unchanged — see above; `mo:bls12-381`'s `fp_mul` is the same schoolbook `(a*b) % P` the from-scratch version used, now an external dependency's code rather than this package's to hand-optimize) |

The "before" row is the git history of this file/`README.md` before 2026-09-24 (same
`moxzid`/`MOXZI_FUEL=1` methodology, several measurements across build-host load, hence
the range); the "after" row is a single run captured alongside this change. The ~42x
`verify` speedup is driven almost entirely by the final exponentiation (naive
single-~4314-bit-exponent `f12Pow` before, Granger-Scott cyclotomic squaring over an
easy/hard-part split now) and the sparse/NAF Miller loop; `fp_mul` did not change because
neither version's `fp_mul` did (Barrett reduction — measured ~1.6x fewer instructions than
schoolbook reduction on this same field, `test/BlsBench.mo`'s `fpMulBarrett`/`checkBarrett`
— was never wired into `mo:bls12-381`'s `fp_mul`; it would need to be upstreamed there, not
patched here).

**The honest verdict (G3's input, not hidden):** pure-Motoko BLS12-381 verification is now
**usable off-chain routinely**, not just occasionally — 1.44 billion instructions and
~0.16 s is a normal, unremarkable operation for a moxzid backend or a CLI tool, well under
even a conservative fraction of a single message's instruction budget; `#required` stays
the default with much less of a tax for choosing it. It is **on the edge of usable
on-chain**: the IC's real per-message instruction limit is on the order of several billion
(`moxzid`'s own default `--instruction-limit`, 40 billion, is now ~28x the cost of one
`Bls.verify` call rather than below it), so a SINGLE certificate check inside a real IC
message is now plausible where before it was categorically not — though still a
meaningful fraction of a message's budget if combined with other real work, and still
untested on the IC's actual metering (`moxzid`'s wasmtime-fuel counts are the best
available proxy off-chain, not a substitute for an on-chain measurement). On a phone or in
a browser tab (G3's stated targets), 1.44 billion instructions is in the range where a
sub-second check is realistic on typical hardware, which was not true of the old ~61
billion. `mo:bls12-381`'s own saved benchmarks (`.bench/bls12_381.bench.json`) are the
authority on where further headroom would come from (`fp_sqrt` and `fp2_sqrt` are now
disproportionately expensive relative to the pairing, for instance) — that is a question
for that package, not this one.

## Proof

`scripts/ic_agent_gate.sh`: the known-answer tests in `test/Vectors.mo` (request ids
from the interface spec's worked example and from agent-js, an envelope byte for byte,
ed25519 keys/principals/signatures against node's crypto, secp256k1 keys and principals,
hash-tree root and lookups against agent-js) and `test/BlsVectors.mo` (hash-to-curve KATs
against `py_ecc`, G2 decompression round trips and rejections — including a point that is
on the curve but off the r-order subgroup — a direct bilinearity check, and full
sign/verify against a `py_ecc`-composed signature; `mo:bls12-381`'s own pairing
correctness is that package's test/bench suite's concern, not re-proven here — see
`Bls12381.mo`'s module comment) built by **both** moxzi and moc with the same count; then a
moxzid actor against a PocketIC instance behind a live gateway — status/root key, anonymous
query, an ed25519-signed query, secp256k1 `call` and `submit`+`poll` (every one of these now
BLS-VERIFIES the certificate PocketIC actually signed, against PocketIC's own root key —
the real-wire half of the BLS proof, alongside the `py_ecc` KATs), agent-js reading the
same counter — the BLS12-381 cost table (wasm instructions, `MOXZI_FUEL=1`) — and one
anonymous query on mainnet.

Dependencies: `cbor` (MIT), `sha2` (Apache-2.0), `ed25519` (MIT), `libsecp256k1` (Apache-2.0),
`bls12-381` (Apache-2.0, `icdevsorg/bls12-381.mo` — **not yet on the mops registry**; this
package currently pulls it by GitHub ref (`mops.toml`), so publishing `ic-agent` to mops
requires `bls12-381` to be published there first).

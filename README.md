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
| `Bls12381` | pure-Motoko BLS12-381 (field towers, curves, hash-to-curve, pairing) `verify` needs — see "Certificate verification cost" below before using it in a hot path |
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

There is no pure-Motoko BLS12-381 on mops (checked 2026-09-23 while building this: the
`BLS12-381.mo` the alpha-7 survey cited turned out to be the Rust crates `ic_bls12_381`/
`ic-verify-bls-signature` the CLI links, not a Motoko library). `Bls12381.mo` is a
from-scratch port — field towers (`Fp`→`Fp2`→`Fp6`→`Fp12`), projective G1/G2, RFC 9380
hash-to-curve for G1, a Miller loop and a **deliberately naive** (single-exponent, no
Frobenius-coefficient easy part, no BLS-parameter addition chain for the hard part) final
exponentiation — validated against `py_ecc` (`.plan/audit/g2-bls-report.md`: byte-exact
hash-to-curve and point-compression matches, plus real py_ecc-composed signatures verifying
correctly here). `Fp` is `Nat` — moxzi/Motoko's arbitrary-precision bignum, not fixed-width
limbs. Measured on `moxzid` (`MOXZI_FUEL=1`, real wasmtime-fuel instruction counts, this
build host, `scripts/ic_agent_gate.sh` step 1d):

| Operation | Wasm instructions | Wall time |
|---|--:|--:|
| One `Bls.verify` call (2 pairings + hash-to-curve + decompression + subgroup checks) | 55.5-61.1 billion | 5.1-9 s |
| One pairing (Miller loop + final exponentiation) | 27.0-28.6 billion | 2.6-3 s |
| — of which, the Miller loop alone | ~1.9 billion | 0.2-1 s |
| — of which, the (naive) final exponentiation | ~25-27 billion (~93% of a pairing) | ~2.4-2.8 s |

(A range, not noise to round away: a freshly-started `moxzid` gives the low end; the SAME
build measured after other work on the same server — e.g. right after `test/BlsVectors.mo`'s
own 10-pairing `check()`, as `scripts/ic_agent_gate.sh` does — gives the high end, instruction
count included, not just wall time. Read as "several tens of billions of instructions,
several seconds," not as a number precise to three significant figures.)

**The honest verdict (G3's input, not hidden):** pure-Motoko BLS12-381 is usable
**off-chain, occasionally** — a few seconds to verify one certificate is fine for "check
this query result before I act on it" in a moxzid backend or a CLI tool, and is why
`#required` is still the default here. It is **not usable in a hot path**: a game or UI
polling certificates every tick would stall on this, which is the actual reason `#skip`
exists, not a convenience. It is **not usable on-chain at all** under anything like
today's numbers: `moxzid`'s own default `--instruction-limit` (40 billion, chosen to
mirror the IC's real per-message ceiling) is already BELOW the cost of one `Bls.verify`
call — the gate has to raise it explicitly to let the BLS steps run at all. On a phone or
in a browser tab (G3's stated targets), this number needs the ~10-100x a properly
Jacobian-coordinate, sparse-Miller-loop, Frobenius-coefficient-final-exponentiation
implementation would buy back (none of that is done here — see `Bls12381.mo`'s module
comment for exactly which corners were cut and why), and even then would still be a
noticeably heavier operation than anything else this package does. If G3 needs
sub-second, on-chain-affordable certificate checks, the answer is not "optimize this
file harder" alone — it is a different approach entirely (a precompiled/native verifier,
an attested oracle, or accepting unverified certificates from a specifically trusted
gateway via `#skip`).

## Proof

`scripts/ic_agent_gate.sh`: the known-answer tests in `test/Vectors.mo` (request ids
from the interface spec's worked example and from agent-js, an envelope byte for byte,
ed25519 keys/principals/signatures against node's crypto, secp256k1 keys and principals,
hash-tree root and lookups against agent-js) and `test/BlsVectors.mo` (field/curve/
hash-to-curve/compression KATs against `py_ecc`, pairing self-consistency, and full
sign/verify against a `py_ecc`-composed signature — see `Bls12381.mo`'s module comment)
built by **both** moxzi and moc with the same count; then a moxzid actor against a
PocketIC instance behind a live gateway — status/root key, anonymous query, an
ed25519-signed query, secp256k1 `call` and `submit`+`poll` (every one of these now
BLS-VERIFIES the certificate PocketIC actually signed, against PocketIC's own root key —
the real-wire half of the BLS proof, alongside the `py_ecc` KATs), agent-js reading the
same counter — the BLS12-381 cost table (wasm instructions, `MOXZI_FUEL=1`) — and one
anonymous query on mainnet.

Dependencies: `cbor` (MIT), `sha2` (Apache-2.0), `ed25519` (MIT), `libsecp256k1` (Apache-2.0).

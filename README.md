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
synchronous v4 endpoint and poll only if the replica answers 202.

## What is here

| Module | Does |
|---|---|
| `Agent` (`lib.mo`) | `queryCall`/`queryWith`, `submit`/`submitWith`, `poll`, `call`/`callWith`, `readState`, `readSubnetState`, `subnetQuery`, `subnetCall`, `pollSubnet`, `moduleHash`, `controllers`, `metadata`, `status`, `apiVersions`; `Config`, `defaults`, `Options`, `effectiveCanisterId`, `MAINNET_ROOT_KEY`, typed `RejectCode`; the pure halves of query verification, `subnetKeysFromCertificate` and `checkNodeSignatures` |
| `Identity` | anonymous, ed25519, secp256k1, any `Signer` a host supplies, delegation chains (Internet Identity); self-authenticating principals |
| `Envelope` | the content maps (with the optional `sender_info`), request ids (representation-independent hashing), the signed CBOR envelope, delegation hashing |
| `Certificate` | certificate decoding, hash trees, `lookup` / `lookupAll` (the spec's `lookup*`) / `wellFormed`, request status, `verifyScoped` (BLS signature, one delegation scoped to a canister or subnet, `/time` freshness), node keys, `certifiedData`, `verifyCanisterSignature` |
| `NodeSignature` | query-response signatures: the `ic-response` hash, node-key unwrap |
| `Ed25519` | RFC 8032 signing and verification over `Nat` field arithmetic; verification is total (false, never a trap, on hostile input) |
| `Candid` | just enough Candid to route a management-canister call to its effective canister id |
| `Bls12381` | the min_sig BLS12-381 `verify` certificates need; field, curve and pairing come from `mo:bls12-381` |
| `Transport` | `Http` — HTTPS outcalls through the management canister by default; a host can plug its own |
| `Hash`, `Cbor` | sha256/sha224, LEB128, hex; the CBOR the interface needs over `mo:cbor` |

## Everything that comes back is verified

With `Config.verify = #required` (the default), nothing a node sends is trusted until it is
checked against the root key (`Config.rootKey`, mainnet's by default):

- **Certificates** (`call`, `poll`, `readState`, `readSubnetState`, the canister-info
  reads): the BLS signature over `domain_sep("ic-state-root") ‖ root_hash(tree)`; at most
  one subnet delegation, itself verified against the root key and **scoped** — to the
  canister asked about (both the sharded `/canister_ranges/<subnet>/…` that v3/v4 endpoints
  return and the whole `/subnet/<subnet>/canister_ranges` blob are read) or to the subnet
  asked about; a well-formed tree; and a `/time` within `Config.maxCertificateAgeNs`
  (5 minutes) of now. The delegation's own certificate is held to `maxDelegationAgeNs`
  (30 days by default; mainnet refreshes delegations on replica upgrades).
- **Query replies and query rejections**: every node signature, Ed25519 over
  `"\x0Bic-response" · hash_of_map(response)`, against that node's key from a verified
  `/subnet` certificate of the subnet hosting the canister; every signature timestamp fresh;
  and, when the root subnet answers without a delegation, the canister must be in the root
  subnet's own certified ranges. Node keys are cached per subnet while their certificate is
  fresh, and refreshed once if a signature names a node the cache does not know.

`#skip` turns all of it off and prints a loud `Debug.print` line for every response it
skips. There is no silent mode.

## Interface-spec coverage

| Spec section | Here |
|---|---|
| Request: Call (v4 synchronous, v3, v2 asynchronous) | `call` / `callWith` try v4, then v3, then v2 + polling, downgrading once per agent on 404/405; `submit` is v2; `apiVersions()` reports what is in use |
| Request: Query call (v3, v2; subnet v3) | `queryCall` / `queryWith`, `subnetQuery`; replies and rejections signature-verified |
| Request: Read state (canister v3/v2, subnet v3/v2) | `readState`, `readSubnetState`, `poll`, `pollSubnet` |
| Subnet-scoped call (`/api/v4/subnet/…/call`) | `subnetCall` |
| Effective canister id | derived from the Candid argument for `aaaaa-aa` (`canister_id`, or `target_canister` for `install_chunked_code`); `Options.effectiveCanisterId` when the argument names none |
| Authentication | anonymous, ed25519, secp256k1, host `Signer` (any scheme, e.g. P-256 or WebAuthn held by the host), delegation chains with targets |
| `sender_info` | `Options.senderInfo` |
| Certification, Lookup, Delegation | `Certificate.verifyScoped`, `lookup`, `lookupAll`, `wellFormed` |
| Canister information (`module_hash`, `controllers`, `metadata`) | `moduleHash`, `controllers`, `metadata` |
| Certified data | `Certificate.certifiedData` |
| Canister signatures | `Certificate.verifyCanisterSignature` (incl. the `cloud_engine` subnet-type rule) |
| Status endpoint | `status` (the spec: never trust its root key on mainnet) |

**Not yet:** a browser transport (G5); native P-256 and WebAuthn signing (supply them as a
host `Signer`). Signing with secp256k1 builds the generator table once per identity — keep
the identity.

## Cost

Measured on moxzid with `MOXZI_FUEL=1` (real wasm instruction counts):

| Step | Instructions | How often |
|---|--:|---|
| Verify one certificate (one BLS signature) | 1.44 billion | per certificate; two under a delegation |
| Verify a delegated `/subnet` certificate and extract node keys | 2.96 billion | once per subnet per `maxCertificateAgeNs` (5 minutes) |
| Verify one query response's node signature | 155 million | per query |

The IC's per-message limit is 40 billion instructions for an update and 5 billion for a query,
so every step fits inside one message. `Fp` arithmetic is `Nat`: `mo:bls12-381`'s own
benchmark measured fixed-limb Montgomery multiplication about 80x slower in pure Motoko.

## Proof

`scripts/ic_agent_gate.sh` in the moxzi repository:

- **Known-answer tests**, built by both moxzi and moc with the same count: request ids from
  the spec's worked example and agent-js, an envelope byte for byte, ed25519 and secp256k1
  keys, principals and signatures, hash trees (`test/Vectors.mo`); BLS hash-to-curve and G2
  decompression against `py_ecc` (`test/BlsVectors.mo`).
- **The interface spec against mainnet** (`test/SpecVectors.mo`, 121 checks): real query responses and
  `/subnet` certificates captured from `icp-api.io` — the ICP ledger (root subnet), ckBTC
  (delegated), and an Internet Identity rejection with `error_code` — whose node signatures
  must verify; a tampered reply, a wrong request id, another subnet's keys, stale and future
  timestamps, a stale certificate, an out-of-scope delegation and a wrong root key must all
  fail; hostile Ed25519 input must return false without trapping; 64 Ed25519 keys and signatures made by
  OpenSSL must be reproduced byte for byte, verify, and fail when altered; Candid routing vectors
  cross-checked with agent-js; the spec's example tree.
- **Live against PocketIC** (an NNS root subnet plus an application subnet, so answers come
  under a real delegation): verified anonymous and signed queries, a verified query
  rejection, secp256k1 `call` and `submit` + `poll`, `module_hash` / `controllers` /
  `metadata`, subnet read_state and query, canister creation and `canister_status` through
  `aaaaa-aa` routed by effective canister id, a canister signature and certified data issued
  by a real canister, the generated typed façade, and agent-js as an independent oracle.
- **Live against mainnet**: verified queries on the root subnet (ICP ledger) and a delegated
  subnet (ckBTC) and certified `module_hash` reads on both. Unreachable is a named skip;
  reachable and failing is a failure. The subnet query endpoint is proven on mainnet (a verified
  rejection); PocketIC's gateway does not serve it.

Dependencies: `cbor` (MIT), `sha2` (Apache-2.0), `libsecp256k1` (Apache-2.0),
`bls12-381` (Apache-2.0, `icdevsorg/bls12-381.mo`).

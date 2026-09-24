/// A moxzid actor that talks to a canister through `mo:ic-agent`. Text in, text out, so
/// the gate can drive it with one Candid text argument per call and read the answers.
import Agent "../../src/lib";
import Identity "../../src/Identity";
import Hash "../../src/Hash";
import Certificate "../../src/Certificate";
import Time "mo:base/Time";
import Int "mo:base/Int";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";

persistent actor {
  var host = "";
  var canister = "aaaaa-aa";
  transient var agent : ?Agent.Agent = null;
  transient var rootKey : Blob = Agent.MAINNET_ROOT_KEY;

  // Fixed keys: the gate checks the principals PocketIC reports against these.
  let ED_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  let SECP_SECRET = "0000000000000000000000000000000000000000000000000000000000000001";

  func hex(t : Text) : Blob = switch (Hash.fromHex(t)) { case (?b) b; case null Debug.trap("bad hex " # t) };
  func a() : Agent.Agent = switch agent { case (?x) x; case null Debug.trap("configure first") };
  func target() : Principal = Principal.fromText(canister);

  /// `who` is anonymous | ed25519 | secp256k1. `rootKeyHex` overrides the mainnet default
  /// (G2: certificates are now VERIFIED, so a PocketIC/local-replica target must pass ITS
  /// OWN root key here -- `doStatus` reports it -- or every certificate-consuming call
  /// (`doCall`, `doSubmit`+`doPoll`) fails with `#err(#certificate ...)`); "" keeps mainnet's.
  public func configure(h : Text, c : Text, who : Text, rootKeyHex : Text) : async () {
    host := h;
    canister := c;
    let identity : Identity.Identity = switch who {
      case "ed25519" Identity.ed25519(hex(ED_SEED));
      case "secp256k1" Identity.secp256k1(hex(SECP_SECRET));
      case _ #anonymous;
    };
    let base = Agent.defaults(h, identity);
    rootKey := if (rootKeyHex == "") Agent.MAINNET_ROOT_KEY else hex(rootKeyHex);
    let cfg = { base with rootKey = ?rootKey };
    agent := ?Agent.Agent(cfg);
  };

  public func principal() : async Text { Principal.toText(a().principal()) };

  public func doQuery(method : Text, argHex : Text) : async Text {
    switch (await* a().queryCall(target(), method, hex(argHex))) {
      case (#ok r) Hash.toHex(r);
      case (#err e) "ERR " # debug_show e;
    }
  };

  public func doSubmit(method : Text, argHex : Text) : async Text {
    switch (await* a().submit(target(), method, hex(argHex))) {
      case (#ok rid) Hash.toHex(rid);
      case (#err e) "ERR " # debug_show e;
    }
  };

  public func doPoll(ridHex : Text) : async Text {
    switch (await* a().poll(target(), hex(ridHex))) {
      case (#ok(#pending(#received))) "pending received";
      case (#ok(#pending(#processing))) "pending processing";
      case (#ok(#replied r)) "replied " # Hash.toHex(r);
      case (#ok(#rejected rj)) "rejected " # debug_show rj;
      case (#ok(#done)) "done";
      case (#ok(#unknown)) "unknown";
      case (#err e) "ERR " # debug_show e;
    }
  };

  public func doCall(method : Text, argHex : Text, maxPolls : Nat) : async Text {
    switch (await* a().call(target(), method, hex(argHex), maxPolls)) {
      case (#ok r) Hash.toHex(r);
      case (#err e) "ERR " # debug_show e;
    }
  };

  public func doStatus() : async Text {
    switch (await* a().status()) {
      case (#ok s) { switch (s.rootKey) { case (?k) Hash.toHex(k); case null "no root key" } };
      case (#err e) "ERR " # debug_show e;
    }
  };

  func err(e : Agent.Error) : Text = "ERR " # debug_show e;
  func policy() : Certificate.Policy = { now = ?Int.abs(Time.now()); maxAgeNs = Certificate.FIVE_MINUTES_NS; maxDelegationAgeNs = null };

  /// Which endpoints the agent is on after any fallback ("query/read_state/call").
  public func apiVersions() : async Text { let v = a().apiVersions(); v.query_ # "/" # v.readState # "/" # v.call };

  /// A query that REJECTS: the rejection must come back verified, as `#rejected`.
  public func doQueryReject(method : Text) : async Text {
    switch (await* a().queryCall(target(), method, "DIDL\00\00")) {
      case (#ok r) "UNEXPECTED reply " # Hash.toHex(r);
      case (#err(#rejected rj)) "rejected " # debug_show rj.code;
      case (#err e) err(e);
    }
  };

  public func doModuleHash() : async Text {
    switch (await* a().moduleHash(target())) { case (#ok(?h)) Hash.toHex(h); case (#ok null) "empty"; case (#err e) err(e) };
  };

  public func doControllers() : async Text {
    switch (await* a().controllers(target())) {
      case (#ok ps) { var t = ""; for (p in ps.values()) { t #= (if (t == "") "" else ",") # Principal.toText(p) }; t };
      case (#err e) err(e);
    }
  };

  public func doMetadata(name : Text) : async Text {
    switch (await* a().metadata(target(), name)) { case (#ok(?b)) "bytes " # debug_show b.size(); case (#ok null) "absent"; case (#err e) err(e) };
  };

  /// provisional_create_canister_with_cycles: the argument names no canister, so the
  /// effective id is chosen explicitly (spec, "Effective canister id").
  public func doCreate() : async Text {
    let arg = to_candid ({ amount = ?(1_000_000_000_000 : Nat); settings = (null : ?{ controllers : ?[Principal] }) });
    let o = { Agent.NO_OPTIONS with effectiveCanisterId = ?target() };
    switch (await* a().callWith(Agent.managementCanister(), "provisional_create_canister_with_cycles", arg, 40, o)) {
      case (#ok r) { let ?x : ?{ canister_id : Principal } = from_candid(r) else return "undecodable"; Principal.toText(x.canister_id) };
      case (#err e) err(e);
    }
  };

  /// provisional_create_canister_with_cycles through the SUBNET call endpoint
  /// (`/api/v4/subnet/<subnet>/call`), certificate scoped to that subnet.
  public func doSubnetCreate(subnet : Text) : async Text {
    let arg = to_candid ({ amount = ?(1_000_000_000_000 : Nat); settings = (null : ?{ controllers : ?[Principal] }) });
    switch (await* a().subnetCall(Principal.fromText(subnet), "provisional_create_canister_with_cycles", arg, 40)) {
      case (#ok r) { let ?x : ?{ canister_id : Principal } = from_candid(r) else return "undecodable"; Principal.toText(x.canister_id) };
      case (#err e) err(e);
    }
  };

  /// With no effective id, the same call must be refused BEFORE anything is sent.
  public func doCreateWithoutEffective() : async Text {
    let arg = to_candid ({ amount = ?(1 : Nat); settings = (null : ?{ controllers : ?[Principal] }) });
    switch (await* a().call(Agent.managementCanister(), "provisional_create_canister_with_cycles", arg, 1)) {
      case (#err(#noEffectiveCanisterId _)) "refused";
      case (#ok _) "UNEXPECTED ok";
      case (#err e) err(e);
    }
  };

  /// canister_status through aaaaa-aa: the agent must route it to the canister in the argument.
  public func doCanisterStatus(cid : Text) : async Text {
    let arg = to_candid ({ canister_id = Principal.fromText(cid) });
    switch (await* a().call(Agent.managementCanister(), "canister_status", arg, 40)) {
      case (#ok r) {
        let ?x : ?{ status : { #running; #stopping; #stopped }; module_hash : ?Blob } = from_candid(r) else return "undecodable";
        (switch (x.status) { case (#running) "running"; case (#stopping) "stopping"; case (#stopped) "stopped" }) # (if (x.module_hash == null) " empty" else " installed")
      };
      case (#err e) err(e);
    }
  };

  public func doReadSubnetTime(subnet : Text) : async Text {
    switch (await* a().readSubnetState(Principal.fromText(subnet), [["time"]])) {
      case (#ok c) { switch (Certificate.time(c.tree)) { case (?t) "time " # debug_show (t > 0); case null "no time" } };
      case (#err e) err(e);
    }
  };

  public func doSubnetQuery(subnet : Text) : async Text {
    let arg = to_candid ({ canister_id = target() });
    switch (await* a().subnetQuery(Principal.fromText(subnet), "list_canisters", arg)) {
      case (#ok r) "bytes " # debug_show r.size();
      case (#err e) err(e);
    }
  };

  /// A canister signature by `signer` over `payload`, fetched through a VERIFIED query and
  /// checked by `Certificate.verifyCanisterSignature`; then the same signature against a
  /// different payload, which must fail.
  public func doCanisterSignature(signer : Text, seedHex : Text, payloadHex : Text) : async Text {
    let sid = Principal.fromText(signer);
    let seed = hex(seedHex);
    let payload = hex(payloadHex);
    switch (await* a().call(sid, "sign", to_candid (seed, payload), 40)) { case (#err e) return "sign: " # err(e); case (#ok _) {} };
    let sigBlob = switch (await* a().queryCall(sid, "signature", to_candid ())) {
      case (#ok r) { let ?x : ??Blob = from_candid(r) else return "undecodable"; switch x { case (?b) b; case null return "no signature" } };
      case (#err e) return "signature: " # err(e);
    };
    let cid = Principal.toBlob(sid);
    let body = Array.flatten<Nat8>([[Nat8.fromNat(cid.size())], Blob.toArray(cid), Blob.toArray(seed)]);
    let der = Blob.fromArray(Array.flatten<Nat8>([
      [0x30, Nat8.fromNat(14 + 2 + body.size() + 1), 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb8, 0x43, 0x01, 0x02, 0x03, Nat8.fromNat(body.size() + 1), 0x00],
      body,
    ]));
    let good = switch (Certificate.verifyCanisterSignature(payload, der, sigBlob, rootKey, policy())) { case (#ok()) "valid"; case (#err e) "INVALID " # debug_show e };
    let bad = switch (Certificate.verifyCanisterSignature("other payload", der, sigBlob, rootKey, policy())) { case (#ok()) "ACCEPTED-FORGERY"; case (#err(#badSignature)) "forgery-rejected"; case (#err e) "other " # debug_show e };
    good # " " # bad
  };

  /// The signer's certified data, from its data certificate, verified and compared to the
  /// tree root it claims.
  public func doCertifiedData(signer : Text) : async Text {
    let sid = Principal.fromText(signer);
    let certBlob = switch (await* a().queryCall(sid, "certificate", to_candid ())) {
      case (#ok r) { let ?x : ??Blob = from_candid(r) else return "undecodable"; switch x { case (?b) b; case null return "no certificate" } };
      case (#err e) return err(e);
    };
    let want = switch (await* a().queryCall(sid, "expectedCertifiedData", to_candid ())) {
      case (#ok r) { let ?x : ?Blob = from_candid(r) else return "undecodable"; x };
      case (#err e) return err(e);
    };
    switch (Certificate.certifiedData(certBlob, sid, rootKey, policy())) {
      case (#ok cd) if (cd == want) "certified " # Hash.toHex(cd) else "MISMATCH";
      case (#err e) "INVALID " # debug_show e;
    }
  };
};

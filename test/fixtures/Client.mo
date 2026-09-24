/// A moxzid actor that talks to a canister through `mo:ic-agent`. Text in, text out, so
/// the gate can drive it with one Candid text argument per call and read the answers.
import Agent "../../src/lib";
import Identity "../../src/Identity";
import Hash "../../src/Hash";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";

persistent actor {
  var host = "";
  var canister = "aaaaa-aa";
  transient var agent : ?Agent.Agent = null;

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
    let cfg = if (rootKeyHex == "") base else { { base with rootKey = ?hex(rootKeyHex) } };
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
};

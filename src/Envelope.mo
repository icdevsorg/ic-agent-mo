/// The request content maps of the IC's HTTP interface (call, query, read_state), their
/// request ids, and the signed CBOR envelope a boundary node accepts.
import Hash "Hash";
import Cbor "Cbor";
import Identity "Identity";
import Principal "mo:base/Principal";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Text "mo:base/Text";
import Nat64 "mo:base/Nat64";

module {
  public type Call = { sender : Principal; canister : Principal; method : Text; arg : Blob; expiry : Nat64; nonce : ?Blob };
  public type ReadState = { sender : Principal; paths : [[Blob]]; expiry : Nat64 };
  public type Content = {
    #call : Call;
    #queryCall : Call;
    #readState : ReadState;
  };

  /// Domain separators: a length byte, then the tag.
  public let DOMAIN_REQUEST : Blob = "\0aic-request";
  public let DOMAIN_DELEGATION : Blob = "\1aic-request-auth-delegation";

  func callFields(requestType : Text, c : Call) : [(Text, Hash.Value)] {
    let buf = Buffer.Buffer<(Text, Hash.Value)>(7);
    buf.add(("request_type", #text requestType));
    buf.add(("sender", #blob(Principal.toBlob(c.sender))));
    switch (c.nonce) { case (?n) buf.add(("nonce", #blob n)); case null {} };
    buf.add(("ingress_expiry", #nat(Nat64.toNat(c.expiry))));
    buf.add(("canister_id", #blob(Principal.toBlob(c.canister))));
    buf.add(("method_name", #text(c.method)));
    buf.add(("arg", #blob(c.arg)));
    Buffer.toArray(buf)
  };

  public func hashFields(c : Content) : [(Text, Hash.Value)] = switch c {
    case (#call x) callFields("call", x);
    case (#queryCall x) callFields("query", x);
    case (#readState x) [
      ("request_type", #text "read_state"),
      ("sender", #blob(Principal.toBlob(x.sender))),
      ("ingress_expiry", #nat(Nat64.toNat(x.expiry))),
      ("paths", #list(Array.map<[Blob], Hash.Value>(x.paths, func(p) = #list(Array.map<Blob, Hash.Value>(p, func(b) = #blob b))))),
    ];
  };

  public func requestId(c : Content) : Blob = Hash.hashOfMap(hashFields(c));

  func cborOf(v : Hash.Value) : Cbor.Value = switch v {
    case (#blob b) Cbor.bytes(b);
    case (#text t) Cbor.text(t);
    case (#nat n) Cbor.nat64(Nat64.fromNat(n));
    case (#list vs) Cbor.array(Array.map<Hash.Value, Cbor.Value>(vs, cborOf));
    // Keys in bytewise order: the hash does not care, but a canonical envelope compares
    // byte for byte with agent-js's (and with the replica's own encoders).
    case (#map fs) {
      let sorted = Array.sort<(Text, Hash.Value)>(fs, func(a, b) = Text.compare(a.0, b.0));
      Cbor.map(Array.map<(Text, Hash.Value), (Text, Cbor.Value)>(sorted, func((k, x)) = (k, cborOf(x))))
    };
  };

  public func content(c : Content) : Cbor.Value = cborOf(#map(hashFields(c)));

  func delegationValue(sd : Identity.SignedDelegation) : Cbor.Value {
    let d = sd.delegation;
    let buf = Buffer.Buffer<(Text, Cbor.Value)>(3);
    buf.add(("pubkey", Cbor.bytes(d.pubkey)));
    buf.add(("expiration", Cbor.nat64(d.expiration)));
    switch (d.targets) {
      case (?ts) buf.add(("targets", Cbor.array(Array.map<Principal, Cbor.Value>(ts, func(p) = Cbor.bytes(Principal.toBlob(p))))));
      case null {};
    };
    Cbor.map([("delegation", Cbor.map(Buffer.toArray(buf))), ("signature", Cbor.bytes(sd.signature))])
  };

  /// The bytes a delegation's signature covers.
  public func delegationHash(d : Identity.Delegation) : Blob {
    let buf = Buffer.Buffer<(Text, Hash.Value)>(3);
    buf.add(("pubkey", #blob(d.pubkey)));
    buf.add(("expiration", #nat(Nat64.toNat(d.expiration))));
    switch (d.targets) {
      case (?ts) buf.add(("targets", #list(Array.map<Principal, Hash.Value>(ts, func(p) = #blob(Principal.toBlob(p))))));
      case null {};
    };
    Hash.concat([DOMAIN_DELEGATION, Hash.hashOfMap(Buffer.toArray(buf))])
  };

  /// The signed envelope: `content`, and for a signing identity `sender_pubkey`,
  /// `sender_sig` over "\x0Aic-request" ++ request id, plus `sender_delegation` for a chain.
  public func encode(c : Content, id : Identity.Identity) : Blob {
    let body = content(c);
    let message = Hash.concat([DOMAIN_REQUEST, requestId(c)]);
    let fields : [(Text, Cbor.Value)] = switch id {
      case (#anonymous) [("content", body)];
      case (#signer s) [("content", body), ("sender_pubkey", Cbor.bytes(s.publicKey)), ("sender_sig", Cbor.bytes(s.sign(message)))];
      case (#delegated d) [
        ("content", body),
        ("sender_pubkey", Cbor.bytes(d.publicKey)),
        ("sender_sig", Cbor.bytes(d.signer.sign(message))),
        ("sender_delegation", Cbor.array(Array.map<Identity.SignedDelegation, Cbor.Value>(d.chain, delegationValue))),
      ];
    };
    Cbor.encode(Cbor.map(fields))
  };
}

/// Query-response signatures (interface spec, "Request: Query call"). Every query reply
/// carries `signatures : [+ node-signature]`, each an Ed25519 signature by ONE replica
/// node over
///
///     "\x0Bic-response" · hash_of_map({ status; reply | reject_code, reject_message,
///                                        error_code?; timestamp; request_id })
///
/// and the node's public key lives, certified, at `/subnet/<subnet>/node/<node>/public_key`
/// in a `read_state` certificate for the subnet that answered. This module is the part of
/// that check that needs no network: the response hash, the DER key unwrap, and the Ed25519
/// check (`Ed25519.mo`: total, fast, never traps on hostile input).
import Hash "Hash";
import Cbor "Cbor";
import Buffer "mo:base/Buffer";
import Nat64 "mo:base/Nat64";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Ed25519 "Ed25519";

module {
  public let DOMAIN_RESPONSE : Blob = "\0bic-response";

  /// RFC 8410 SubjectPublicKeyInfo prefix for an Ed25519 key (44 bytes in all).
  public let ED25519_DER_PREFIX : [Nat8] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

  /// The response a node signed, as the spec's `verify_node_signatures` names its fields.
  public type Response = {
    /// The reply map exactly as the node sent it (normally just `arg`), so any field the
    /// node signed is hashed -- `mapFields` converts the decoded CBOR.
    #replied : [(Text, Hash.Value)];
    #rejected : { code : Nat; message : Text; errorCode : ?Text };
  };

  /// `"\x0Bic-response" · hash_of_map({...})`: the exact bytes the node's key signed.
  public func message(r : Response, timestamp : Nat, requestId : Blob) : Blob {
    let fields : [(Text, Hash.Value)] = switch r {
      case (#replied x) [
        ("status", #text "replied"),
        ("reply", #map(x)),
        ("timestamp", #nat timestamp),
        ("request_id", #blob requestId),
      ];
      case (#rejected x) {
        let base : [(Text, Hash.Value)] = [
          ("status", #text "rejected"),
          ("reject_code", #nat(x.code)),
          ("reject_message", #text(x.message)),
          ("timestamp", #nat timestamp),
          ("request_id", #blob requestId),
        ];
        // `error_code` is optional in the response; a field that is absent is absent from
        // the hashed map too (representation-independent hashing omits omitted fields).
        switch (x.errorCode) { case (?e) Array.append(base, [("error_code", #text e)]); case null base };
      };
    };
    Hash.concat([DOMAIN_RESPONSE, Hash.hashOfMap(fields)])
  };

  /// A decoded CBOR value as the representation-independent hash sees it: byte strings,
  /// text, naturals, arrays and text-keyed maps. Null for anything else (a node never signs
  /// floats or negative numbers in a query response).
  public func hashValue(v : Cbor.Value) : ?Hash.Value = switch v {
    case (#majorType0 n) ?#nat(Nat64.toNat(n));
    case (#majorType2 b) ?#blob(Blob.fromArray(b));
    case (#majorType3 t) ?#text t;
    case (#majorType4 vs) {
      let out = Buffer.Buffer<Hash.Value>(vs.size());
      for (x in vs.values()) { switch (hashValue(x)) { case (?h) out.add(h); case null return null } };
      ?#list(Buffer.toArray(out))
    };
    case (#majorType5 _) { switch (mapFields(v)) { case (?m) ?#map m; case null null } };
    case _ null;
  };

  public func mapFields(v : Cbor.Value) : ?[(Text, Hash.Value)] = switch v {
    case (#majorType5 fs) {
      let out = Buffer.Buffer<(Text, Hash.Value)>(fs.size());
      for ((k, x) in fs.values()) {
        switch (k, hashValue(x)) { case (#majorType3 t, ?h) out.add((t, h)); case _ return null };
      };
      ?Buffer.toArray(out)
    };
    case _ null;
  };

  /// The raw 32-byte key out of its RFC 8410 DER wrapping, or null if it is not one.
  public func unwrapDer(der : Blob) : ?Blob {
    let b = Blob.toArray(der);
    if (b.size() != ED25519_DER_PREFIX.size() + 32) return null;
    var i = 0;
    while (i < ED25519_DER_PREFIX.size()) { if (b[i] != ED25519_DER_PREFIX[i]) return null; i += 1 };
    ?Blob.fromArray(Array.tabulate<Nat8>(32, func(j) = b[ED25519_DER_PREFIX.size() + j]))
  };

  /// Ed25519 verification of a node signature: false, never a trap, on malformed input.
  public func verifyEd25519(sig : Blob, msg : Blob, pub : Blob) : Bool = Ed25519.verify(sig, msg, pub);
}

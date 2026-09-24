/// The little CBOR the IC's HTTP interface needs, over `mo:cbor`: maps with text keys,
/// byte strings, text, unsigned integers, arrays, and the self-describe tag (55799)
/// every request and response carries.
import C "mo:cbor";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Nat64 "mo:base/Nat64";
import Debug "mo:base/Debug";

module {
  public type Value = C.Value;

  public let SELF_DESCRIBE : Nat64 = 55799;

  public func bytes(b : Blob) : Value = #majorType2(Blob.toArray(b));
  public func text(t : Text) : Value = #majorType3 t;
  public func nat64(n : Nat64) : Value = #majorType0 n;
  public func array(vs : [Value]) : Value = #majorType4 vs;
  public func map(fields : [(Text, Value)]) : Value =
    #majorType5(Array.map<(Text, Value), (Value, Value)>(fields, func((k, v)) = (#majorType3 k, v)));

  /// Encode with the self-describe tag in front, as agents and replicas do.
  public func encode(v : Value) : Blob {
    switch (C.toBytes(#majorType6 { tag = SELF_DESCRIBE; value = v })) {
      case (#ok bs) Blob.fromArray(bs);
      // Our own values are always encodable; a failure here is a bug, not an input error.
      case (#err e) Debug.trap("cbor encode: " # debug_show e);
    }
  };

  /// Decode, dropping the self-describe tag if present.
  public func decode(b : Blob) : ?Value {
    switch (C.fromBytes(b.values())) {
      case (#ok(#majorType6 t)) { if (t.tag == SELF_DESCRIBE) ?t.value else ?(#majorType6 t) };
      case (#ok v) ?v;
      case (#err _) null;
    }
  };

  public func field(v : Value, key : Text) : ?Value = switch v {
    case (#majorType5 fs) {
      for ((k, x) in fs.values()) {
        switch k { case (#majorType3 t) { if (t == key) return ?x }; case _ {} };
      };
      null
    };
    case _ null;
  };

  public func asBytes(v : ?Value) : ?Blob = switch v { case (?(#majorType2 bs)) ?Blob.fromArray(bs); case _ null };
  public func asText(v : ?Value) : ?Text = switch v { case (?(#majorType3 t)) ?t; case _ null };
  public func asNat(v : ?Value) : ?Nat = switch v { case (?(#majorType0 n)) ?Nat64.toNat(n); case _ null };
  public func asArray(v : ?Value) : ?[Value] = switch v { case (?(#majorType4 vs)) ?vs; case _ null };
}

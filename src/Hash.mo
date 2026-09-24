/// Representation-independent hashing (interface spec, "Request ids"). A request id is a
/// hash of the request's CONTENT MAP, independent of how the CBOR happened to be laid out,
/// so two agents that encode differently still name the same request.
import Sha256 "mo:sha2/Sha256";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Text "mo:base/Text";
import Nat32 "mo:base/Nat32";
import Char "mo:base/Char";

module {
  public type Value = {
    #blob : Blob;
    #text : Text;
    #nat : Nat;
    #list : [Value];
    #map : [(Text, Value)];
  };

  public func sha256(b : Blob) : Blob = Sha256.fromBlob(#sha256, b);
  public func sha224(b : Blob) : Blob = Sha256.fromBlob(#sha224, b);

  public func concat(parts : [Blob]) : Blob {
    let buf = Buffer.Buffer<Nat8>(64);
    for (p in parts.values()) { for (x in p.values()) { buf.add(x) } };
    Blob.fromArray(Buffer.toArray(buf))
  };

  /// Unsigned LEB128: the spec's byte form of a natural number before it is hashed.
  public func leb128(n : Nat) : Blob {
    let buf = Buffer.Buffer<Nat8>(10);
    var v = n;
    loop {
      let byte = Nat8.fromNat(v % 128);
      v := v / 128;
      if (v == 0) { buf.add(byte); return Blob.fromArray(Buffer.toArray(buf)) }
      else buf.add(byte | 0x80);
    };
  };

  /// The inverse, for LEB128 leaves in a certificate (`reject_code`).
  public func unleb128(b : Blob) : Nat {
    var n = 0;
    var shift = 1;
    for (x in b.values()) {
      n += Nat8.toNat(x & 0x7f) * shift;
      shift *= 128;
    };
    n
  };

  public func hash(v : Value) : Blob = switch v {
    case (#blob b) sha256(b);
    case (#text t) sha256(Text.encodeUtf8(t));
    case (#nat n) sha256(leb128(n));
    case (#list vs) sha256(concat(Array.map<Value, Blob>(vs, hash)));
    case (#map fs) hashOfMap(fs);
  };

  /// hash_of_map: sha256(key) ++ hash(value) per field, the pairs sorted bytewise, the
  /// concatenation hashed.
  public func hashOfMap(fields : [(Text, Value)]) : Blob {
    let pairs = Array.map<(Text, Value), Blob>(fields, func((k, v)) = concat([sha256(Text.encodeUtf8(k)), hash(v)]));
    sha256(concat(Array.sort<Blob>(pairs, Blob.compare)))
  };

  public func toHex(b : Blob) : Text {
    let digits = "0123456789abcdef";
    let ds = Text.toArray(digits);
    var t = "";
    for (x in b.values()) {
      t #= Text.fromChar(ds[Nat8.toNat(x / 16)]) # Text.fromChar(ds[Nat8.toNat(x % 16)]);
    };
    t
  };

  public func fromHex(t : Text) : ?Blob {
    let cs = Text.toArray(t);
    if (cs.size() % 2 != 0) return null;
    let buf = Buffer.Buffer<Nat8>(cs.size() / 2);
    var i = 0;
    while (i < cs.size()) {
      let hi = nibble(cs[i]);
      let lo = nibble(cs[i + 1]);
      switch (hi, lo) {
        case (?h, ?l) buf.add(Nat8.fromNat(h * 16 + l));
        case _ return null;
      };
      i += 2;
    };
    ?Blob.fromArray(Buffer.toArray(buf))
  };

  func nibble(c : Char) : ?Nat {
    let n = Nat32.toNat(Char.toNat32(c));
    if (n >= 48 and n <= 57) ?(n - 48)
    else if (n >= 97 and n <= 102) ?(n - 87)
    else if (n >= 65 and n <= 70) ?(n - 55)
    else null
  };
}

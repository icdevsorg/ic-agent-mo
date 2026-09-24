/// Just enough Candid to route a management-canister request (interface spec, "Effective
/// canister id"): an ingress call to `aaaaa-aa` must be sent to the canister it is ABOUT --
/// the principal in the first argument's `canister_id` field (or `target_canister` for
/// `install_chunked_code`). Finding that field means walking the type table and skipping
/// every value before it, so this is a complete Candid VALUE SKIPPER for every wire type --
/// but it builds nothing: it answers "which principal is in field F of the first argument's
/// record", or null.
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Text "mo:base/Text";
import Int "mo:base/Int";
import Principal "mo:base/Principal";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";

module {
  /// Candid's field-name hash: h = h * 223 + byte, mod 2^32.
  public func fieldHash(name : Text) : Nat {
    var h : Nat32 = 0;
    for (b in Text.encodeUtf8(name).values()) { h := h *% 223 +% Nat32.fromNat(Nat8.toNat(b)) };
    Nat32.toNat(h)
  };

  type T = {
    #prim : Int;                     // negative opcode
    #opt : Int; #vec : Int;          // element type (index or negative opcode)
    #record : [(Nat, Int)]; #variant : [(Nat, Int)];
    #func_; #service;
  };

  /// A cursor that fails (returns null) instead of trapping on short input.
  class Reader(bytes : [Nat8]) {
    var i = 0;
    public var bad = false;
    public func byte() : Nat { if (i >= bytes.size()) { bad := true; return 0 }; let b = Nat8.toNat(bytes[i]); i += 1; b };
    public func skip(n : Nat) { if (i + n > bytes.size()) { bad := true; i := bytes.size() } else i += n };
    public func take(n : Nat) : [Nat8] {
      if (i + n > bytes.size()) { bad := true; i := bytes.size(); return [] };
      let out = Array.tabulate<Nat8>(n, func(k) = bytes[i + k]);
      i += n;
      out
    };
    public func leb() : Nat {
      var n = 0; var mul = 1;
      loop { let b = byte(); if (bad) return 0; n += (b % 128) * mul; mul *= 128; if (b < 128) return n };
    };
    public func sleb() : Int {
      var n : Int = 0; var mul : Int = 1;
      loop {
        let b = byte(); if (bad) return 0;
        n += (b % 128) * mul; mul *= 128;
        if (b < 128) { if (b >= 64) n -= mul; return n };
      };
    };
  };

  /// The principal in field `name` of the first argument, if the first argument is a record
  /// with such a field of type `principal`. Null for anything else, including malformed input.
  public func principalField(arg : Blob, name : Text) : ?Principal {
    let r = Reader(Blob.toArray(arg));
    if (r.byte() != 0x44 or r.byte() != 0x49 or r.byte() != 0x44 or r.byte() != 0x4c) return null;
    let nTypes = r.leb();
    if (r.bad or nTypes > 10_000) return null;
    let table = Buffer.Buffer<T>(nTypes);
    var k = 0;
    while (k < nTypes) {
      let op = r.sleb();
      let t : T = switch op {
        case (-18) #opt(r.sleb());
        case (-19) #vec(r.sleb());
        case (-20 or -21) {
          let n = r.leb();
          if (r.bad or n > 100_000) return null;
          let fs = Buffer.Buffer<(Nat, Int)>(n);
          var j = 0;
          while (j < n) { let h = r.leb(); let ty = r.sleb(); fs.add((h, ty)); j += 1 };
          if (op == -20) #record(Buffer.toArray(fs)) else #variant(Buffer.toArray(fs))
        };
        case (-22) {  // func: arg types, result types, annotations
          let na = r.leb(); var j = 0; while (j < na and not r.bad) { ignore r.sleb(); j += 1 };
          let nr = r.leb(); j := 0; while (j < nr and not r.bad) { ignore r.sleb(); j += 1 };
          let nn = r.leb(); r.skip(nn);
          #func_
        };
        case (-23) {  // service: methods (name, func type)
          let nm = r.leb(); var j = 0;
          while (j < nm and not r.bad) { let l = r.leb(); r.skip(l); ignore r.sleb(); j += 1 };
          #service
        };
        case _ return null;
      };
      if (r.bad) return null;
      table.add(t);
      k += 1;
    };
    let nArgs = r.leb();
    if (r.bad or nArgs == 0) return null;
    let first = r.sleb();
    var a = 1;
    while (a < nArgs and not r.bad) { ignore r.sleb(); a += 1 };
    if (r.bad or first < 0) return null;
    let fields = switch (table.getOpt(Int.abs(first))) { case (?#record fs) fs; case _ return null };
    let want = fieldHash(name);

    func resolve(t : Int) : ?T = if (t < 0) ?#prim t else table.getOpt(Int.abs(t));

    func readPrincipal() : ?Blob {
      if (r.byte() != 1) return null;
      let l = r.leb();
      if (r.bad or l > 29) return null;
      let b = r.take(l);
      if (r.bad) null else ?Blob.fromArray(b)
    };

    // Skip one value of type `t`. `depth` bounds recursion through self-referential types.
    func skipValue(t : Int, depth : Nat) : Bool {
      if (depth > 200 or r.bad) return false;
      switch (resolve(t)) {
        case null false;
        case (?#prim p) {
          switch p {
            case (-1 or -16) {};                       // null, reserved
            case (-2 or -5 or -9) r.skip(1);           // bool, nat8, int8
            case (-6 or -10) r.skip(2);
            case (-7 or -11 or -13) r.skip(4);
            case (-8 or -12 or -14) r.skip(8);
            case (-3) ignore r.leb();
            case (-4) ignore r.sleb();
            case (-15) { let l = r.leb(); r.skip(l) };  // text
            case (-24) { ignore readPrincipal() };
            case _ return false;                       // empty (-17) has no values
          };
          not r.bad
        };
        case (?#opt e) { switch (r.byte()) { case 0 true; case 1 skipValue(e, depth + 1); case _ false } };
        case (?#vec e) {
          let n = r.leb();
          if (r.bad) return false;
          if (e == -5 or e == -9) { r.skip(n); return not r.bad };
          if (n > 1_000_000) return false;   // no management argument has a vector this long
          var j = 0;
          while (j < n) { if (not skipValue(e, depth + 1)) return false; j += 1 };
          true
        };
        case (?#record fs) { for ((_, ft) in fs.values()) { if (not skipValue(ft, depth + 1)) return false }; true };
        case (?#variant fs) {
          let idx = r.leb();
          if (r.bad or idx >= fs.size()) return false;
          skipValue(fs[idx].1, depth + 1)
        };
        case (?#func_) { if (r.byte() != 1) return false; if (readPrincipal() == null) return false; let l = r.leb(); r.skip(l); not r.bad };
        case (?#service) { readPrincipal() != null };
      }
    };

    for ((h, ft) in fields.values()) {
      if (h == want) {
        if (ft != -24) return null;
        return switch (readPrincipal()) { case (?b) ?Principal.fromBlob(b); case null null };
      };
      if (not skipValue(ft, 0)) return null;
    };
    null
  };

}

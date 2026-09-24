/// Round-trips a value of every generated type through Candid: what `to_candid` writes,
/// `from_candid` reads back equal, for the types `types.did` declares. Built next to a
/// generated `Types.mo` by the gate.
import Types "Types";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";

persistent actor {
  var passed = 0;
  func expect(name : Text, ok : Bool) { if (ok) { passed += 1 } else { Debug.trap("FAIL: " # name) } };

  public func check() : async Nat {
    passed := 0;
    let tree : Types.Tree = #node(#leaf 1, #node(#leaf 2, #leaf 3));
    let rec : Types.Rec = {
      id = 18446744073709551615; name = "moxzi"; tags = ["a", "b"]; bytes = "\01\02\ff";
      owner = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai"); maybe = ?(-7); nested = ?(?true);
      tuple = (5, "five"); tree; flt = 1.5; when = -1_000_000_000_000_000_000; big = 2 ** 100;
      sub = { x = -8; y = 65535; z = -9_223_372_036_854_775_808; w = 4_294_967_295; v = -32768 };
      status = #retired { at = 42 }; flag = true; nothing = null; matrix = ["\00", "\01\02"];
    };
    expect("Rec round trip", (from_candid(to_candid(rec)) : ?Types.Rec) == ?rec);
    expect("Tree round trip", (from_candid(to_candid(tree)) : ?Types.Tree) == ?tree);
    let st : Types.Status = #suspended "why";
    expect("Status round trip", (from_candid(to_candid(st)) : ?Types.Status) == ?st);
    expect("two results decode as a pair", (from_candid(to_candid(rec, st)) : ?(Types.Rec, Types.Status)) == ?(rec, st));
    expect("nested opt keeps its levels", (from_candid(to_candid({ rec with nested = ?null })) : ?Types.Rec) == ?{ rec with nested = ?null });
    expect("unit result", (from_candid(to_candid()) : ?()) == ?());
    passed
  };
};

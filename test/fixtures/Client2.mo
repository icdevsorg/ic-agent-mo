/// The Counter façade in use: `Counter.connect(agent, p)` and typed calls, no Candid.
/// Built next to a generated `Counter.mo` by the gate.
import Agent "mo:ic-agent";
import Counter "Counter";
import Principal "mo:base/Principal";
import Nat "mo:base/Nat";
import Nat32 "mo:base/Nat32";
import Char "mo:base/Char";
import Text "mo:base/Text";
import Buffer "mo:base/Buffer";
import Blob "mo:base/Blob";
import Nat8 "mo:base/Nat8";
import Debug "mo:base/Debug";

persistent actor {
  transient var facade : ?Counter.Facade = null;
  // A tiny local hex decoder (not `Hash.fromHex`, to avoid a second cross-package relative
  // import the gate's sed rewrite would also have to know about -- see `Client.mo`'s `hex`).
  func nibble(c : Char) : Nat {
    let n = Nat32.toNat(Char.toNat32(c));
    if (n >= 48 and n <= 57) { n - 48 } else if (n >= 97 and n <= 102) { n - 87 } else { Debug.trap("bad hex digit") };
  };
  func hex(t : Text) : Blob {
    let cs = Text.toArray(t);
    let buf = Buffer.Buffer<Nat8>(cs.size() / 2);
    var i = 0;
    while (i + 1 < cs.size()) {
      buf.add(Nat8.fromNat(nibble(cs[i]) * 16 + nibble(cs[i + 1])));
      i += 2;
    };
    Blob.fromArray(Buffer.toArray(buf))
  };
  /// `rootKeyHex`: see `Client.mo`'s `configure` -- "" keeps the mainnet default.
  public func configure(host : Text, canister : Text, rootKeyHex : Text) : async () {
    let base = Agent.defaults(host, #anonymous);
    let cfg = if (rootKeyHex == "") base else { { base with rootKey = ?hex(rootKeyHex) } };
    facade := ?Counter.connectText(Agent.Agent(cfg), canister);
  };
  func f() : Counter.Facade = switch facade { case (?x) x; case null Debug.trap("configure first") };
  /// inc through the façade (submit + poll), then get: "inc=<n> get=<m>".
  public func run() : async Text {
    let n = switch (await* f().inc()) { case (#ok n) n; case (#err e) return "ERR inc " # debug_show e };
    let m = switch (await* f().get()) { case (#ok m) m; case (#err e) return "ERR get " # debug_show e };
    "inc=" # Nat.toText(n) # " get=" # Nat.toText(m)
  };
  /// The two-step form: submit now, poll until replied.
  public func runTicking() : async Text {
    let rid = switch (await* f().inc_submit()) { case (#ok r) r; case (#err e) return "ERR submit " # debug_show e };
    var polls = 0;
    while (polls < 40) {
      switch (await* f().inc_poll(rid)) {
        case (#ok(#replied n)) return "replied=" # Nat.toText(n) # " polls=" # Nat.toText(polls + 1);
        case (#ok(#pending _)) {};
        case (#ok(#unknown)) {};
        case (#ok other) return "ERR " # debug_show other;
        case (#err e) return "ERR poll " # debug_show e;
      };
      polls += 1;
    };
    "ERR still pending"
  };
};

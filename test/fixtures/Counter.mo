/// The canister the gate installs on PocketIC and drives from moxzid through the agent.
persistent actor Counter {
  var n : Nat = 0;
  public func inc() : async Nat { n += 1; n };
  public query func get() : async Nat { n };
  public shared query ({ caller }) func whoami() : async Principal { caller };
};

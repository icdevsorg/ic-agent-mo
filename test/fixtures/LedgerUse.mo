/// The NNS ledger façade compiles and its types are the interface's (build-only in the gate).
import Ledger "Ledger";
import Agent "mo:ic-agent";
import Principal "mo:base/Principal";

persistent actor {
  transient let ledger = Ledger.connectText(Agent.Agent(Agent.defaults("https://icp-api.io", #anonymous)), "ryjl3-tyaaa-aaaaa-aaaba-cai");
  public func name() : async Text {
    switch (await* ledger.icrc1_name()) { case (#ok n) n; case (#err e) debug_show e }
  };
  public func balance(owner : Principal) : async Nat {
    let acct : Ledger.Account = { owner; subaccount = null };
    switch (await* ledger.icrc1_balance_of(acct)) { case (#ok n) n; case (#err _) 0 }
  };
};

/// `mo:ic-agent` -- an Internet Computer agent in Motoko. Query, submit, poll and read
/// canisters over the IC's HTTP interface, signed by an identity, from an off-chain Motoko
/// program (a moxzid actor, a game, a browser tab) or from anywhere HTTPS outcalls exist.
///
/// An update call is TWO operations here: `submit` sends the envelope and returns the
/// request id at once; `poll` is one `read_state` round trip. A game courier submits on one
/// tick and polls on later ticks, so its own message never blocks on the network. `call`
/// composes the two for code that can afford to wait.
///
/// Certificates are decoded AND VERIFIED (alpha-7 G2): the BLS signature over the tree's root
/// hash is checked against the root key, following one delegation if the certificate carries
/// one. Verification is expensive in pure Motoko (`Bls12381.mo`'s module comment, and
/// `README.md`'s "Certificate verification cost" -- roughly 28-56 billion wasm instructions,
/// several seconds off-chain, PER CERTIFICATE) -- `Config.verify` is the escape hatch for a
/// caller who has already read that cost and wants a different tradeoff.
import Envelope "Envelope";
import Identity "Identity";
import Certificate "Certificate";
import Cbor "Cbor";
import Transport "Transport";
import Hash "Hash";
import Principal "mo:base/Principal";
import Time "mo:base/Time";
import Int "mo:base/Int";
import Nat64 "mo:base/Nat64";
import Option "mo:base/Option";
import Debug "mo:base/Debug";

module {
  public type Result<T, E> = { #ok : T; #err : E };
  public type Identity = Identity.Identity;
  public type RequestId = Blob;

  public type RejectCode = { #sysFatal; #sysTransient; #destinationInvalid; #canisterReject; #canisterError; #other : Nat };
  public func rejectCode(n : Nat) : RejectCode = switch n {
    case 1 #sysFatal; case 2 #sysTransient; case 3 #destinationInvalid; case 4 #canisterReject; case 5 #canisterError; case _ #other n;
  };
  public type Reject = { code : RejectCode; message : Text; errorCode : ?Text };

  public type Error = {
    /// The boundary node answered with an error status.
    #http : { status : Nat; body : Blob };
    /// A response we could not decode.
    #malformed : Text;
    /// The canister or the system rejected the call.
    #rejected : Reject;
    /// `call`: still pending after the polls allowed; keep polling with the id.
    #pending : RequestId;
    /// `call`: the reply was already collected and pruned (`done`).
    #done : RequestId;
    /// The certificate's BLS signature did not check out, or its delegation/canister-range
    /// was malformed -- see `Certificate.Error`. Never returned when `Config.verify` is
    /// `#skip` (a skipped certificate is trusted, loudly, not rejected).
    #certificate : Certificate.Error;
  };

  public type Poll = {
    #pending : { #received; #processing };
    #replied : Blob;
    #rejected : Reject;
    #done;
    /// Not in the state tree: not yet seen by the subnet, or expired and forgotten.
    #unknown;
  };

  /// `#required` (the default): every certificate is BLS-verified before this agent trusts
  /// it -- a bad signature is `#err(#certificate ...)`, never a silent pass. `#skip` bypasses
  /// verification entirely (no pairing, no cost) and prints a LOUD line via `Debug.print` on
  /// every certificate it skips (P1: nothing silent) -- for a caller who has already weighed
  /// the cost in `README.md` ("Certificate verification cost") against their own trust model
  /// (e.g. a moxzid host pinned to a specific subnet it already trusts some other way).
  public type Verify = { #required; #skip };

  public type Config = {
    /// "https://icp-api.io", or a local replica / PocketIC gateway.
    host : Text;
    identity : Identity;
    /// The root key certificates are verified against; mainnet's by default. Required
    /// (verification fails closed) whenever `verify = #required` and this is `null`.
    rootKey : ?Blob;
    /// How far ahead each request's ingress expiry is set. The IC allows up to 5 minutes.
    ingressExpiryNs : Nat64;
    http : Transport.Http;
    /// A fresh nonce per request, when identical calls must not share a request id.
    nonce : ?(() -> Blob);
    /// Certificate verification: `#required` by default. See `Verify`.
    verify : Verify;
  };

  public let MAINNET_ROOT_KEY : Blob = "\30\81\82\30\1d\06\0d\2b\06\01\04\01\82\dc\7c\05\03\01\02\01\06\0c\2b\06\01\04\01\82\dc\7c\05\03\02\01\03\61\00\81\4c\0e\6e\c7\1f\ab\58\3b\08\bd\81\37\3c\25\5c\3c\37\1b\2e\84\86\3c\98\a4\f1\e0\8b\74\23\5d\14\fb\5d\9c\0c\d5\46\d9\68\5f\91\3a\0c\0b\2c\c5\34\15\83\bf\4b\43\92\e4\67\db\96\d6\5b\9b\b4\cb\71\71\12\f8\47\2e\0d\5a\4d\14\50\5f\fd\74\84\b0\12\91\09\1c\5f\87\b9\88\83\46\3f\98\09\1a\0b\aa\ae";

  public func defaults(host : Text, identity : Identity) : Config = {
    host;
    identity;
    rootKey = ?MAINNET_ROOT_KEY;
    ingressExpiryNs = 4 * 60 * 1_000_000_000;
    verify = #required;
    http = Transport.outcalls(0, 2_000_000);
    nonce = null;
  };

  public class Agent(cfg : Config) {
    let sender = Identity.principal(cfg.identity);

    public func principal() : Principal = sender;

    func expiry() : Nat64 = Nat64.fromNat(Int.abs(Time.now())) + cfg.ingressExpiryNs;
    func nonce() : ?Blob = switch (cfg.nonce) { case (?f) ?f(); case null null };
    func url(canister : Principal, endpoint : Text) : Text = cfg.host # "/api/v2/canister/" # Principal.toText(canister) # "/" # endpoint;

    func reject(v : Cbor.Value) : Reject = {
      code = rejectCode(Option.get(Cbor.asNat(Cbor.field(v, "reject_code")), 0));
      message = Option.get(Cbor.asText(Cbor.field(v, "reject_message")), "");
      errorCode = Cbor.asText(Cbor.field(v, "error_code"));
    };

    /// Verify (or, loudly, skip verifying) a decoded certificate before anything in this agent
    /// trusts it. Every `Certificate.decode` result passes through here -- see `readState` and
    /// `call`'s synchronous (v3) branch, the two places a certificate enters this file.
    func verifyCert(canister : Principal, cert : Certificate.Certificate) : Result<(), Error> {
      switch (cfg.verify) {
        case (#skip) {
          Debug.print("mo:ic-agent: certificate verification SKIPPED (Config.verify = #skip) for canister " # Principal.toText(canister) # " -- trusting an UNVERIFIED certificate");
          #ok()
        };
        case (#required) {
          let ?rootKey = cfg.rootKey else return #err(#malformed "verify = #required but Config.rootKey is null: cannot verify any certificate");
          switch (Certificate.verify(cert, rootKey, canister)) {
            case (#ok()) #ok();
            case (#err e) #err(#certificate e);
          }
        };
      }
    };

    /// A query call: the reply bytes (Candid), or why not.
    public func queryCall(canister : Principal, method : Text, arg : Blob) : async* Result<Blob, Error> {
      let content = #queryCall { sender; canister; method; arg; expiry = expiry(); nonce = nonce() };
      let r = await* cfg.http.post(url(canister, "query"), Envelope.encode(content, cfg.identity));
      if (r.status != 200) return #err(#http { status = r.status; body = r.body });
      let ?v = Cbor.decode(r.body) else return #err(#malformed "query response is not CBOR");
      switch (Cbor.asText(Cbor.field(v, "status"))) {
        case (?"replied") {
          switch (Cbor.field(v, "reply")) {
            case (?reply) { switch (Cbor.asBytes(Cbor.field(reply, "arg"))) { case (?arg) #ok arg; case null #err(#malformed "reply without arg") } };
            case null #err(#malformed "replied without a reply");
          }
        };
        case (?"rejected") #err(#rejected(reject(v)));
        case (?other) #err(#malformed("query status " # other));
        case null #err(#malformed "query response without status");
      }
    };

    /// Send an update call; back at once with its request id (accepted, not yet executed).
    public func submit(canister : Principal, method : Text, arg : Blob) : async* Result<RequestId, Error> {
      let content = #call { sender; canister; method; arg; expiry = expiry(); nonce = nonce() };
      await* submitEnvelope(canister, Envelope.encode(content, cfg.identity), Envelope.requestId(content))
    };

    func submitEnvelope(canister : Principal, envelope : Blob, rid : RequestId) : async* Result<RequestId, Error> {
      let r = await* cfg.http.post(url(canister, "call"), envelope);
      switch (r.status) {
        case 202 #ok rid;
        // A synchronous (non-replicated) rejection comes back as 200 with a CBOR body.
        case 200 {
          let ?v = Cbor.decode(r.body) else return #err(#malformed "call response is not CBOR");
          switch (Cbor.asText(Cbor.field(v, "status"))) {
            case (?"non_replicated_rejection") #err(#rejected(reject(v)));
            case _ #ok rid;
          }
        };
        case s #err(#http { status = s; body = r.body });
      }
    };

    func settle(status : Certificate.RequestStatus, rid : RequestId) : Result<Blob, Error> = switch status {
      case (#replied r) #ok r;
      case (#rejected rj) #err(#rejected { code = rejectCode(rj.code); message = rj.message; errorCode = rj.errorCode });
      case (#done) #err(#done rid);
      case (#malformed m) #err(#malformed m);
      case (#received or #processing or #unknown) #err(#pending rid);
    };

    func pollLoop(canister : Principal, rid : RequestId, maxPolls : Nat) : async* Result<Blob, Error> {
      var n = 0;
      while (n < maxPolls) {
        switch (await* poll(canister, rid)) {
          case (#err e) return #err e;
          case (#ok(#replied r)) return #ok r;
          case (#ok(#rejected rj)) return #err(#rejected rj);
          case (#ok(#done)) return #err(#done rid);
          case (#ok _) {};
        };
        n += 1;
      };
      #err(#pending rid)
    };

    /// One `read_state` round trip for a submitted request.
    public func poll(canister : Principal, requestId : RequestId) : async* Result<Poll, Error> {
      let paths : [[Blob]] = [["request_status", requestId]];
      switch (await* readState(canister, paths)) {
        case (#err e) #err e;
        case (#ok cert) {
          switch (Certificate.requestStatus(cert.tree, requestId)) {
            case (#received) #ok(#pending(#received));
            case (#processing) #ok(#pending(#processing));
            case (#replied r) #ok(#replied r);
            case (#rejected rj) #ok(#rejected { code = rejectCode(rj.code); message = rj.message; errorCode = rj.errorCode });
            case (#done) #ok(#done);
            case (#unknown) #ok(#unknown);
            case (#malformed m) #err(#malformed m);
          }
        };
      }
    };

    /// An update call for code that can wait. The SYNCHRONOUS endpoint (`/api/v3/…/call`)
    /// is tried first: the boundary node holds the request until it executes (up to its
    /// own timeout) and answers with the certificate, so no polling is needed at all. A
    /// 202 (still executing) or a gateway without v3 falls back to `read_state` polling,
    /// back to back, up to `maxPolls` times -- an agent has no clock to pace them with,
    /// which is exactly why `submit` + `poll` exist for callers that do.
    public func call(canister : Principal, method : Text, arg : Blob, maxPolls : Nat) : async* Result<Blob, Error> {
      let content = #call { sender; canister; method; arg; expiry = expiry(); nonce = nonce() };
      let rid = Envelope.requestId(content);
      let envelope = Envelope.encode(content, cfg.identity);
      let r = await* cfg.http.post(cfg.host # "/api/v3/canister/" # Principal.toText(canister) # "/call", envelope);
      switch (r.status) {
        case 200 {
          let ?v = Cbor.decode(r.body) else return #err(#malformed "call response is not CBOR");
          switch (Cbor.asText(Cbor.field(v, "status"))) {
            case (?"replied") {
              let ?bytes = Cbor.asBytes(Cbor.field(v, "certificate")) else return #err(#malformed "replied without a certificate");
              let ?cert = Certificate.decode(bytes) else return #err(#malformed "certificate does not decode");
              switch (verifyCert(canister, cert)) {
                case (#err e) #err e;
                case (#ok()) settle(Certificate.requestStatus(cert.tree, rid), rid);
              }
            };
            case (?"non_replicated_rejection") #err(#rejected(reject(v)));
            case (?other) #err(#malformed("call status " # other));
            case null #err(#malformed "call response without status");
          }
        };
        case 202 await* pollLoop(canister, rid, maxPolls);
        // No v3 here (an older gateway): the same envelope through v2, then poll. The
        // request id is the same, so a v3 attempt that did land is not a second call.
        case (404 or 405) {
          switch (await* submitEnvelope(canister, envelope, rid)) {
            case (#err e) #err e;
            case (#ok _) await* pollLoop(canister, rid, maxPolls);
          }
        };
        case s #err(#http { status = s; body = r.body });
      }
    };

    /// Read paths of the canister's state tree; the certificate is decoded AND VERIFIED
    /// (`Config.verify`) before it is returned -- every caller of `readState` (including
    /// `poll`) gets a certificate this agent has already checked, never a raw decode.
    public func readState(canister : Principal, paths : [[Blob]]) : async* Result<Certificate.Certificate, Error> {
      let content = #readState { sender; paths; expiry = expiry() };
      let r = await* cfg.http.post(url(canister, "read_state"), Envelope.encode(content, cfg.identity));
      if (r.status != 200) return #err(#http { status = r.status; body = r.body });
      let ?v = Cbor.decode(r.body) else return #err(#malformed "read_state response is not CBOR");
      let ?bytes = Cbor.asBytes(Cbor.field(v, "certificate")) else return #err(#malformed "read_state response without a certificate");
      let ?cert = Certificate.decode(bytes) else return #err(#malformed "certificate does not decode");
      switch (verifyCert(canister, cert)) {
        case (#err e) #err e;
        case (#ok()) #ok cert;
      }
    };

    /// GET /api/v2/status: the replica's root key (a local replica's differs from mainnet's).
    public func status() : async* Result<{ rootKey : ?Blob; implVersion : ?Text }, Error> {
      let r = await* cfg.http.get(cfg.host # "/api/v2/status");
      if (r.status != 200) return #err(#http { status = r.status; body = r.body });
      let ?v = Cbor.decode(r.body) else return #err(#malformed "status response is not CBOR");
      #ok { rootKey = Cbor.asBytes(Cbor.field(v, "root_key")); implVersion = Cbor.asText(Cbor.field(v, "impl_version")) }
    };
  };

  public func requestIdHex(id : RequestId) : Text = Hash.toHex(id);
}

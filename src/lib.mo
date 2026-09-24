/// `mo:ic-agent` -- an Internet Computer agent in Motoko. Query, submit, poll and read
/// canisters over the IC's HTTPS interface, signed by an identity, from an off-chain Motoko
/// program (a moxzid actor, a game, a browser tab) or from anywhere HTTPS outcalls exist.
///
/// An update call is TWO operations here: `submit` sends the envelope and returns the
/// request id at once; `poll` is one `read_state` round trip. A game courier submits on one
/// tick and polls on later ticks, so its own message never blocks on the network. `call`
/// composes the two for code that can afford to wait.
///
/// EVERYTHING THAT COMES BACK IS VERIFIED (`Config.verify = #required`, the default):
///  - certificates (`call`, `poll`, `readState`, the canister-info reads): the BLS signature
///    over the tree's root hash against the root key, one level of subnet delegation SCOPED to
///    the canister or subnet asked about, a well-formed tree, and a `/time` no older than
///    `Config.maxCertificateAgeNs`;
///  - query replies AND query rejections: every node signature (Ed25519, over
///    `"\x0Bic-response" · hash_of_map(response)`) against that node's key, which comes from a
///    VERIFIED `read_state` certificate for the subnet that hosts the canister (cached per
///    subnet while that certificate is fresh), and every signature timestamp fresh.
/// `#skip` turns all of it off, loudly, per response.
///
/// Endpoints follow the current interface spec: v3 query, v3 read_state and v4 synchronous
/// call, each falling back ONCE per agent to the older version (v2 / v3 / v2 + polling) when a
/// gateway answers 404 or 405 -- and remembering that it did.
import Envelope "Envelope";
import Identity "Identity";
import Certificate "Certificate";
import NodeSignature "NodeSignature";
import Candid "Candid";
import Cbor "Cbor";
import Transport "Transport";
import Hash "Hash";
import Principal "mo:base/Principal";
import Time "mo:base/Time";
import Int "mo:base/Int";
import Nat64 "mo:base/Nat64";
import Option "mo:base/Option";
import Debug "mo:base/Debug";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Text "mo:base/Text";

module {
  public type Result<T, E> = { #ok : T; #err : E };
  public type Identity = Identity.Identity;
  public type RequestId = Blob;
  public type SenderInfo = Envelope.SenderInfo;

  public type RejectCode = { #sysFatal; #sysTransient; #destinationInvalid; #canisterReject; #canisterError; #sysUnknown; #other : Nat };
  public func rejectCode(n : Nat) : RejectCode = switch n {
    case 1 #sysFatal; case 2 #sysTransient; case 3 #destinationInvalid; case 4 #canisterReject; case 5 #canisterError; case 6 #sysUnknown; case _ #other n;
  };
  public type Reject = { code : RejectCode; message : Text; errorCode : ?Text };

  /// Why a query response's node signatures were not accepted.
  public type QuerySignatureError = {
    /// The response carried no `signatures` (or an empty list).
    #missing;
    /// A signature names a node that is not in the canister's subnet (after one refresh of
    /// that subnet's node keys).
    #unknownNode : Principal;
    /// The node's Ed25519 signature does not verify over the response.
    #badSignature : Principal;
    /// A signature's timestamp is outside `Config.maxCertificateAgeNs` of now.
    #stale : { node : Principal; timestamp : Nat; now : Nat };
    /// A node key in the subnet certificate is not an RFC 8410 Ed25519 key.
    #badNodeKey : Principal;
    /// The read_state certificate proved no node keys for the subnet.
    #noNodeKeys : Principal;
    /// Without a delegation, the root subnet's certified canister ranges do not contain the
    /// canister (spec `verify_response`).
    #canisterNotInSubnet : { canister : Principal; subnet : Principal };
  };

  public type Error = {
    /// The boundary node answered with an error status. 429 and 5xx may succeed on retry.
    #http : { status : Nat; body : Blob };
    /// A response we could not decode.
    #malformed : Text;
    /// The canister or the system rejected the call (for a query: a VERIFIED rejection).
    #rejected : Reject;
    /// `call`: still pending after the polls allowed; keep polling with the id.
    #pending : RequestId;
    /// `call`: the reply was already collected and pruned (`done`).
    #done : RequestId;
    /// A certificate failed verification -- see `Certificate.Error`. Never returned when
    /// `Config.verify` is `#skip` (a skipped certificate is trusted, loudly, not rejected).
    #certificate : Certificate.Error;
    /// A query response's node signatures failed verification. Never with `#skip`.
    #querySignature : QuerySignatureError;
    /// `aaaaa-aa` was called with an argument that names no target canister, and no
    /// `effectiveCanisterId` was given (spec, "Effective canister id").
    #noEffectiveCanisterId : Text;
  };

  public type Poll = {
    #pending : { #received; #processing };
    #replied : Blob;
    #rejected : Reject;
    #done;
    /// Not in the state tree: not yet seen by the subnet, or expired and forgotten.
    #unknown;
  };

  /// `#required` (the default): every certificate and every query response is verified
  /// before this agent trusts it -- a bad one is an `#err`, never a silent pass. `#skip`
  /// bypasses verification entirely and prints a LOUD line via `Debug.print` on every
  /// response it skips (P1: nothing silent).
  public type Verify = { #required; #skip };

  public type Config = {
    /// "https://icp-api.io", or a local replica / PocketIC gateway.
    host : Text;
    identity : Identity;
    /// The root key everything is verified against; mainnet's by default. Required
    /// (verification fails closed) whenever `verify = #required` and this is `null`.
    rootKey : ?Blob;
    /// How far ahead each request's ingress expiry is set. The IC allows up to 5 minutes.
    ingressExpiryNs : Nat64;
    http : Transport.Http;
    /// A fresh nonce per request, when identical calls must not share a request id.
    nonce : ?(() -> Blob);
    /// Verification: `#required` by default. See `Verify`.
    verify : Verify;
    /// A certificate's `/time`, and a query signature's timestamp, must be within this of
    /// now (either side). The spec suggests 5 minutes. Also how long a subnet's node keys
    /// are reused: they come from a certificate held to the same bound.
    maxCertificateAgeNs : Nat;
    /// The same bound on a delegation's own certificate. Mainnet refreshes delegations only
    /// on replica upgrades, so the spec asks for at least a week; `null` disables it.
    maxDelegationAgeNs : ?Nat;
  };

  /// Per-request extras (spec, "Request: Call" / "Query call").
  public type Options = {
    /// Where to send a request to `aaaaa-aa` when its argument names no canister
    /// (`create_canister`, `provisional_create_canister_with_cycles`, `list_canisters`).
    /// Ignored for any other target, whose effective id is always itself or, for the
    /// management canister, the `canister_id`/`target_canister` its argument names.
    effectiveCanisterId : ?Principal;
    senderInfo : ?SenderInfo;
    /// Overrides `Config.nonce` for this request.
    nonce : ?Blob;
  };
  public let NO_OPTIONS : Options = { effectiveCanisterId = null; senderInfo = null; nonce = null };

  public let MAINNET_ROOT_KEY : Blob = "\30\81\82\30\1d\06\0d\2b\06\01\04\01\82\dc\7c\05\03\01\02\01\06\0c\2b\06\01\04\01\82\dc\7c\05\03\02\01\03\61\00\81\4c\0e\6e\c7\1f\ab\58\3b\08\bd\81\37\3c\25\5c\3c\37\1b\2e\84\86\3c\98\a4\f1\e0\8b\74\23\5d\14\fb\5d\9c\0c\d5\46\d9\68\5f\91\3a\0c\0b\2c\c5\34\15\83\bf\4b\43\92\e4\67\db\96\d6\5b\9b\b4\cb\71\71\12\f8\47\2e\0d\5a\4d\14\50\5f\fd\74\84\b0\12\91\09\1c\5f\87\b9\88\83\46\3f\98\09\1a\0b\aa\ae";

  /// `aaaaa-aa`, the management canister (the empty principal).
  public func managementCanister() : Principal = Principal.fromBlob("");

  public func defaults(host : Text, identity : Identity) : Config = {
    host;
    identity;
    rootKey = ?MAINNET_ROOT_KEY;
    ingressExpiryNs = 4 * 60 * 1_000_000_000;
    verify = #required;
    http = Transport.outcalls(0, 2_000_000);
    nonce = null;
    maxCertificateAgeNs = Certificate.FIVE_MINUTES_NS;
    maxDelegationAgeNs = ?Certificate.THIRTY_DAYS_NS;
  };

  /// The effective canister id of a request (spec, "Effective canister id"): the target
  /// itself, or for the management canister the principal its argument is about. `null` when
  /// the management call names none (canister creation, `list_canisters`) -- the caller then
  /// chooses, via `Options.effectiveCanisterId`.
  public func effectiveCanisterId(canister : Principal, method : Text, arg : Blob) : ?Principal {
    if (canister != managementCanister()) return ?canister;
    if (method == "install_chunked_code") {
      switch (Candid.principalField(arg, "target_canister")) { case (?p) return ?p; case null {} };
    };
    Candid.principalField(arg, "canister_id")
  };

  /// A subnet's node keys, proven by a verified `/subnet` certificate.
  public type SubnetKeys = { subnet : Principal; keys : [(Principal, Blob)]; time : Nat; canisters : [Principal] };

  public type Target = { #canister : Principal; #subnet : Principal };

  /// The first half of the spec's `verify_response` / `verify_subnet_response`: from a
  /// certificate for the path `/subnet` (read at the canister's -- or subnet's -- own
  /// read_state endpoint), the serving subnet and its nodes' keys. Verifies the certificate
  /// (signature, delegation scoped to `target`, well-formed, `policy` time), and, when the
  /// ROOT subnet signed without a delegation, that the canister is in the root subnet's own
  /// certified ranges.
  public func subnetKeysFromCertificate(cert : Certificate.Certificate, rootKey : Blob, target : Target, policy : Certificate.Policy) : Result<SubnetKeys, Error> {
    let scope : Certificate.Scope = switch target { case (#canister c) #canister c; case (#subnet s) #subnet s };
    let v = switch (Certificate.verifyScoped(cert, rootKey, scope, policy)) { case (#ok v) v; case (#err e) return #err(#certificate e) };
    switch target {
      case (#canister c) {
        if (not v.delegated) {
          switch (Certificate.canisterInSubnet(cert.tree, v.subnetId, c)) {
            case (#yes) {};
            case _ return #err(#querySignature(#canisterNotInSubnet { canister = c; subnet = v.subnetId }));
          };
        };
      };
      case (#subnet _) {};
    };
    let keys = Certificate.nodeKeys(cert.tree, v.subnetId);
    if (keys.size() == 0) return #err(#querySignature(#noNodeKeys(v.subnetId)));
    #ok { subnet = v.subnetId; keys; time = v.time; canisters = switch target { case (#canister c) [c]; case (#subnet _) [] } }
  };

  /// The response a query answered with, as the node signed it: the reply map, or the
  /// rejection (`error_code` only when present). Null if `v` is neither.
  public func queryResponse(v : Cbor.Value) : ?NodeSignature.Response {
    switch (Cbor.asText(Cbor.field(v, "status"))) {
      case (?"replied") {
        let ?reply = Cbor.field(v, "reply") else return null;
        switch (NodeSignature.mapFields(reply)) { case (?f) ?#replied f; case null null }
      };
      case (?"rejected") {
        let ?code = Cbor.asNat(Cbor.field(v, "reject_code")) else return null;
        let ?message = Cbor.asText(Cbor.field(v, "reject_message")) else return null;
        ?#rejected { code; message; errorCode = Cbor.asText(Cbor.field(v, "error_code")) }
      };
      case _ null;
    }
  };

  /// The second half: spec `verify_node_signatures`. Every signature in `v` (the decoded
  /// query response) is by a node in `keys`, verifies over this response and request id, and
  /// -- when `now` is given -- has a timestamp within `maxAgeNs` of it. `#unknownNode` is the
  /// one error a caller may cure by refreshing `keys` (node membership changes).
  public func checkNodeSignatures(v : Cbor.Value, requestId : Blob, keys : SubnetKeys, now : ?Nat, maxAgeNs : Nat) : Result<(), QuerySignatureError> {
    let ?response = queryResponse(v) else return #err(#missing);
    let ?sigs = Cbor.asArray(Cbor.field(v, "signatures")) else return #err(#missing);
    if (sigs.size() == 0) return #err(#missing);
    for (s in sigs.values()) {
      let ?ts = Cbor.asNat(Cbor.field(s, "timestamp")) else return #err(#missing);
      let ?sig = Cbor.asBytes(Cbor.field(s, "signature")) else return #err(#missing);
      let ?nodeBytes = Cbor.asBytes(Cbor.field(s, "identity")) else return #err(#missing);
      let node = Principal.fromBlob(nodeBytes);
      switch now {
        case (?t) { if (ts + maxAgeNs < t or ts > t + maxAgeNs) return #err(#stale { node; timestamp = ts; now = t }) };
        case null {};
      };
      let ?(_, der) = Array.find<(Principal, Blob)>(keys.keys, func((n, _)) = n == node) else return #err(#unknownNode node);
      let ?raw = NodeSignature.unwrapDer(der) else return #err(#badNodeKey node);
      if (not NodeSignature.verifyEd25519(sig, NodeSignature.message(response, ts, requestId), raw)) return #err(#badSignature node);
    };
    #ok()
  };


  public class Agent(cfg : Config) {
    let sender = Identity.principal(cfg.identity);

    // Which endpoint generation the gateway speaks; downgraded once on a 404/405.
    var queryV3 = true;
    var readStateV3 = true;
    var callV4 = true;
    var callV3 = true;
    // Node keys per subnet, from verified read_state certificates (`nodeKeysFor`).
    var subnetKeys : [SubnetKeys] = [];

    public func principal() : Principal = sender;

    /// Which endpoint generation this agent is using, after any fallbacks so far -- a gateway
    /// that forced a downgrade says so here instead of silently (P1).
    public func apiVersions() : { query_ : Text; readState : Text; call : Text } = {
      query_ = if queryV3 "v3" else "v2";
      readState = if readStateV3 "v3" else "v2";
      call = if callV4 "v4" else if callV3 "v3" else "v2";
    };

    func now() : Nat = Int.abs(Time.now());
    func expiry() : Nat64 = Nat64.fromNat(now()) + cfg.ingressExpiryNs;
    func nonceFor(o : Options) : ?Blob = switch (o.nonce, cfg.nonce) { case (?n, _) ?n; case (null, ?f) ?f(); case (null, null) null };
    func policy() : Certificate.Policy = { now = ?now(); maxAgeNs = cfg.maxCertificateAgeNs; maxDelegationAgeNs = cfg.maxDelegationAgeNs };
    func canisterUrl(version : Text, ecid : Principal, endpoint : Text) : Text =
      cfg.host # "/api/" # version # "/canister/" # Principal.toText(ecid) # "/" # endpoint;
    func subnetUrl(version : Text, subnet : Principal, endpoint : Text) : Text =
      cfg.host # "/api/" # version # "/subnet/" # Principal.toText(subnet) # "/" # endpoint;
    func unsupported(status : Nat) : Bool = status == 404 or status == 405;

    func reject(v : Cbor.Value) : Reject = {
      code = rejectCode(Option.get(Cbor.asNat(Cbor.field(v, "reject_code")), 0));
      message = Option.get(Cbor.asText(Cbor.field(v, "reject_message")), "");
      errorCode = Cbor.asText(Cbor.field(v, "error_code"));
    };

    func skipped(what : Text) {
      Debug.print("mo:ic-agent: verification SKIPPED (Config.verify = #skip) for " # what # " -- trusting an UNVERIFIED response");
    };

    func ecidOf(canister : Principal, method : Text, arg : Blob, o : Options) : Result<Principal, Error> {
      switch (effectiveCanisterId(canister, method, arg)) {
        case (?p) #ok p;
        case null {
          switch (o.effectiveCanisterId) {
            case (?p) #ok p;
            case null #err(#noEffectiveCanisterId("aaaaa-aa." # method # ": the argument names no canister_id; pass Options.effectiveCanisterId"));
          }
        };
      }
    };

    /// Verify (or, loudly, skip verifying) a decoded certificate before anything trusts it.
    func verifyCert(scope : Certificate.Scope, cert : Certificate.Certificate) : Result<?Certificate.Verified, Error> {
      switch (cfg.verify) {
        case (#skip) { skipped("a certificate (" # debug_show scope # ")"); #ok null };
        case (#required) {
          let ?rootKey = cfg.rootKey else return #err(#malformed "verify = #required but Config.rootKey is null: cannot verify any certificate");
          switch (Certificate.verifyScoped(cert, rootKey, scope, policy())) {
            case (#ok v) #ok(?v);
            case (#err e) #err(#certificate e);
          }
        };
      }
    };

    // ---- read_state ------------------------------------------------------------------------

    func postReadState(url2 : Text, url3 : Text, paths : [[Blob]]) : async* Result<Certificate.Certificate, Error> {
      let content = #readState { sender; paths; expiry = expiry() };
      let envelope = Envelope.encode(content, cfg.identity);
      var r = await* cfg.http.post(if readStateV3 url3 else url2, envelope);
      if (readStateV3 and unsupported(r.status)) { readStateV3 := false; r := await* cfg.http.post(url2, envelope) };
      if (r.status != 200) return #err(#http { status = r.status; body = r.body });
      let ?v = Cbor.decode(r.body) else return #err(#malformed "read_state response is not CBOR");
      let ?bytes = Cbor.asBytes(Cbor.field(v, "certificate")) else return #err(#malformed "read_state response without a certificate");
      let ?cert = Certificate.decode(bytes) else return #err(#malformed "certificate does not decode");
      #ok cert
    };

    /// Read paths of a canister's state tree (at `/api/v3/canister/<canister>/read_state`); the
    /// certificate is VERIFIED -- scoped to `canister`, fresh -- before it is returned.
    public func readState(canister : Principal, paths : [[Blob]]) : async* Result<Certificate.Certificate, Error> {
      switch (await* readStateVerified(canister, paths)) { case (#ok(c, _)) #ok c; case (#err e) #err e };
    };

    func readStateVerified(canister : Principal, paths : [[Blob]]) : async* Result<(Certificate.Certificate, ?Certificate.Verified), Error> {
      let cert = switch (await* postReadState(canisterUrl("v2", canister, "read_state"), canisterUrl("v3", canister, "read_state"), paths)) {
        case (#ok c) c; case (#err e) return #err e;
      };
      switch (verifyCert(#canister canister, cert)) { case (#ok v) #ok((cert, v)); case (#err e) #err e };
    };

    /// Read paths of a SUBNET's state tree (`/api/v3/subnet/<subnet>/read_state`) -- what the
    /// spec asks for `/time`, `/canister_ranges/<subnet>` and `/subnet/<subnet>/metrics`. The
    /// certificate must come from that subnet (or the root subnet, if `subnet` is the root).
    public func readSubnetState(subnet : Principal, paths : [[Blob]]) : async* Result<Certificate.Certificate, Error> {
      switch (await* readSubnetStateVerified(subnet, paths)) { case (#ok(c, _)) #ok c; case (#err e) #err e };
    };

    func readSubnetStateVerified(subnet : Principal, paths : [[Blob]]) : async* Result<(Certificate.Certificate, ?Certificate.Verified), Error> {
      let cert = switch (await* postReadState(subnetUrl("v2", subnet, "read_state"), subnetUrl("v3", subnet, "read_state"), paths)) {
        case (#ok c) c; case (#err e) return #err e;
      };
      switch (verifyCert(#subnet subnet, cert)) { case (#ok v) #ok((cert, v)); case (#err e) #err e };
    };

    // ---- node keys for query verification ----------------------------------------------------

    func cachedKeys(target : Target) : ?SubnetKeys {
      let t = now();
      for (e in subnetKeys.values()) {
        let fresh = e.time + cfg.maxCertificateAgeNs >= t;
        let matches = switch target {
          case (#subnet s) e.subnet == s;
          case (#canister c) Option.isSome(Array.find<Principal>(e.canisters, func(x) = x == c));
        };
        if (fresh and matches) return ?e;
      };
      null
    };

    func remember(e : SubnetKeys) {
      let t = now();
      let kept = Array.filter<SubnetKeys>(subnetKeys, func(x) = x.subnet != e.subnet and x.time + cfg.maxCertificateAgeNs >= t);
      subnetKeys := Array.append(kept, [e]);
    };

    /// The subnet serving `target` and its nodes' keys, from a VERIFIED certificate for the
    /// path `/subnet` (spec, "Request: Query call": "a certificate Cert that is obtained by
    /// requesting the path /subnet in a separate read state request"). Cached per subnet
    /// while that certificate is within `maxCertificateAgeNs`.
    func nodeKeysFor(target : Target, refresh : Bool) : async* Result<SubnetKeys, Error> {
      if (not refresh) { switch (cachedKeys(target)) { case (?e) return #ok e; case null {} } };
      let ?rootKey = cfg.rootKey else return #err(#malformed "verify = #required but Config.rootKey is null: cannot verify any query");
      let paths : [[Blob]] = [["subnet"]];
      let raw = switch target {
        case (#canister c) await* postReadState(canisterUrl("v2", c, "read_state"), canisterUrl("v3", c, "read_state"), paths);
        case (#subnet s) await* postReadState(subnetUrl("v2", s, "read_state"), subnetUrl("v3", s, "read_state"), paths);
      };
      let cert = switch raw { case (#ok c) c; case (#err e) return #err e };
      let fresh = switch (subnetKeysFromCertificate(cert, rootKey, target, policy())) { case (#ok k) k; case (#err e) return #err e };
      // Keep every canister already proven to live on this subnet.
      let previous = switch (Array.find<SubnetKeys>(subnetKeys, func(x) = x.subnet == fresh.subnet)) { case (?e) e.canisters; case null [] };
      let canisters = Array.append(Array.filter<Principal>(previous, func(p) = Option.isNull(Array.find<Principal>(fresh.canisters, func(q) = q == p))), fresh.canisters);
      let e = { fresh with canisters };
      remember(e);
      #ok e
    };

    /// Spec `verify_node_signatures`, with one refresh of the subnet's keys if a signature
    /// names a node the cached keys do not know.
    func verifyQueryResponse(target : Target, requestId : Blob, v : Cbor.Value) : async* Result<(), Error> {
      switch (cfg.verify) {
        case (#skip) { skipped("a query response"); return #ok() };
        case (#required) {};
      };
      let keys = switch (await* nodeKeysFor(target, false)) { case (#ok e) e; case (#err e) return #err e };
      switch (checkNodeSignatures(v, requestId, keys, ?now(), cfg.maxCertificateAgeNs)) {
        case (#ok()) #ok();
        case (#err(#unknownNode _)) {
          let again = switch (await* nodeKeysFor(target, true)) { case (#ok e) e; case (#err e) return #err e };
          switch (checkNodeSignatures(v, requestId, again, ?now(), cfg.maxCertificateAgeNs)) {
            case (#ok()) #ok();
            case (#err e) #err(#querySignature e);
          }
        };
        case (#err e) #err(#querySignature e);
      }
    };

    // ---- queries -------------------------------------------------------------------------------

    /// A query call: the reply bytes (Candid), or why not. The reply -- or the rejection --
    /// is node-signature VERIFIED before it is returned.
    public func queryCall(canister : Principal, method : Text, arg : Blob) : async* Result<Blob, Error> {
      await* queryWith(canister, method, arg, NO_OPTIONS)
    };

    public func queryWith(canister : Principal, method : Text, arg : Blob, o : Options) : async* Result<Blob, Error> {
      let ecid = switch (ecidOf(canister, method, arg, o)) { case (#ok p) p; case (#err e) return #err e };
      let content = #queryCall { sender; canister; method; arg; expiry = expiry(); nonce = nonceFor(o); senderInfo = o.senderInfo };
      let envelope = Envelope.encode(content, cfg.identity);
      var r = await* cfg.http.post(canisterUrl(if queryV3 "v3" else "v2", ecid, "query"), envelope);
      if (queryV3 and unsupported(r.status)) { queryV3 := false; r := await* cfg.http.post(canisterUrl("v2", ecid, "query"), envelope) };
      await* settleQuery(#canister ecid, Envelope.requestId(content), r)
    };

    /// A subnet-scoped query (`/api/v3/subnet/<subnet>/query`) -- the spec allows only
    /// `aaaaa-aa.list_canisters` here. Verified against the subnet's own node keys.
    public func subnetQuery(subnet : Principal, method : Text, arg : Blob) : async* Result<Blob, Error> {
      let content = #queryCall { sender; canister = managementCanister(); method; arg; expiry = expiry(); nonce = nonceFor(NO_OPTIONS); senderInfo = null };
      let r = await* cfg.http.post(subnetUrl("v3", subnet, "query"), Envelope.encode(content, cfg.identity));
      await* settleQuery(#subnet subnet, Envelope.requestId(content), r)
    };

    func settleQuery(target : Target, rid : Blob, r : Transport.Response) : async* Result<Blob, Error> {
      if (r.status != 200) return #err(#http { status = r.status; body = r.body });
      let ?v = Cbor.decode(r.body) else return #err(#malformed "query response is not CBOR");
      switch (Cbor.asText(Cbor.field(v, "status"))) {
        case (?"replied") {
          let ?reply = Cbor.field(v, "reply") else return #err(#malformed "replied without a reply");
          let ?arg = Cbor.asBytes(Cbor.field(reply, "arg")) else return #err(#malformed "reply without arg");
          switch (await* verifyQueryResponse(target, rid, v)) { case (#err e) #err e; case (#ok()) #ok arg };
        };
        case (?"rejected") {
          let ?code = Cbor.asNat(Cbor.field(v, "reject_code")) else return #err(#malformed "rejection without reject_code");
          let ?message = Cbor.asText(Cbor.field(v, "reject_message")) else return #err(#malformed "rejection without reject_message");
          let errorCode = Cbor.asText(Cbor.field(v, "error_code"));
          switch (await* verifyQueryResponse(target, rid, v)) {
            case (#err e) #err e;
            case (#ok()) #err(#rejected { code = rejectCode(code); message; errorCode });
          }
        };
        case (?other) #err(#malformed("query status " # other));
        case null #err(#malformed "query response without status");
      }
    };

    // ---- update calls --------------------------------------------------------------------------

    /// Send an update call; back at once with its request id (accepted, not yet executed).
    /// Poll it with `poll(effectiveCanisterId(canister, method, arg), id)` -- which is
    /// `canister` itself for every target but the management canister.
    public func submit(canister : Principal, method : Text, arg : Blob) : async* Result<RequestId, Error> {
      await* submitWith(canister, method, arg, NO_OPTIONS)
    };

    public func submitWith(canister : Principal, method : Text, arg : Blob, o : Options) : async* Result<RequestId, Error> {
      let ecid = switch (ecidOf(canister, method, arg, o)) { case (#ok p) p; case (#err e) return #err e };
      let content = #call { sender; canister; method; arg; expiry = expiry(); nonce = nonceFor(o); senderInfo = o.senderInfo };
      await* submitEnvelope(ecid, Envelope.encode(content, cfg.identity), Envelope.requestId(content))
    };

    /// The asynchronous endpoint (`/api/v2/canister/<ecid>/call`: 202 = accepted).
    func submitEnvelope(ecid : Principal, envelope : Blob, rid : RequestId) : async* Result<RequestId, Error> {
      let r = await* cfg.http.post(canisterUrl("v2", ecid, "call"), envelope);
      switch (r.status) {
        case 202 #ok rid;
        // A synchronous (non-replicated) rejection comes back as 200 with a CBOR body.
        case 200 {
          let ?v = Cbor.decode(r.body) else return #err(#malformed "call response is not CBOR");
          if (Cbor.field(v, "reject_code") != null) #err(#rejected(reject(v))) else #ok rid
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

    func pollLoop(target : Target, rid : RequestId, maxPolls : Nat) : async* Result<Blob, Error> {
      var n = 0;
      while (n < maxPolls) {
        let p = switch target {
          case (#canister c) await* poll(c, rid);
          case (#subnet s) await* pollSubnet(s, rid);
        };
        switch p {
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

    func pollOf(cert : Certificate.Certificate, requestId : RequestId) : Result<Poll, Error> {
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

    /// One `read_state` round trip for a submitted request. `effectiveCanister` is the
    /// canister the request was SENT to (its effective canister id).
    public func poll(effectiveCanister : Principal, requestId : RequestId) : async* Result<Poll, Error> {
      switch (await* readState(effectiveCanister, [["request_status", requestId]])) {
        case (#err e) #err e;
        case (#ok cert) pollOf(cert, requestId);
      }
    };

    /// `poll` for a request sent to a subnet endpoint (`subnetCall`).
    public func pollSubnet(subnet : Principal, requestId : RequestId) : async* Result<Poll, Error> {
      switch (await* readSubnetState(subnet, [["request_status", requestId]])) {
        case (#err e) #err e;
        case (#ok cert) pollOf(cert, requestId);
      }
    };

    /// An update call for code that can wait. The SYNCHRONOUS endpoint (`/api/v4/…/call`, or
    /// v3 on a gateway without v4) is tried first: the replica holds the request until it
    /// executes and answers with a certificate, so no polling is needed. A 202 (still
    /// executing) falls back to `read_state` polling, back to back, up to `maxPolls` times; a
    /// gateway with neither synchronous endpoint gets the v2 call and polling.
    public func call(canister : Principal, method : Text, arg : Blob, maxPolls : Nat) : async* Result<Blob, Error> {
      await* callWith(canister, method, arg, maxPolls, NO_OPTIONS)
    };

    public func callWith(canister : Principal, method : Text, arg : Blob, maxPolls : Nat, o : Options) : async* Result<Blob, Error> {
      let ecid = switch (ecidOf(canister, method, arg, o)) { case (#ok p) p; case (#err e) return #err e };
      let content = #call { sender; canister; method; arg; expiry = expiry(); nonce = nonceFor(o); senderInfo = o.senderInfo };
      let rid = Envelope.requestId(content);
      let envelope = Envelope.encode(content, cfg.identity);
      var r = { status = 404; body = "" : Blob };
      if (callV4) {
        r := await* cfg.http.post(canisterUrl("v4", ecid, "call"), envelope);
        if (unsupported(r.status)) callV4 := false;
      };
      if (not callV4 and callV3) {
        r := await* cfg.http.post(canisterUrl("v3", ecid, "call"), envelope);
        if (unsupported(r.status)) callV3 := false;
      };
      if (not callV4 and not callV3) {
        // The request id is the same, so a synchronous attempt that did land is not a second call.
        return switch (await* submitEnvelope(ecid, envelope, rid)) {
          case (#err e) #err e;
          case (#ok _) await* pollLoop(#canister ecid, rid, maxPolls);
        };
      };
      await* settleSyncCall(#canister ecid, r, rid, maxPolls)
    };

    /// A subnet-scoped update call (`/api/v4/subnet/<subnet>/call`) -- the spec allows only
    /// canister creation on `aaaaa-aa` here; `subnet` is where the canister is created.
    public func subnetCall(subnet : Principal, method : Text, arg : Blob, maxPolls : Nat) : async* Result<Blob, Error> {
      let content = #call { sender; canister = managementCanister(); method; arg; expiry = expiry(); nonce = nonceFor(NO_OPTIONS); senderInfo = null };
      let rid = Envelope.requestId(content);
      let r = await* cfg.http.post(subnetUrl("v4", subnet, "call"), Envelope.encode(content, cfg.identity));
      await* settleSyncCall(#subnet subnet, r, rid, maxPolls)
    };

    func settleSyncCall(target : Target, r : Transport.Response, rid : RequestId, maxPolls : Nat) : async* Result<Blob, Error> {
      switch (r.status) {
        case 200 {
          let ?v = Cbor.decode(r.body) else return #err(#malformed "call response is not CBOR");
          switch (Cbor.asText(Cbor.field(v, "status"))) {
            case (?"replied") {
              let ?bytes = Cbor.asBytes(Cbor.field(v, "certificate")) else return #err(#malformed "replied without a certificate");
              let ?cert = Certificate.decode(bytes) else return #err(#malformed "certificate does not decode");
              let scope : Certificate.Scope = switch target { case (#canister c) #canister c; case (#subnet s) #subnet s };
              switch (verifyCert(scope, cert)) {
                case (#err e) #err e;
                case (#ok _) settle(Certificate.requestStatus(cert.tree, rid), rid);
              }
            };
            case (?"non_replicated_rejection") #err(#rejected(reject(v)));
            case (?other) #err(#malformed("call status " # other));
            case null #err(#malformed "call response without status");
          }
        };
        case 202 await* pollLoop(target, rid, maxPolls);
        case s #err(#http { status = s; body = r.body });
      }
    };

    // ---- certified canister information (spec, "Canister information") ------------------------

    func lookupOne(canister : Principal, path : [Blob]) : async* Result<?Blob, Error> {
      switch (await* readState(canister, [path])) {
        case (#err e) #err e;
        case (#ok cert) {
          switch (Certificate.lookup(cert.tree, path)) {
            case (#found v) #ok(?v);
            case (#absent) #ok null;
            case (#unknown) #err(#malformed "the certificate neither reveals nor excludes the path");
            case (#error m) #err(#malformed m);
          }
        };
      }
    };

    /// SHA-256 of the installed module; `null` for an empty canister.
    public func moduleHash(canister : Principal) : async* Result<?Blob, Error> {
      await* lookupOne(canister, ["canister", Principal.toBlob(canister), "module_hash"])
    };

    /// The canister's controllers (order is implementation-defined, per the spec).
    public func controllers(canister : Principal) : async* Result<[Principal], Error> {
      switch (await* lookupOne(canister, ["canister", Principal.toBlob(canister), "controllers"])) {
        case (#err e) #err e;
        case (#ok null) #ok([]);
        case (#ok(?bytes)) {
          let ?v = Cbor.decode(bytes) else return #err(#malformed "controllers is not CBOR");
          let ?items = Cbor.asArray(?v) else return #err(#malformed "controllers is not an array");
          let out = Buffer.Buffer<Principal>(items.size());
          for (x in items.values()) {
            switch (Cbor.asBytes(?x)) { case (?b) out.add(Principal.fromBlob(b)); case null return #err(#malformed "controller is not a principal") };
          };
          #ok(Buffer.toArray(out))
        };
      }
    };

    /// A `icp:public <name>` custom section (or `icp:private`, to a controller); `null` if absent.
    public func metadata(canister : Principal, name : Text) : async* Result<?Blob, Error> {
      await* lookupOne(canister, ["canister", Principal.toBlob(canister), "metadata", Text.encodeUtf8(name)])
    };

    /// GET /api/v2/status: the replica's root key (a local replica's differs from mainnet's).
    /// The spec: for mainnet, never trust this key -- `Config.rootKey` is the trusted one.
    public func status() : async* Result<{ rootKey : ?Blob; implVersion : ?Text }, Error> {
      let r = await* cfg.http.get(cfg.host # "/api/v2/status");
      if (r.status != 200) return #err(#http { status = r.status; body = r.body });
      let ?v = Cbor.decode(r.body) else return #err(#malformed "status response is not CBOR");
      #ok { rootKey = Cbor.asBytes(Cbor.field(v, "root_key")); implVersion = Cbor.asText(Cbor.field(v, "impl_version")) }
    };
  };

  public func requestIdHex(id : RequestId) : Text = Hash.toHex(id);
}

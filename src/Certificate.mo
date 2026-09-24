/// Certificates and hash trees (interface spec, "Certification"): decode a certificate,
/// walk its tree for a path, read a request's status, and (alpha-7 G2) VERIFY the BLS
/// signature over the tree's root hash against a subnet's public key, including one level of
/// delegation, with the spec's scoping and time checks. `verifyScoped` is the thing that makes a certificate worth trusting; the rest of
/// this file (decode, lookup, rootHash) is decoding the ENVELOPE the signature covers.
import Cbor "Cbor";
import Hash "Hash";
import Bls "Bls12381";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Text "mo:base/Text";
import Nat8 "mo:base/Nat8";
import Principal "mo:base/Principal";

module {
  public type HashTree = {
    #empty;
    #fork : (HashTree, HashTree);
    #labeled : (Blob, HashTree);
    #leaf : Blob;
    #pruned : Blob;
  };
  public type Delegation = { subnetId : Blob; certificate : Blob };
  public type Certificate = { tree : HashTree; signature : Blob; delegation : ?Delegation };

  /// A tree is a CBOR array tagged by its first element: [0] empty, [1, l, r] fork,
  /// [2, label, t] labeled, [3, bytes] leaf, [4, hash] pruned.
  public func decodeTree(v : Cbor.Value) : ?HashTree = switch v {
    case (#majorType4 items) {
      if (items.size() == 0) return null;
      switch (items.size(), items[0]) {
        case (1, #majorType0 0) ?#empty;
        case (3, #majorType0 1) { do ? { #fork(decodeTree(items[1])!, decodeTree(items[2])!) } };
        case (3, #majorType0 2) { do ? { #labeled(Cbor.asBytes(?items[1])!, decodeTree(items[2])!) } };
        case (2, #majorType0 3) { do ? { #leaf(Cbor.asBytes(?items[1])!) } };
        case (2, #majorType0 4) { do ? { #pruned(Cbor.asBytes(?items[1])!) } };
        case _ null;
      }
    };
    case _ null;
  };

  public func decode(bytes : Blob) : ?Certificate = do ? {
    let v = Cbor.decode(bytes)!;
    let tree = decodeTree(Cbor.field(v, "tree")!)!;
    let signature = Cbor.asBytes(Cbor.field(v, "signature"))!;
    let delegation = switch (Cbor.field(v, "delegation")) {
      case null null;
      case (?d) ?{ subnetId = Cbor.asBytes(Cbor.field(d, "subnet_id"))!; certificate = Cbor.asBytes(Cbor.field(d, "certificate"))! };
    };
    { tree; signature; delegation }
  };

  func domain(sep : Text, parts : [Blob]) : Blob =
    Hash.sha256(Hash.concat(Array.append<Blob>([Blob.fromArray([Nat8.fromNat(sep.size())]), Text.encodeUtf8(sep)], parts)));

  /// reconstruct: the domain-separated hash of a tree.
  public func rootHash(t : HashTree) : Blob = switch t {
    case (#empty) domain("ic-hashtree-empty", []);
    case (#fork(l, r)) domain("ic-hashtree-fork", [rootHash(l), rootHash(r)]);
    case (#labeled(lbl, sub)) domain("ic-hashtree-labeled", [lbl, rootHash(sub)]);
    case (#leaf v) domain("ic-hashtree-leaf", [v]);
    case (#pruned h) h;
  };

  public type Lookup = { #found : Blob; #absent; #unknown; #error : Text };

  /// lookup_path, as the spec defines it: `#absent` only when the flattened siblings PROVE
  /// the label is not there (two labeled neighbours bracket it, or it falls before the
  /// first / after the last labeled node); a pruned node that could hide it is `#unknown`.
  public func lookup(t : HashTree, path : [Blob]) : Lookup {
    var cur = t;
    var i = 0;
    while (i < path.size()) {
      switch (findLabel(cur, path[i])) {
        case (#found sub) cur := sub;
        case (#absent) return #absent;
        case (#unknown) return #unknown;
      };
      i += 1;
    };
    switch cur {
      case (#leaf v) #found v;
      case (#empty) #absent;
      case (#pruned _) #unknown;
      case _ #error "the path ends at a subtree, not a leaf";
    }
  };

  func flatten(t : HashTree, out : Buffer.Buffer<HashTree>) {
    switch t {
      case (#empty) {};
      case (#fork(l, r)) { flatten(l, out); flatten(r, out) };
      case other out.add(other);
    }
  };

  func labelOf(t : HashTree) : ?Blob = switch t { case (#labeled(l, _)) ?l; case _ null };

  func findLabel(t : HashTree, lbl : Blob) : { #found : HashTree; #absent; #unknown } {
    let buf = Buffer.Buffer<HashTree>(8);
    flatten(t, buf);
    let ts = Buffer.toArray(buf);
    for (x in ts.values()) {
      switch x { case (#labeled(l, sub)) { if (l == lbl) return #found sub }; case _ {} };
    };
    if (ts.size() == 0) return #unknown;
    switch (labelOf(ts[0])) { case (?l1) { if (Blob.compare(lbl, l1) == #less) return #absent }; case null {} };
    switch (labelOf(ts[ts.size() - 1])) { case (?l1) { if (Blob.compare(lbl, l1) == #greater) return #absent }; case null {} };
    var i = 0;
    while (i + 1 < ts.size()) {
      switch (labelOf(ts[i]), labelOf(ts[i + 1])) {
        case (?l1, ?l2) { if (Blob.compare(l1, lbl) == #less and Blob.compare(lbl, l2) == #less) return #absent };
        case _ {};
      };
      i += 1;
    };
    #unknown
  };

  public type RequestStatus = {
    #received;
    #processing;
    #replied : Blob;
    #rejected : { code : Nat; message : Text; errorCode : ?Text };
    #done;
    /// Not in the tree: not yet received, or expired and forgotten.
    #unknown;
    #malformed : Text;
  };

  /// The state of a request under `request_status/<request id>/…`.
  public func requestStatus(tree : HashTree, requestId : Blob) : RequestStatus {
    let base : [Blob] = ["request_status", requestId];
    func at(leaf : Text) : Lookup = lookup(tree, Array.append<Blob>(base, [Text.encodeUtf8(leaf)]));
    switch (at("status")) {
      case (#found s) {
        switch (Text.decodeUtf8(s)) {
          case (?"replied") { switch (at("reply")) { case (#found r) #replied r; case _ #malformed "replied without a reply" } };
          case (?"rejected") {
            let code = switch (at("reject_code")) { case (#found c) Hash.unleb128(c); case _ 0 };
            let message = switch (at("reject_message")) { case (#found m) { switch (Text.decodeUtf8(m)) { case (?t) t; case null "" } }; case _ "" };
            let errorCode = switch (at("error_code")) { case (#found e) Text.decodeUtf8(e); case _ null };
            #rejected { code; message; errorCode }
          };
          case (?"received") #received;
          case (?"processing") #processing;
          case (?"done") #done;
          case (?other) #malformed("unexpected status " # other);
          case null #malformed "status is not utf-8";
        }
      };
      case (#absent) #unknown;
      case (#unknown) #unknown;
      case (#error e) #malformed e;
    }
  };


  /// A subtree at `path` (not only a leaf): what `lookup*` and the node-key walk descend into.
  public func lookupSubtree(t : HashTree, path : [Blob]) : { #found : HashTree; #absent; #unknown } {
    var cur = t;
    for (l in path.values()) {
      switch (findLabel(cur, l)) {
        case (#found sub) cur := sub;
        case (#absent) return #absent;
        case (#unknown) return #unknown;
      };
    };
    #found cur
  };

  /// The labeled children directly under `path`, as (label, subtree) pairs, in tree order.
  public func children(t : HashTree, path : [Blob]) : [(Blob, HashTree)] {
    switch (lookupSubtree(t, path)) {
      case (#found sub) {
        let buf = Buffer.Buffer<HashTree>(8);
        flatten(sub, buf);
        let out = Buffer.Buffer<(Blob, HashTree)>(buf.size());
        for (x in buf.vals()) { switch x { case (#labeled(l, s)) out.add((l, s)); case _ {} } };
        Buffer.toArray(out)
      };
      case _ [];
    }
  };

  /// `lookup*(prefix, cert)` (spec, "Lookup"): every value found at a path that extends
  /// `prefix`, in tree order. Pruned parts contribute nothing -- which is why a caller must
  /// treat "none found" as "not proven", never as "proven absent".
  public func lookupAll(t : HashTree, prefix : [Blob]) : [Blob] {
    let out = Buffer.Buffer<Blob>(4);
    func collect(x : HashTree) {
      switch x {
        case (#leaf v) out.add(v);
        case (#fork(l, r)) { collect(l); collect(r) };
        case (#labeled(_, s)) collect(s);
        case (#empty or #pruned _) {};
      }
    };
    switch (lookupSubtree(t, prefix)) { case (#found sub) collect(sub); case _ {} };
    Buffer.toArray(out)
  };

  /// `well_formed` (spec, "Lookup"): labels strictly increasing within each forest, and no
  /// leaf mixed in among labeled siblings. `lookup` is only defined on well-formed trees, and
  /// the IC only signs well-formed ones -- so a tree that is not is refused before any lookup.
  public func wellFormed(t : HashTree) : Bool {
    switch t {
      case (#leaf _) true;
      case _ {
        let buf = Buffer.Buffer<HashTree>(8);
        flatten(t, buf);
        var prev : ?Blob = null;
        for (x in buf.vals()) {
          switch x {
            case (#leaf _) return false;
            case (#labeled(l, sub)) {
              switch prev { case (?p) { if (Blob.compare(p, l) != #less) return false }; case null {} };
              prev := ?l;
              if (not wellFormed(sub)) return false;
            };
            case _ {};
          };
        };
        true
      };
    }
  };

  /// The certified `/time` of a tree, in nanoseconds since 1970 (a LEB128 leaf).
  public func time(t : HashTree) : ?Nat = switch (lookup(t, ["time"])) {
    case (#found v) ?Hash.unleb128(v);
    case _ null;
  };

  // ============================================================================================
  // Signature verification (interface spec, "Certification"). The signature is BLS12-381
  // min_sig (public key in G2, signature in G1) over `domain_sep("ic-state-root") ‖
  // root_hash(tree)`, `domain_sep(s) = len(s) byte ‖ s`. A certificate may carry ONE
  // delegation: the inner certificate is signed by the root key and its tree holds the
  // subnet's own (DER-wrapped) public key and the subnet's canister ranges; the outer
  // certificate is then verified against that subnet key, and the delegation must be SCOPED
  // to what was asked (`Scope`).
  public type Result<T, E> = { #ok : T; #err : E };
  public type Error = {
    /// The certificate does not decode into the shape `verify` needs (missing/malformed
    /// delegation fields, a canister_ranges blob that is not valid CBOR, an unparseable DER key,
    /// no `/time`).
    #malformed : Text;
    /// The certificate carries a delegation whose OWN certificate is itself delegated -- the
    /// spec allows exactly one level.
    #delegationTooDeep;
    /// The target canister is not inside any range the delegation's canister ranges list.
    #canisterOutOfRange;
    /// A subnet-scoped request was answered under another subnet's delegation.
    #subnetMismatch : { expected : Principal; got : Principal };
    /// The BLS signature itself does not check out (root or, under a delegation, subnet key).
    #badSignature;
    /// The tree is not well formed (spec `well_formed`), so no lookup in it means anything.
    #notWellFormed;
    /// The certificate's `/time` is older than the policy allows (a replayed or stale answer).
    #stale : { certified : Nat; now : Nat; maxAgeNs : Nat };
    /// The certificate's `/time` is further in the future than the policy's clock skew allows.
    #fromFuture : { certified : Nat; now : Nat };
    /// A canister signature's delegation names a `cloud_engine` subnet, or no subnet type.
    #subnetType : Text;
  };

  /// How recent a certificate must be. `now = null` skips the time check (for verifying an
  /// OLD signed artifact -- a canister signature on a delegation, a stored ICRC-3 tip -- where
  /// age is the caller's business, not the protocol's).
  public type Policy = {
    now : ?Nat;
    /// A certificate whose `/time` is older than this is `#stale`; one this far AHEAD of `now`
    /// is `#fromFuture`. The spec suggests 5 minutes (the IC's own maximum ingress expiry).
    maxAgeNs : Nat;
    /// The same check on a delegation's own certificate. Mainnet refreshes delegations only
    /// on replica upgrades, so the spec says at least a week; `null` skips it.
    maxDelegationAgeNs : ?Nat;
  };

  public let FIVE_MINUTES_NS : Nat = 300_000_000_000;
  public let THIRTY_DAYS_NS : Nat = 2_592_000_000_000_000;

  /// What the delegation must be scoped to (spec: "Delegations are scoped").
  public type Scope = {
    /// A canister endpoint: the delegation's ranges must contain this canister. Both range
    /// encodings are read -- the sharded `/canister_ranges/<subnet>/<start>` (what v3
    /// read_state and v4 call return) and the whole `/subnet/<subnet>/canister_ranges` blob
    /// (v2 read_state, v3 call). Each is certified by the ROOT key inside the delegation, so
    /// either one is equally authoritative about the subnet's ranges.
    #canister : Principal;
    /// A subnet endpoint: the delegation's subnet must be this subnet (or, without a
    /// delegation, this must be the root subnet).
    #subnet : Principal;
  };

  /// What a verified certificate proved, beyond "the signature is good".
  public type Verified = {
    /// The subnet that signed: the delegation's subnet, or the root subnet.
    subnetId : Principal;
    /// The certificate's `/time`.
    time : Nat;
    delegated : Bool;
  };

  /// The fixed 37-byte ASN.1 prefix DER-wrapping a raw 96-byte BLS12-381 G2 public key
  /// (OIDs 1.3.6.1.4.1.44668.5.3.1.2.1 and 1.3.6.1.4.1.44668.5.3.2.1).
  let DER_PREFIX : [Nat8] = [
    0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05,
    0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03,
    0x02, 0x01, 0x03, 0x61, 0x00,
  ];

  /// Strip the DER wrapping, checking the fixed prefix matches (a public key from ANYWHERE on
  /// the wire is untrusted bytes). `Bls.decompressG2` (called from `Bls.verify`) is what
  /// validates that the 96 bytes are actually a point in the right subgroup.
  func unwrapDer(der : Blob) : ?Blob {
    let bytes = Blob.toArray(der);
    if (bytes.size() != DER_PREFIX.size() + 96) return null;
    var i = 0;
    while (i < DER_PREFIX.size()) { if (bytes[i] != DER_PREFIX[i]) return null; i += 1 };
    ?Blob.fromArray(Array.tabulate<Nat8>(96, func(j) = bytes[DER_PREFIX.size() + j]))
  };

  /// The root subnet's id: the self-authenticating principal of the root key,
  /// `sha224(der) ‖ 0x02`. For mainnet this is `tdb26-jop6k-…-eqe`, the id the spec names;
  /// for a PocketIC instance or local replica it is that instance's own root subnet.
  public func rootSubnetId(rootKeyDer : Blob) : Principal =
    Principal.fromBlob(Hash.concat([Hash.sha224(rootKeyDer), "\02"]));

  /// `domain_sep("ic-state-root") ‖ root_hash(tree)` -- the exact bytes the signature covers.
  func stateRootMessage(tree : HashTree) : Blob {
    let sep = "ic-state-root";
    Hash.concat([Blob.fromArray([Nat8.fromNat(sep.size())]), Text.encodeUtf8(sep), rootHash(tree)])
  };

  func checkSig(tree : HashTree, signature : Blob, pubkeyDer : Blob) : Result<(), Error> {
    let ?pubkeyRaw = unwrapDer(pubkeyDer) else return #err(#malformed "public key does not DER-decode to a 96-byte G2 point");
    if (Bls.verify(pubkeyRaw, signature, stateRootMessage(tree), Bls.IC_DST)) #ok() else #err(#badSignature)
  };

  func checkTime(tree : HashTree, now : ?Nat, maxAgeNs : ?Nat) : Result<Nat, Error> {
    let ?t = time(tree) else return #err(#malformed "certificate has no /time");
    switch (now, maxAgeNs) {
      case (?n, ?max) {
        if (t + max < n) return #err(#stale { certified = t; now = n; maxAgeNs = max });
        if (t > n + max) return #err(#fromFuture { certified = t; now = n });
      };
      case _ {};
    };
    #ok t
  };

  /// Is `canisterId` inside one of a CBOR `canister_ranges` value's closed intervals? The
  /// value is `#6.55799([* [principal principal]])`, ordered by the principals' raw bytes.
  func inRanges(canisterId : Principal, rangesCbor : Blob) : Bool {
    let ?v = Cbor.decode(rangesCbor) else return false;
    let ?pairs = Cbor.asArray(?v) else return false;
    let idBytes = Principal.toBlob(canisterId);
    for (pair in pairs.values()) {
      let ?p = Cbor.asArray(?pair) else return false;
      if (p.size() != 2) return false;
      let ?lo = Cbor.asBytes(?p[0]) else return false;
      let ?hi = Cbor.asBytes(?p[1]) else return false;
      if (Blob.compare(idBytes, lo) != #less and Blob.compare(idBytes, hi) != #greater) return true;
    };
    false
  };

  /// Every canister-range value the tree certifies for `subnetId`, in either encoding.
  public func subnetRanges(tree : HashTree, subnetId : Principal) : [Blob] {
    let sid = Principal.toBlob(subnetId);
    let sharded = lookupAll(tree, ["canister_ranges", sid]);
    let whole = switch (lookup(tree, ["subnet", sid, "canister_ranges"])) { case (#found r) [r]; case _ [] };
    Array.append(sharded, whole)
  };

  /// Is `canisterId` in the ranges `tree` certifies for `subnetId`? `#unproven` when the tree
  /// reveals no ranges for that subnet at all (pruned or not requested).
  public func canisterInSubnet(tree : HashTree, subnetId : Principal, canisterId : Principal) : { #yes; #no; #unproven } {
    let rs = subnetRanges(tree, subnetId);
    if (rs.size() == 0) return #unproven;
    for (r in rs.values()) { if (inRanges(canisterId, r)) return #yes };
    #no
  };

  /// `verify_cert` plus the delegation scoping and time policy (see `Scope`, `Policy`).
  public func verifyScoped(cert : Certificate, rootKeyDer : Blob, scope : Scope, policy : Policy) : Result<Verified, Error> {
    if (not wellFormed(cert.tree)) return #err(#notWellFormed);
    let t = switch (checkTime(cert.tree, policy.now, ?policy.maxAgeNs)) { case (#ok t) t; case (#err e) return #err e };
    switch (cert.delegation) {
      case null {
        let root = rootSubnetId(rootKeyDer);
        switch scope {
          case (#subnet s) { if (s != root) return #err(#subnetMismatch { expected = s; got = root }) };
          case (#canister _) {};   // the root key may certify for any canister
        };
        switch (checkSig(cert.tree, cert.signature, rootKeyDer)) { case (#err e) return #err e; case (#ok()) {} };
        #ok { subnetId = root; time = t; delegated = false }
      };
      case (?d) {
        let ?inner = decode(d.certificate) else return #err(#malformed "delegation certificate does not decode");
        if (inner.delegation != null) return #err(#delegationTooDeep);
        if (not wellFormed(inner.tree)) return #err(#notWellFormed);
        switch (checkTime(inner.tree, policy.now, policy.maxDelegationAgeNs)) { case (#err e) return #err e; case (#ok _) {} };
        switch (checkSig(inner.tree, inner.signature, rootKeyDer)) { case (#err e) return #err e; case (#ok()) {} };
        let subnet = Principal.fromBlob(d.subnetId);
        let ?subnetKeyDer = (switch (lookup(inner.tree, ["subnet", d.subnetId, "public_key"])) { case (#found k) ?k; case _ null }) else {
          return #err(#malformed "delegation: subnet public_key not in the inner certificate's tree");
        };
        switch scope {
          case (#subnet s) { if (s != subnet) return #err(#subnetMismatch { expected = s; got = subnet }) };
          case (#canister c) {
            switch (canisterInSubnet(inner.tree, subnet, c)) {
              case (#yes) {};
              case (#no) return #err(#canisterOutOfRange);
              case (#unproven) return #err(#malformed "delegation: no canister ranges for the subnet in the inner certificate");
            };
          };
        };
        switch (checkSig(cert.tree, cert.signature, subnetKeyDer)) { case (#err e) return #err e; case (#ok()) {} };
        #ok { subnetId = subnet; time = t; delegated = true }
      };
    }
  };

  /// The 0.1.0 entry point, kept: signature + delegation scope to `canisterId`, no time check.
  /// New code should call `verifyScoped` with a `Policy`, which is what `Agent` does.
  public func verify(cert : Certificate, rootKeyDer : Blob, canisterId : Principal) : Result<(), Error> {
    switch (verifyScoped(cert, rootKeyDer, #canister canisterId, { now = null; maxAgeNs = 0; maxDelegationAgeNs = null })) {
      case (#ok _) #ok();
      case (#err e) #err e;
    }
  };

  /// The nodes of `subnetId` and their DER Ed25519 keys, from `/subnet/<subnet>/node/<node>/public_key`.
  public func nodeKeys(tree : HashTree, subnetId : Principal) : [(Principal, Blob)] {
    let out = Buffer.Buffer<(Principal, Blob)>(16);
    for ((node, _) in children(tree, ["subnet", Principal.toBlob(subnetId), "node"]).values()) {
      switch (lookup(tree, ["subnet", Principal.toBlob(subnetId), "node", node, "public_key"])) {
        case (#found k) out.add((Principal.fromBlob(node), k));
        case _ {};
      };
    };
    Buffer.toArray(out)
  };

  /// `/subnet/<subnet>/type`, if certified.
  public func subnetType(tree : HashTree, subnetId : Principal) : ?Text = switch (lookup(tree, ["subnet", Principal.toBlob(subnetId), "type"])) {
    case (#found t) Text.decodeUtf8(t);
    case _ null;
  };

  // ============================================================================================
  // Certified data and canister signatures (spec, "Certified data" and "Canister signatures").

  /// A canister's certified data out of a certificate it handed out (e.g. from
  /// `ic0.data_certificate` via an ICRC-3 `icrc3_get_tip_certificate` or an HTTP asset
  /// certificate): the certificate is verified, scoped to `canisterId`, under `policy`, and the
  /// value at `/canister/<id>/certified_data` returned.
  public func certifiedData(certBytes : Blob, canisterId : Principal, rootKeyDer : Blob, policy : Policy) : Result<Blob, Error> {
    let ?cert = decode(certBytes) else return #err(#malformed "certificate does not decode");
    switch (verifyScoped(cert, rootKeyDer, #canister canisterId, policy)) { case (#err e) return #err e; case (#ok _) {} };
    switch (lookup(cert.tree, ["canister", Principal.toBlob(canisterId), "certified_data"])) {
      case (#found v) #ok v;
      case _ #err(#malformed "certificate does not reveal the canister's certified_data");
    }
  };

  /// OID 1.3.6.1.4.1.56387.1.2 (canister-signature public keys), DER-encoded content bytes.
  let CANISTER_SIG_OID : [Nat8] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb8, 0x43, 0x01, 0x02];

  /// A DER TLV at `i`: (tag, content start, content length), long-form lengths included.
  func tlv(b : [Nat8], i : Nat) : ?(Nat8, Nat, Nat) {
    if (i + 2 > b.size()) return null;
    let tag = b[i];
    let l0 = Nat8.toNat(b[i + 1]);
    if (l0 < 0x80) { if (i + 2 + l0 > b.size()) return null; return ?(tag, i + 2, l0) };
    let n : Nat = l0 - (0x80 : Nat);
    if (n == 0 or n > 3 or i + 2 + n > b.size()) return null;
    var len = 0;
    var k = 0;
    while (k < n) { len := len * 256 + Nat8.toNat(b[i + 2 + k]); k += 1 };
    if (i + 2 + n + len > b.size()) return null;
    ?(tag, i + 2 + n, len)
  };

  /// Split a canister-signature public key into (signing canister, seed).
  public func canisterSigPublicKey(der : Blob) : ?(Principal, Blob) {
    let b = Blob.toArray(der);
    let ?(t0, s0, l0) = tlv(b, 0) else return null;
    if (t0 != 0x30 or s0 + l0 != b.size()) return null;
    let ?(t1, s1, l1) = tlv(b, s0) else return null;       // AlgorithmIdentifier
    if (t1 != 0x30) return null;
    let ?(t2, s2, l2) = tlv(b, s1) else return null;       // OID
    if (t2 != 0x06 or l2 != CANISTER_SIG_OID.size()) return null;
    var k = 0;
    while (k < l2) { if (b[s2 + k] != CANISTER_SIG_OID[k]) return null; k += 1 };
    let ?(t3, s3, l3) = tlv(b, s1 + l1) else return null;  // BIT STRING
    if (t3 != 0x03 or l3 < 2 or b[s3] != 0x00) return null;
    let key = Array.tabulate<Nat8>(l3 - 1, func(j) = b[s3 + 1 + j]);
    let idLen = Nat8.toNat(key[0]);
    if (1 + idLen > key.size()) return null;
    let id = Blob.fromArray(Array.tabulate<Nat8>(idLen, func(j) = key[1 + j]));
    let seed = Blob.fromArray(Array.tabulate<Nat8>((key.size() : Nat) - (1 + idLen : Nat), func(j) = key[1 + idLen + j]));
    ?(Principal.fromBlob(id), seed)
  };

  /// Verify a canister signature (spec, "Canister signatures") -- how Internet Identity signs
  /// the root of a delegation chain. `payload` is the full signed payload INCLUDING its domain
  /// separator (for a delegation: `"\x1Aic-request-auth-delegation" · hash_of_map(delegation)`).
  public func verifyCanisterSignature(payload : Blob, publicKeyDer : Blob, signature : Blob, rootKeyDer : Blob, policy : Policy) : Result<(), Error> {
    let ?(signer, seed) = canisterSigPublicKey(publicKeyDer) else return #err(#malformed "not a canister-signature public key");
    let ?v = Cbor.decode(signature) else return #err(#malformed "canister signature is not CBOR");
    let ?certBytes = Cbor.asBytes(Cbor.field(v, "certificate")) else return #err(#malformed "canister signature without certificate");
    let ?treeV = Cbor.field(v, "tree") else return #err(#malformed "canister signature without tree");
    let ?sigTree = decodeTree(treeV) else return #err(#malformed "canister signature tree does not decode");
    let ?cert = decode(certBytes) else return #err(#malformed "canister signature certificate does not decode");
    let verified = switch (verifyScoped(cert, rootKeyDer, #canister signer, policy)) { case (#ok x) x; case (#err e) return #err e };
    if (verified.delegated) {
      // The subnet type lives in the delegation's certificate, which verifyScoped checked.
      let ?d = cert.delegation else return #err(#malformed "delegation vanished");
      let ?inner = decode(d.certificate) else return #err(#malformed "delegation certificate does not decode");
      switch (subnetType(inner.tree, verified.subnetId)) {
        case (?"cloud_engine") return #err(#subnetType "cloud_engine");
        case null return #err(#subnetType "absent");
        case _ {};
      };
    };
    switch (lookup(cert.tree, ["canister", Principal.toBlob(signer), "certified_data"])) {
      case (#found cd) { if (cd != rootHash(sigTree)) return #err(#badSignature) };
      case _ return #err(#malformed "certificate does not reveal the signer's certified_data");
    };
    if (not wellFormed(sigTree)) return #err(#notWellFormed);
    switch (lookup(sigTree, ["sig", Hash.sha256(seed), Hash.sha256(payload)])) {
      case (#found v) { if (v.size() == 0) #ok() else #err(#badSignature) };
      case _ #err(#badSignature);
    }
  };
}

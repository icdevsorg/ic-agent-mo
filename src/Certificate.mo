/// Certificates and hash trees (interface spec, "Certification"): decode a certificate,
/// walk its tree for a path, read a request's status, and (alpha-7 G2) VERIFY the BLS
/// signature over the tree's root hash against a subnet's public key, including one level of
/// delegation. `verify` is the thing that makes a certificate worth trusting; the rest of
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

  // ============================================================================================
  // Signature verification (alpha-7 G2). The interface spec's "Certification": the signature
  // is BLS12-381 min_sig (public key in G2, signature in G1) over
  // `domain_sep("ic-state-root") ‖ root_hash(tree)`, `domain_sep(s) = len(s) byte ‖ s`. A
  // certificate may carry ONE delegation: the inner certificate is signed by the root key and
  // its tree holds the subnet's own (DER-wrapped) public key and its `canister_ranges`; the
  // outer certificate is then verified against that subnet key, and the target canister must
  // fall in one of the ranges.
  public type Result<T, E> = { #ok : T; #err : E };
  public type Error = {
    /// The certificate does not decode into the shape `verify` needs (missing/malformed
    /// delegation fields, a canister_ranges blob that is not valid CBOR, an unparseable DER key).
    #malformed : Text;
    /// The certificate carries a delegation whose OWN certificate is itself delegated -- the
    /// spec allows exactly one level.
    #delegationTooDeep;
    /// The target canister is not inside any range the delegation's `canister_ranges` lists.
    #canisterOutOfRange;
    /// The BLS signature itself does not check out (root or, under a delegation, subnet key).
    #badSignature;
  };

  /// The fixed 37-byte ASN.1 prefix DER-wrapping a raw 96-byte BLS12-381 G2 public key
  /// (interface spec; also `Agent.MAINNET_ROOT_KEY`'s own first 37 bytes).
  let DER_PREFIX : [Nat8] = [
    0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05,
    0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03,
    0x02, 0x01, 0x03, 0x61, 0x00,
  ];

  /// Strip the DER wrapping, checking the fixed prefix matches (a public key from ANYWHERE on
  /// the wire, root key or a delegation's subnet key, is untrusted bytes the first time they
  /// are seen). Returns the raw 96-byte G2 point, still uncompressed-checked --
  /// `Bls.decompressG2` (called from `Bls.verify`) is what validates it is actually a point.
  func unwrapDer(der : Blob) : ?Blob {
    let bytes = Blob.toArray(der);
    if (bytes.size() != DER_PREFIX.size() + 96) return null;
    var i = 0;
    while (i < DER_PREFIX.size()) { if (bytes[i] != DER_PREFIX[i]) return null; i += 1 };
    ?Blob.fromArray(Array.tabulate<Nat8>(96, func(j) = bytes[DER_PREFIX.size() + j]))
  };

  /// `domain_sep("ic-state-root") ‖ root_hash(tree)` -- the exact bytes the signature covers.
  /// NOT itself hashed again (unlike a hash-tree node's own `domain_sep`, which IS sha256'd --
  /// see the private `domain` helper above): the spec's `request_id`/certification signing
  /// scheme signs this concatenation directly.
  func stateRootMessage(tree : HashTree) : Blob {
    let sep = "ic-state-root";
    Hash.concat([Blob.fromArray([Nat8.fromNat(sep.size())]), Text.encodeUtf8(sep), rootHash(tree)])
  };

  func checkSig(tree : HashTree, signature : Blob, pubkeyDer : Blob) : Result<(), Error> {
    let ?pubkeyRaw = unwrapDer(pubkeyDer) else return #err(#malformed "public key does not DER-decode to a 96-byte G2 point");
    if (Bls.verify(pubkeyRaw, signature, stateRootMessage(tree), Bls.IC_DST)) #ok() else #err(#badSignature)
  };

  /// A CBOR-encoded list of `(low, high)` principal-blob pairs (the tree leaf at
  /// `subnet/<subnet_id>/canister_ranges`); both ends inclusive, ordered by the principal's
  /// raw bytes (the same ordering `Principal`/`Blob.compare` uses).
  func canisterInRanges(canisterId : Principal, rangesCbor : Blob) : Bool {
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

  /// Verify a certificate: its signature checks out against `rootKeyDer` (directly, or via
  /// one delegation whose subnet range covers `canisterId`). `rootKeyDer` is normally
  /// `Agent.MAINNET_ROOT_KEY`, or a replica/PocketIC gateway's own root key from
  /// `GET /api/v2/status`.
  ///
  /// PERFORMANCE: this is 1-2 BLS pairings' worth of work -- roughly 28-56 billion wasm
  /// instructions, several seconds off-chain (`mops/mo-ic-agent/README.md`, "Certificate
  /// verification cost"). `Agent`'s `verify` option (`lib.mo`) is what lets a caller who
  /// already knows that cost and does not want to pay it every poll say so, loudly.
  public func verify(cert : Certificate, rootKeyDer : Blob, canisterId : Principal) : Result<(), Error> {
    switch (cert.delegation) {
      case null checkSig(cert.tree, cert.signature, rootKeyDer);
      case (?d) {
        let ?inner = decode(d.certificate) else return #err(#malformed "delegation certificate does not decode");
        if (inner.delegation != null) return #err(#delegationTooDeep);
        switch (checkSig(inner.tree, inner.signature, rootKeyDer)) {
          case (#err e) return #err e;
          case (#ok()) {};
        };
        let subnetPath : [Blob] = ["subnet", d.subnetId, "public_key"];
        let ?subnetKeyDer = (switch (lookup(inner.tree, subnetPath)) { case (#found k) ?k; case _ null }) else {
          return #err(#malformed "delegation: subnet public_key not in the inner certificate's tree");
        };
        let rangesPath : [Blob] = ["subnet", d.subnetId, "canister_ranges"];
        let ?rangesCbor = (switch (lookup(inner.tree, rangesPath)) { case (#found r) ?r; case _ null }) else {
          return #err(#malformed "delegation: canister_ranges not in the inner certificate's tree");
        };
        if (not canisterInRanges(canisterId, rangesCbor)) return #err(#canisterOutOfRange);
        checkSig(cert.tree, cert.signature, subnetKeyDer)
      };
    }
  };
}

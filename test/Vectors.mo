/// Known-answer tests: request ids from the interface spec's worked example and from
/// agent-js, an envelope byte-for-byte against agent-js, ed25519 keys/principals/signatures
/// against node's crypto, secp256k1 keys/principals against node, and a hash tree's root
/// and lookups against agent-js. `check()` returns the number of checks passed and traps
/// on the first failure, so the same actor built by moxzi and by moc must agree.
import Hash "../src/Hash";
import Cbor "../src/Cbor";
import Identity "../src/Identity";
import Envelope "../src/Envelope";
import Certificate "../src/Certificate";
import Agent "../src/lib";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";
import Text "mo:base/Text";

persistent actor {
  var passed = 0;
  func expect(name : Text, ok : Bool) { if (ok) { passed += 1 } else { Debug.trap("FAIL: " # name) } };
  func expectBlob(name : Text, got : Blob, want : Blob) {
    if (got == want) { passed += 1 } else { Debug.trap("FAIL: " # name # "\n  got  " # Hash.toHex(got) # "\n  want " # Hash.toHex(want)) }
  };
  func hex(t : Text) : Blob = switch (Hash.fromHex(t)) { case (?b) b; case null Debug.trap("bad hex " # t) };

  let SPEC_CALL_ID = "1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101";
  let ED_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  let ED_DER = "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  let SECP_DER = "3056301006072a8648ce3d020106052b8104000a0342000479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
  let TREE = "d9d9f783018302416182034178830182045820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa83024e726571756573745f737461747573830258201d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b10183018302457265706c798203484449444c00017d2a8302467374617475738203477265706c696564";

  public func check() : async Nat {
    passed := 0;
    // ---- LEB128 and hex
    expect("leb128 624485", Hash.leb128(624485) == hex("e58e26"));
    expect("leb128 0", Hash.leb128(0) == hex("00"));
    expect("unleb128", Hash.unleb128(hex("e58e26")) == 624485);
    expect("hex round trip", Hash.toHex(hex("00ff10")) == "00ff10");

    // ---- request ids: the spec's worked example, and agent-js for the other shapes
    let anon = Identity.anonymous();
    let can = Principal.fromBlob(hex("00000000000004d2"));
    let arg = hex("4449444c00fd2a");
    let call : Envelope.Content = #call { sender = anon; canister = can; method = "hello"; arg; expiry = 1685570400000000000; nonce = null; senderInfo = null };
    expect("request id: spec call", Envelope.requestId(call) == hex(SPEC_CALL_ID));
    let q : Envelope.Content = #queryCall { sender = anon; canister = can; method = "hello"; arg; expiry = 1685570400000000000; nonce = null; senderInfo = null };
    expect("request id: query", Envelope.requestId(q) == hex("74aff80b32e98aafb7f1b6cbedc29d2f7de9227d60a55169342600099f0e4147"));
    let rs : Envelope.Content = #readState { sender = anon; expiry = 1685570400000000000; paths = [["request_status", hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")]] };
    expect("request id: read_state", Envelope.requestId(rs) == hex("1786cf115454c5880804cb00867211ba06ca8f8bb96778677c24a8cb8bc72759"));
    let withNonce : Envelope.Content = #call { sender = anon; canister = can; method = "hello"; arg; expiry = 1685570400000000000; nonce = ?hex("0102030405060708"); senderInfo = null };
    expect("request id: call with nonce", Envelope.requestId(withNonce) == hex("746566dba1acd0cefb00e8c123c5b54bc55f621270284b533e9d007665dbf5d2"));

    // ---- the envelope, byte for byte (anonymous query, an expiry agent-js encodes as a uint)
    let small : Envelope.Content = #queryCall { sender = anon; canister = can; method = "hello"; arg; expiry = 1000000; nonce = null; senderInfo = null };
    expectBlob("envelope: anonymous query bytes", Envelope.encode(small, #anonymous), hex("d9d9f7a167636f6e74656e74a663617267474449444c00fd2a6b63616e69737465725f69644800000000000004d26e696e67726573735f6578706972791a000f42406b6d6574686f645f6e616d656568656c6c6f6c726571756573745f747970656571756572796673656e6465724104"));
    expect("request id: small expiry", Envelope.requestId(small) == hex("190e9719eebd7c31dae641e7ff7423c96c09b85c3c59528d1ab4e8c6aabb6775"));

    // ---- ed25519 (RFC 8032 test key; node crypto signed the same bytes)
    let ed = Identity.ed25519(hex(ED_SEED));
    expect("ed25519: DER public key", Identity.publicKey(ed) == ?hex(ED_DER));
    expect("ed25519: principal", Principal.toText(Identity.principal(ed)) == "e73il-iz5tp-nkgt7-idxyw-ngkah-47bpv-qdase-pzde6-g6vwc-a3eql-jae");
    let msg = Hash.concat([Envelope.DOMAIN_REQUEST, hex(SPEC_CALL_ID)]);
    expect("ed25519: signature", Identity.sign(ed, msg) == ?hex("c7be853914dd46450447efacbc97d6b95e8439a632d0505cedab86b0ec1ac068253834ca0204f7aec20de634e1d4357d12b5636d398207b116c14cd6778fa009"));
    let ?env = Cbor.decode(Envelope.encode(call, ed)) else Debug.trap("signed envelope does not decode");
    expect("ed25519: envelope carries pubkey and signature", Cbor.asBytes(Cbor.field(env, "sender_pubkey")) == Identity.publicKey(ed) and Cbor.asBytes(Cbor.field(env, "sender_sig")) == Identity.sign(ed, msg));
    expect("ed25519: envelope content", Cbor.field(env, "content") == ?Envelope.content(call));

    // ---- secp256k1 (secret 1: the generator point; node derived the key and principal)
    let k = Identity.secp256k1(hex("0000000000000000000000000000000000000000000000000000000000000001"));
    expect("secp256k1: DER public key", Identity.publicKey(k) == ?hex(SECP_DER));
    expect("secp256k1: principal", Principal.toText(Identity.principal(k)) == "vh5jj-2v5av-uunuh-hbba5-pss3b-vrzng-7dqdp-xcku3-zj2tc-36shc-bqe");
    let s1 = Identity.sign(k, msg);
    expect("secp256k1: 64-byte deterministic signature", (switch s1 { case (?s) s.size() == 64; case null false }) and s1 == Identity.sign(k, msg));

    // ---- principals
    expect("anonymous principal", Principal.toText(anon) == "2vxsx-fae");
    expect("self-authenticating from DER", Identity.selfAuthenticating(hex(ED_DER)) == Identity.principal(ed));

    // ---- a delegation chain: the principal is the ROOT key's, the session key signs
    let chain : [Identity.SignedDelegation] = [{ delegation = { pubkey = hex(ED_DER); expiration = 1_700_000_000_000_000_000; targets = ?[can] }; signature = hex("00") }];
    let del = Identity.delegated(hex(SECP_DER), chain, ed);
    expect("delegated: principal from the root key", Identity.principal(del) == Identity.selfAuthenticating(hex(SECP_DER)));
    let ?denv = Cbor.decode(Envelope.encode(call, del)) else Debug.trap("delegated envelope does not decode");
    expect("delegated: sender_pubkey is the root key", Cbor.asBytes(Cbor.field(denv, "sender_pubkey")) == ?hex(SECP_DER));
    expect("delegated: session key signs", Cbor.asBytes(Cbor.field(denv, "sender_sig")) == Identity.sign(ed, msg));
    let ?ds = Cbor.asArray(Cbor.field(denv, "sender_delegation")) else Debug.trap("no sender_delegation");
    expect("delegated: one delegation", ds.size() == 1);
    expect("delegated: delegation fields", switch (Cbor.field(ds[0], "delegation")) {
      case (?d) Cbor.asBytes(Cbor.field(d, "pubkey")) == ?hex(ED_DER) and Cbor.asNat(Cbor.field(d, "expiration")) == ?1_700_000_000_000_000_000 and (switch (Cbor.asArray(Cbor.field(d, "targets"))) { case (?ts) ts.size() == 1; case null false });
      case null false;
    });
    expect("delegation hash is domain separated", Envelope.delegationHash(chain[0].delegation).size() == 27 + 32);

    // ---- hash trees (agent-js built this tree, reconstructed its root, looked up paths)
    let ?tv = Cbor.decode(hex(TREE)) else Debug.trap("tree cbor");
    let ?t = Certificate.decodeTree(tv) else Debug.trap("tree decode");
    expect("tree: root hash", Certificate.rootHash(t) == hex("429f8d34b1844bfa202b7256f5128b6a4cfcde2a43c0adf92adf50bafa3b943c"));
    let rid = hex(SPEC_CALL_ID);
    expect("tree: lookup found", Certificate.lookup(t, ["request_status", rid, "status"]) == #found(Text.encodeUtf8("replied")));
    expect("tree: lookup absent", Certificate.lookup(t, ["request_status", rid, "reject_code"]) == #absent);
    expect("tree: lookup unknown behind a pruned node", Certificate.lookup(t, ["b"]) == #unknown);
    expect("tree: lookup a", Certificate.lookup(t, ["a"]) == #found(Text.encodeUtf8("x")));
    expect("tree: request status replied", Certificate.requestStatus(t, rid) == #replied(hex("4449444c00017d2a")));
    expect("tree: unknown request", Certificate.requestStatus(t, hex("ff")) == #unknown);
    let cert = Cbor.encode(Cbor.map([("tree", tv), ("signature", Cbor.bytes(hex("aa")))]));
    expect("certificate: decode", switch (Certificate.decode(cert)) { case (?c) c.signature == hex("aa") and c.delegation == null and Certificate.rootHash(c.tree) == Certificate.rootHash(t); case null false });
    // a rejected status, built here
    let rejected : Certificate.HashTree = #labeled("request_status", #labeled(rid, #fork(
      #fork(#labeled("reject_code", #leaf(Hash.leb128(4))), #labeled("reject_message", #leaf("no"))),
      #labeled("status", #leaf("rejected")))));
    expect("tree: request status rejected", Certificate.requestStatus(rejected, rid) == #rejected { code = 4; message = "no"; errorCode = null });
    expect("reject code names", Agent.rejectCode(4) == #canisterReject and Agent.rejectCode(9) == #other 9);
    passed
  };
};

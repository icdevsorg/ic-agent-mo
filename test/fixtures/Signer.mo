/// A canister that SIGNS, for the gate: it publishes a canister signature (spec, "Canister
/// signatures") the way Internet Identity does -- certified data = the root of a tree holding
/// `sig/<sha256 seed>/<sha256 payload> = ""` -- and hands out its data certificate, so the
/// agent under moxzid can verify a real canister signature and a real certified-data
/// certificate issued by PocketIC.
import Certificate "../../src/Certificate";
import Hash "../../src/Hash";
import Cbor "../../src/Cbor";
import CertifiedData "mo:base/CertifiedData";

persistent actor Signer {
  transient var tree : Certificate.HashTree = #empty;

  func treeCbor(t : Certificate.HashTree) : Cbor.Value = switch t {
    case (#empty) Cbor.array([Cbor.nat64(0)]);
    case (#fork(l, r)) Cbor.array([Cbor.nat64(1), treeCbor(l), treeCbor(r)]);
    case (#labeled(l, s)) Cbor.array([Cbor.nat64(2), Cbor.bytes(l), treeCbor(s)]);
    case (#leaf v) Cbor.array([Cbor.nat64(3), Cbor.bytes(v)]);
    case (#pruned h) Cbor.array([Cbor.nat64(4), Cbor.bytes(h)]);
  };

  public func sign(seed : Blob, payload : Blob) : async () {
    tree := #labeled("sig", #labeled(Hash.sha256(seed), #labeled(Hash.sha256(payload), #leaf "")));
    CertifiedData.set(Certificate.rootHash(tree));
  };

  /// The canister signature: CBOR `{certificate, tree}` under the self-describe tag.
  public query func signature() : async ?Blob {
    let ?cert = CertifiedData.getCertificate() else return null;
    ?Cbor.encode(Cbor.map([("certificate", Cbor.bytes(cert)), ("tree", treeCbor(tree))]))
  };

  public query func certificate() : async ?Blob { CertifiedData.getCertificate() };

  public query func expectedCertifiedData() : async Blob { Certificate.rootHash(tree) };
};

/// Who signs. An identity is the anonymous principal, a key that signs (ed25519 or
/// secp256k1, or any signer a host supplies), or a delegation chain ending in a session key
/// -- which is how an Internet Identity user signs from a browser or a phone.
import Hash "Hash";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";
import Ed "mo:ed25519";
import Ecdsa "mo:libsecp256k1/Ecdsa";
import SecretKey "mo:libsecp256k1/SecretKey";
import PublicKey "mo:libsecp256k1/PublicKey";
import Message "mo:libsecp256k1/Message";
import ECMult "mo:libsecp256k1/core/ecmult";
import Random "mo:libsecp256k1/interfaces/Random";

module {
  public type Delegation = { pubkey : Blob; expiration : Nat64; targets : ?[Principal] };
  public type SignedDelegation = { delegation : Delegation; signature : Blob };

  /// A DER-encoded public key and a function that signs the (domain-separated) request
  /// bytes with the matching secret. Host-held keys plug in here.
  public type Signer = { publicKey : Blob; sign : Blob -> Blob };

  public type Identity = {
    #anonymous;
    #signer : Signer;
    /// `publicKey` is the chain's ROOT key: the sender principal derives from it. `signer`
    /// holds the session key the last delegation names, and does the signing.
    #delegated : { publicKey : Blob; chain : [SignedDelegation]; signer : Signer };
  };

  /// SubjectPublicKeyInfo prefixes: id-Ed25519, and id-ecPublicKey with secp256k1.
  public let ED25519_DER_PREFIX : Blob = "\30\2a\30\05\06\03\2b\65\70\03\21\00";
  public let SECP256K1_DER_PREFIX : Blob = "\30\56\30\10\06\07\2a\86\48\ce\3d\02\01\06\05\2b\81\04\00\0a\03\42\00";

  /// A self-authenticating principal: sha224(DER public key) ++ 0x02.
  public func selfAuthenticating(der : Blob) : Principal = Principal.fromBlob(Hash.concat([Hash.sha224(der), "\02"]));

  public func anonymous() : Principal = Principal.fromBlob("\04");

  public func principal(id : Identity) : Principal = switch id {
    case (#anonymous) anonymous();
    case (#signer s) selfAuthenticating(s.publicKey);
    case (#delegated d) selfAuthenticating(d.publicKey);
  };

  public func publicKey(id : Identity) : ?Blob = switch id {
    case (#anonymous) null;
    case (#signer s) ?s.publicKey;
    case (#delegated d) ?d.publicKey;
  };

  public func sign(id : Identity, message : Blob) : ?Blob = switch id {
    case (#anonymous) null;
    case (#signer s) ?s.sign(message);
    case (#delegated d) ?d.signer.sign(message);
  };

  /// An ed25519 identity from its 32-byte seed. Signs the message directly.
  public func ed25519(seed : Blob) : Identity {
    if (seed.size() != 32) Debug.trap("ed25519: a seed is 32 bytes");
    let sk = Blob.toArray(seed);
    let pub = Ed.ED25519.getPublicKey(sk);
    #signer {
      publicKey = Hash.concat([ED25519_DER_PREFIX, Blob.fromArray(pub)]);
      sign = func(m : Blob) : Blob = Blob.fromArray(Ed.ED25519.sign(Blob.toArray(m), sk));
    }
  };

  /// A secp256k1 identity from its 32-byte secret. The IC verifies ECDSA over sha256(message)
  /// and takes the signature as r || s (64 bytes). The generator table (`ECMultGenContext`)
  /// is computed once per identity, which is the expensive part; keep the identity around.
  public func secp256k1(secret : Blob) : Identity {
    let sk = switch (SecretKey.parse(Blob.toArray(secret))) {
      case (#ok k) k;
      case (#err e) Debug.trap("secp256k1: invalid secret key: " # debug_show e);
    };
    let ctx = ECMult.ECMultGenContext(null);
    let pub = PublicKey.from_secret_key_with_context(sk, ctx).serialize();
    let der = Hash.concat([SECP256K1_DER_PREFIX, Blob.fromArray(pub)]);
    #signer {
      publicKey = der;
      sign = func(m : Blob) : Blob {
        let digest = Hash.sha256(m);
        // A DETERMINISTIC nonce: a function of the secret and the digest alone (not RFC
        // 6979's construction, but the same properties that matter here -- signing is
        // reproducible under replay, and two messages never share a nonce). A nonce the
        // curve rejects retries with the counter bumped.
        var counter : Nat8 = 0;
        let random = Random.Random(func() : [Nat8] {
          counter += 1;
          Blob.toArray(Hash.sha256(Hash.concat([secret, digest, Blob.fromArray([counter])])))
        });
        switch (Ecdsa.sign_with_context(Message.parse(Blob.toArray(digest)), sk, ctx, random)) {
          case (#ok((sig, _))) Blob.fromArray(sig.serialize());
          case (#err e) Debug.trap("secp256k1: signing failed: " # debug_show e);
        }
      };
    }
  };

  /// A delegation chain from `rootPublicKey` (DER) down to `session`, which must sign.
  public func delegated(rootPublicKey : Blob, chain : [SignedDelegation], session : Identity) : Identity = switch session {
    case (#signer s) #delegated { publicKey = rootPublicKey; chain; signer = s };
    case (#delegated d) #delegated { publicKey = rootPublicKey; chain = Array.append(chain, d.chain); signer = d.signer };
    case (#anonymous) Debug.trap("a delegation needs a session key that signs");
  };
}

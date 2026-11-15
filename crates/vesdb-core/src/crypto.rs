//! Hybrid signatures: Ed25519 + ML-DSA-65 (FIPS 204). A hybrid signature verifies only if BOTH
//! component signatures verify, so it stays unforgeable while either scheme is unbroken.
//!
//! Keys are derived deterministically from one 32-byte master seed with domain separation, so a
//! key file is just a name and a seed.

use crate::{b64, sha256};
use ed25519_dalek::{Signature as EdSig, SigningKey as EdSk, VerifyingKey as EdVk};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, Signature as MlSig, SigningKey as MlSk, VerifyingKey as MlVk,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Public half of a hybrid key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub name: String,
    #[serde(with = "b64::bytes")]
    pub ed25519: Vec<u8>,
    #[serde(with = "b64::bytes")]
    pub mldsa65: Vec<u8>,
}

impl PublicKey {
    /// Short identifier: first 4 bytes of SHA-256 over name, LF and both keys (C2SP-style key ID).
    pub fn key_id(&self) -> String {
        hex::encode(&sha256(&[self.name.as_bytes(), b"\n", &self.ed25519, &self.mldsa65])[..4])
    }
}

/// A hybrid signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSig {
    #[serde(with = "b64::bytes")]
    pub ed25519: Vec<u8>,
    #[serde(with = "b64::bytes")]
    pub mldsa65: Vec<u8>,
}

/// Secret key file contents.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub name: String,
    pub seed_hex: String,
}

/// A hybrid signing key.
pub struct HybridKey {
    name: String,
    ed: EdSk,
    ml: MlSk<MlDsa65>,
}

impl HybridKey {
    pub fn from_seed(name: impl Into<String>, seed: &[u8; 32]) -> Self {
        let ed_seed = sha256(&[b"vesdb/key/ed25519/v1", seed]);
        let ml_seed = sha256(&[b"vesdb/key/mldsa65/v1", seed]);
        Self {
            name: name.into(),
            ed: EdSk::from_bytes(&ed_seed),
            ml: MlSk::<MlDsa65>::from_seed(&ml_seed.into()),
        }
    }

    pub fn generate(name: impl Into<String>) -> (Self, [u8; 32]) {
        let seed = crate::random_bytes::<32>();
        (Self::from_seed(name, &seed), seed)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            name: self.name.clone(),
            ed25519: self.ed.verifying_key().to_bytes().to_vec(),
            mldsa65: self.ml.verifying_key().encode().to_vec(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> HybridSig {
        let ed: EdSig = self.ed.sign(msg);
        let ml: MlSig<MlDsa65> = self.ml.sign(msg);
        HybridSig {
            ed25519: ed.to_bytes().to_vec(),
            mldsa65: ml.encode().to_vec(),
        }
    }

    /// Ed25519-only signature, for the EventSourcingDB-compatible read-time `signature` field
    /// (`esdb:signature:v1:<hex>` over the `hash` text). Not post-quantum; receipts are.
    pub fn sign_ed25519(&self, msg: &[u8]) -> [u8; 64] {
        let s: EdSig = self.ed.sign(msg);
        s.to_bytes()
    }

    /// Write a new key: secret `{name, seed_hex}` to `path` (mode 0600) and the public key to
    /// `path.pub`.
    pub fn generate_files(name: &str, path: &Path) -> std::io::Result<PublicKey> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let (k, seed) = Self::generate(name);
        let kf = KeyFile {
            name: name.into(),
            seed_hex: hex::encode(seed),
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&serde_json::to_vec_pretty(&kf)?)?;
        let pk = k.public();
        let mut pub_path = path.as_os_str().to_owned();
        pub_path.push(".pub");
        std::fs::write(pub_path, serde_json::to_vec_pretty(&pk)?)?;
        Ok(pk)
    }

    /// Load `{name, seed_hex}` from a JSON key file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let kf: KeyFile = serde_json::from_slice(&std::fs::read(path)?)?;
        let seed: [u8; 32] = hex::decode(&kf.seed_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "seed_hex must be 32 bytes of hex",
                )
            })?;
        Ok(Self::from_seed(kf.name, &seed))
    }
}

pub fn load_public(path: &Path) -> std::io::Result<PublicKey> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Verify a hybrid signature. Both halves must verify.
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &HybridSig) -> bool {
    let Ok(ed_pk): Result<[u8; 32], _> = pk.ed25519.as_slice().try_into() else {
        return false;
    };
    let Ok(ed_vk) = EdVk::from_bytes(&ed_pk) else {
        return false;
    };
    let Ok(ed_sig): Result<[u8; 64], _> = sig.ed25519.as_slice().try_into() else {
        return false;
    };
    if ed_vk
        .verify_strict(msg, &EdSig::from_bytes(&ed_sig))
        .is_err()
    {
        return false;
    }
    let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(pk.mldsa65.as_slice()) else {
        return false;
    };
    let ml_vk = MlVk::<MlDsa65>::decode(&enc);
    let Ok(ml_sig) = MlSig::<MlDsa65>::try_from(sig.mldsa65.as_slice()) else {
        return false;
    };
    ml_vk.verify(msg, &ml_sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_requires_both_halves() {
        let k = HybridKey::from_seed("t", &[1; 32]);
        let other = HybridKey::from_seed("o", &[2; 32]);
        let s = k.sign(b"msg");
        assert!(verify(&k.public(), b"msg", &s));
        assert!(!verify(&k.public(), b"msg2", &s));
        let mut mixed = s.clone();
        mixed.mldsa65 = other.sign(b"msg").mldsa65;
        assert!(
            !verify(&k.public(), b"msg", &mixed),
            "valid Ed25519 + wrong ML-DSA must fail"
        );
        let mut mixed = s.clone();
        mixed.ed25519 = other.sign(b"msg").ed25519;
        assert!(
            !verify(&k.public(), b"msg", &mixed),
            "wrong Ed25519 + valid ML-DSA must fail"
        );
        assert_eq!(s.mldsa65.len(), 3309);
        assert_eq!(
            k.public(),
            HybridKey::from_seed("t", &[1; 32]).public(),
            "deterministic from seed"
        );
    }
}

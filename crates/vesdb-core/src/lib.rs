//! `vesdb-core`: the parts of vesdb that need no I/O.
//!
//! * [`encoding`]   – event metadata, the Merkle leaf encoding, payload commitments, the
//!   EventSourcingDB-compatible `esdb:hash:v2`.
//! * [`merkle`]     – RFC 9162 Merkle tree hash, inclusion and consistency proofs and their
//!   verifiers (the same algorithms as the Lean 4 definitions in the design doc).
//! * [`crypto`]     – hybrid Ed25519 + ML-DSA-65 signatures; a signature is valid only if both
//!   halves verify.
//! * [`checkpoint`] – checkpoints (C2SP checkpoint body), write-time receipts, cosignatures.
//! * [`witness`]    – honest-witness state machine (C2SP tlog-witness behaviour).
//! * [`bundle`]     – evidence bundles and their offline verification.
//! * [`validate`]   – subject / type / source rules shared with EventSourcingDB.

pub mod b64;
pub mod bundle;
pub mod checkpoint;
pub mod crypto;
pub mod encoding;
pub mod merkle;
pub mod objects;
pub mod time;
pub mod ts;
pub mod validate;
pub mod witness;

/// A SHA-256 digest.
pub type Hash = [u8; 32];

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Fill a buffer with operating-system randomness.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS randomness unavailable");
    b
}

//! Evidence bundles: a selection of events with everything needed to verify them offline against
//! one cosigned checkpoint, without trusting the log operator.

use crate::{
    b64,
    checkpoint::{Checkpoint, Receipt},
    crypto::PublicKey,
    encoding::{commitment, EventMeta},
    merkle::verify_inclusion,
    Hash,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleItem {
    pub event: EventMeta,
    /// `None` when the payload has been redacted.
    #[serde(default, with = "opt_bytes")]
    pub salt: Option<Vec<u8>>,
    /// Exact payload bytes (JSON text); `None` when redacted.
    #[serde(default)]
    pub data: Option<String>,
    /// Inclusion of the event's leaf in the bundle checkpoint.
    #[serde(with = "b64::hashes")]
    pub inclusion: Vec<Hash>,
    /// Write-time receipt covering the event and inclusion in the receipt's tree.
    pub receipt: Receipt,
    #[serde(with = "b64::hashes")]
    pub receipt_inclusion: Vec<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub checkpoint: Checkpoint,
    pub items: Vec<BundleItem>,
}

pub const BUNDLE_FORMAT: &str = "vesdb-evidence-bundle/v1";

mod opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&crate::b64::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(None),
            Some(s) => crate::b64::decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ItemReport {
    pub id: u64,
    pub ty: String,
    pub commitment_ok: bool,
    pub redacted: bool,
    pub inclusion_ok: bool,
    pub receipt_ok: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub ok: bool,
    pub log_signature_ok: bool,
    pub cosigners: Vec<String>,
    pub required_cosigners: usize,
    pub checkpoint_size: u64,
    pub items: Vec<ItemReport>,
    pub problems: Vec<String>,
}

/// Verify a bundle offline. `k` = minimum number of valid witness cosignatures.
pub fn verify_bundle(b: &Bundle, log_pub: &PublicKey, witnesses: &[PublicKey], k: usize) -> Report {
    let cp = &b.checkpoint;
    let mut r = Report {
        checkpoint_size: cp.size,
        required_cosigners: k,
        ..Default::default()
    };
    if b.format != BUNDLE_FORMAT {
        r.problems
            .push(format!("unknown bundle format {}", b.format));
    }
    r.log_signature_ok = cp.verify_log_sig(log_pub);
    if !r.log_signature_ok {
        r.problems.push("checkpoint log signature invalid".into());
    }
    r.cosigners = cp.valid_cosigners(witnesses);
    if r.cosigners.len() < k {
        r.problems.push(format!(
            "only {} of {} required witness cosignatures valid",
            r.cosigners.len(),
            k
        ));
    }
    for it in &b.items {
        let e = &it.event;
        let leaf = e.leaf();
        let mut ir = ItemReport {
            id: e.id,
            ty: e.ty.clone(),
            ..Default::default()
        };
        match (&it.salt, &it.data) {
            (Some(salt), Some(data)) => {
                ir.commitment_ok = salt.len() == 32
                    && commitment(
                        salt.as_slice().try_into().unwrap_or(&[0; 32]),
                        data.as_bytes(),
                    ) == e.commit;
            }
            (None, None) => {
                ir.redacted = true;
                ir.commitment_ok = true; // existence provable, content erased by design
            }
            _ => ir.commitment_ok = false,
        }
        ir.inclusion_ok = verify_inclusion(e.id, cp.size, &leaf, &it.inclusion, &cp.root);
        ir.receipt_ok = it.receipt.verify(&cp.origin, log_pub)
            && verify_inclusion(
                e.id,
                it.receipt.size,
                &leaf,
                &it.receipt_inclusion,
                &it.receipt.root,
            );
        if !(ir.commitment_ok && ir.inclusion_ok && ir.receipt_ok) {
            r.problems
                .push(format!("event #{} failed verification", e.id));
        }
        r.items.push(ir);
    }
    r.ok = r.problems.is_empty();
    r
}

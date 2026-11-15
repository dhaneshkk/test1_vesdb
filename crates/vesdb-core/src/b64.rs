//! Serde helpers: binary fields travel as standard base64 (hashes in hex where the wire format
//! of EventSourcingDB uses hex).

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::Error, Deserialize, Deserializer, Serializer};

pub fn encode(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}

/// `Vec<u8>` as base64.
pub mod bytes {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).map_err(D::Error::custom)
    }
}

/// `[u8; 32]` as base64.
pub mod hash {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = decode(&s).map_err(D::Error::custom)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// `Vec<[u8; 32]>` as a list of base64 strings (proof paths).
pub mod hashes {
    use super::*;
    use serde::ser::SerializeSeq;
    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for h in v {
            seq.serialize_element(&encode(h))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.iter()
            .map(|s| {
                let b = decode(s).map_err(D::Error::custom)?;
                b.try_into()
                    .map_err(|_| D::Error::custom("expected 32 bytes"))
            })
            .collect()
    }
}

/// `[u8; 32]` as lowercase hex.
pub mod hex32 {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// `Option<[u8; 32]>` as base64.
pub mod opt_hash {
    use super::*;
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(h) => s.serialize_some(&encode(h)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(None),
            Some(s) => {
                let v = decode(&s).map_err(D::Error::custom)?;
                Ok(Some(
                    v.try_into()
                        .map_err(|_| D::Error::custom("expected 32 bytes"))?,
                ))
            }
        }
    }
}

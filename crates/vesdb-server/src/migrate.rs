//! `vesdb migrate --from <dir> --to <url>`.

use vesdb_core::crypto::HybridKey;
use vesdb_store::{bucket, ObjectBackend, Store, StoreConfig};

pub fn migrate(
    from: &std::path::Path,
    to: &str,
    key_file: &std::path::Path,
) -> Result<String, String> {
    let load = || HybridKey::load(key_file).map_err(|e| format!("signing key: {e}"));
    let origin = load()?.name().to_string();
    let host = origin.split('/').next().unwrap_or(&origin).to_string();
    let cfg = |k: HybridKey| StoreConfig {
        dir: from.to_path_buf(),
        origin: origin.clone(),
        system_source: format!("https://{host}"),
        pii_types: Default::default(),
        key: k,
    };
    let source = Store::open(cfg(load()?)).map_err(|e| format!("source: {e}"))?;
    let mut dest = ObjectBackend::from_url(to).map_err(|e| e.to_string())?;
    bucket::migrate(&source, &mut dest, cfg(load()?)).map_err(|e| e.to_string())
}

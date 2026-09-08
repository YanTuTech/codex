//! Persistent ownership records for installation-scoped WFP objects.
//!
//! Every WFP provider, sublayer, and filter key allocated for one sandbox
//! installation is recorded in `<codex-home>/.sandbox/wfp_ownership.json`.
//! The record is the single source of truth for uninstall: only the exact
//! GUIDs listed here are ever deleted, and a missing record means there is
//! nothing this installation owns to remove.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;
use serde::Serialize;

use crate::installation::SandboxInstallationIdentity;
use crate::installation::random_wfp_guid;

pub const WFP_OWNERSHIP_FILE_NAME: &str = "wfp_ownership.json";
pub const WFP_OWNERSHIP_VERSION: u32 = 1;

/// Keys are raw u128 values serialized as 32-character lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WfpOwnershipRecord {
    pub version: u32,
    pub install_id: String,
    pub provider_key: String,
    pub sublayer_key: String,
    /// Filter keys keyed by the static filter spec name they belong to.
    pub filter_keys: BTreeMap<String, String>,
}

pub fn wfp_ownership_path(codex_home: &Path) -> PathBuf {
    crate::setup::sandbox_dir(codex_home).join(WFP_OWNERSHIP_FILE_NAME)
}

fn key_to_hex(key: u128) -> String {
    format!("{key:032x}")
}

fn key_from_hex(hex: &str) -> Result<u128> {
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("WFP ownership record contains an invalid key");
    }
    u128::from_str_radix(hex, 16).context("parse WFP ownership key")
}

/// Loads the ownership record when it exists, matches `identity`, and is the
/// current format version.
/// Reads any on-disk ownership record regardless of owner, for fail-closed
/// collision detection.
fn read_any_ownership_record(codex_home: &Path) -> Result<Option<WfpOwnershipRecord>> {
    let path = wfp_ownership_path(codex_home);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow::Error::msg(format!(
                "read {}: {err}",
                path.display()
            )));
        }
    };
    let record: WfpOwnershipRecord =
        serde_json::from_str(&contents).with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(record))
}

pub fn load_wfp_ownership(
    codex_home: &Path,
    identity: &SandboxInstallationIdentity,
) -> Result<Option<WfpOwnershipRecord>> {
    let path = wfp_ownership_path(codex_home);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow::Error::msg(format!(
                "read {}: {err}",
                path.display()
            )));
        }
    };
    let record: WfpOwnershipRecord =
        serde_json::from_str(&contents).with_context(|| format!("parse {}", path.display()))?;
    if record.version != WFP_OWNERSHIP_VERSION || record.install_id != identity.install_id_hex() {
        // A record from a different installation or format is not ours to use.
        return Ok(None);
    }
    Ok(Some(record))
}

/// Loads an existing record for `identity` or allocates a fresh one covering
/// every filter spec name, persisting it before returning. The record is
/// written before any WFP object is created so a partially failed setup
/// still leaves a precise cleanup manifest.
pub fn load_or_allocate_wfp_ownership(
    codex_home: &Path,
    identity: &SandboxInstallationIdentity,
    filter_spec_names: &[&str],
) -> Result<WfpOwnershipRecord> {
    // Detect ANY pre-existing record first: a record owned by a different
    // installation identity, or one that is incomplete, must fail closed.
    // Overwriting it would orphan the WFP objects the old record named —
    // they would survive forever with no cleanup manifest.
    let existing = read_any_ownership_record(codex_home)?;
    if let Some(record) = existing {
        if record.install_id != identity.install_id_hex() {
            bail!(
                "WFP ownership record belongs to installation {}; refusing to                  overwrite it for installation {} — uninstall the existing                  installation first so its WFP objects are removed while the                  record still names them",
                record.install_id,
                identity.install_id_hex()
            );
        }
        let complete = filter_spec_names
            .iter()
            .all(|name| record.filter_keys.contains_key(*name));
        if complete {
            return Ok(record);
        }
        bail!(
            "WFP ownership record for this installation is incomplete;              refusing to roll a new allocation — run uninstall to reconcile              while the existing keys are still named"
        );
    }
    let mut filter_keys = BTreeMap::new();
    for name in filter_spec_names {
        filter_keys.insert((*name).to_string(), key_to_hex(random_wfp_guid()));
    }
    let record = WfpOwnershipRecord {
        version: WFP_OWNERSHIP_VERSION,
        install_id: identity.install_id_hex(),
        provider_key: key_to_hex(random_wfp_guid()),
        sublayer_key: key_to_hex(random_wfp_guid()),
        filter_keys,
    };
    write_wfp_ownership(codex_home, &record)?;
    Ok(record)
}

pub fn write_wfp_ownership(codex_home: &Path, record: &WfpOwnershipRecord) -> Result<()> {
    let path = wfp_ownership_path(codex_home);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(record).context("serialize WFP ownership record")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

impl WfpOwnershipRecord {
    pub fn provider_key_u128(&self) -> Result<u128> {
        key_from_hex(&self.provider_key)
    }

    pub fn sublayer_key_u128(&self) -> Result<u128> {
        key_from_hex(&self.sublayer_key)
    }

    pub fn filter_key_u128(&self, spec_name: &str) -> Result<u128> {
        let hex = self
            .filter_keys
            .get(spec_name)
            .ok_or_else(|| anyhow::anyhow!("filter key missing for spec {spec_name}"))?;
        key_from_hex(hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_is_stable_and_installation_scoped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = SandboxInstallationIdentity::generate();
        let specs = ["filter_a", "filter_b"];
        let first =
            load_or_allocate_wfp_ownership(dir.path(), &identity, &specs).expect("allocate");
        let second = load_or_allocate_wfp_ownership(dir.path(), &identity, &specs).expect("reload");
        assert_eq!(first, second, "an existing complete record is reused");

        let other = SandboxInstallationIdentity::generate();
        // The on-disk record belongs to `identity`, so loading it as `other`
        // must yield nothing: another installation never reads our keys.
        assert!(
            load_wfp_ownership(dir.path(), &other)
                .expect("load for other identity")
                .is_none(),
            "a record owned by another installation must not be loaded"
        );
        // A different installation must FAIL CLOSED instead of overwriting:
        // overwriting would orphan the first installation's WFP objects.
        let collision = load_or_allocate_wfp_ownership(dir.path(), &other, &specs);
        assert!(
            collision.is_err(),
            "an ownership collision must fail closed, never overwrite"
        );
        // The on-disk record still belongs to the original installation.
        let on_disk = load_wfp_ownership(dir.path(), &identity)
            .expect("reload")
            .expect("record exists");
        assert_eq!(on_disk.install_id, identity.install_id_hex());
        assert_eq!(on_disk.provider_key, first.provider_key);
    }

    #[test]
    fn derived_keys_never_equal_the_codex_global_keys() {
        const CODEX_PROVIDER: u128 = 0x2e31d31c_3948_4753_9117_e5d1a6496f41;
        const CODEX_SUBLAYER: u128 = 0xe65054fd_4d32_4c7c_95ef_621f0cf6431a;
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = SandboxInstallationIdentity::generate();
        let record =
            load_or_allocate_wfp_ownership(dir.path(), &identity, &["f1"]).expect("allocate");
        assert_ne!(record.provider_key_u128().expect("key"), CODEX_PROVIDER);
        assert_ne!(record.sublayer_key_u128().expect("key"), CODEX_SUBLAYER);
    }

    #[test]
    fn hex_keys_round_trip_and_reject_hostile_shapes() {
        let value = 0x0123456789abcdef0123456789abcdefu128;
        assert_eq!(key_from_hex(&key_to_hex(value)).expect("round trip"), value);
        assert!(key_from_hex("xyz").is_err());
        assert!(key_from_hex(&"a".repeat(31)).is_err());
        assert!(key_from_hex(&"A".repeat(32)).is_err());
    }
}

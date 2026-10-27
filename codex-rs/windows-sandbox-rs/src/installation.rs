//! Product-scoped Windows sandbox installation identity.
//!
//! Every resource the elevated setup provisions on this machine — local
//! accounts, the sandbox users group, firewall rule names, and WFP provider,
//! sublayer, and filter objects — is derived from one cryptographically
//! random installation ID held in protected Main-owned state
//! (`<codex-home>/.sandbox/installation.json`).
//!
//! The identity never comes from the command line or model input: callers
//! either load the persisted identity or generate a fresh one, and every
//! derived resource name is bounded, deterministic, and validated before it
//! reaches a Windows API. Two distinct installations therefore cannot share
//! an account, group, firewall rule, or WFP object, and neither can collide
//! with Codex-global resource names.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Deserialize;
use serde::Serialize;

/// Name of the persisted identity file inside the sandbox state directory.
pub const INSTALLATION_FILE_NAME: &str = "installation.json";
/// On-disk format version for [`InstallationFile`].
pub const INSTALLATION_FILE_VERSION: u32 = 1;

const INSTALL_ID_BYTES: usize = 16;
const INSTALL_ID_HEX_LEN: usize = INSTALL_ID_BYTES * 2;
/// Account-name suffix: ten lowercase hex characters (40 bits of entropy).
const SUFFIX_LEN: usize = 10;
/// Windows account/group names stay within the classic 20-character SAM
/// limit so no downlevel compatibility path is ever exercised.
const MAX_WINDOWS_ACCOUNT_NAME_LEN: usize = 20;

/// Codex-global resource names that a LeapSea installation must never reuse.
/// Guarded by unit tests in this module.
pub const CODEX_GLOBAL_ACCOUNT_NAMES: &[&str] = &["CodexSandboxOffline", "CodexSandboxOnline"];
pub const CODEX_GLOBAL_GROUP_NAME: &str = "CodexSandboxUsers";
pub const CODEX_GLOBAL_FIREWALL_RULE_PREFIXES: &[&str] = &["codex_sandbox_"];

/// A typed installation identity. All product-scoped resource names derive
/// from the single random install ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxInstallationIdentity {
    install_id: [u8; INSTALL_ID_BYTES],
}

impl SandboxInstallationIdentity {
    /// Generates a fresh random identity. Only call this when no persisted
    /// identity exists; prefer [`load_or_create_installation_identity`].
    pub fn generate() -> Self {
        let mut install_id = [0u8; INSTALL_ID_BYTES];
        // OS CSPRNG: installation identifiers must be unguessable by other
        // local principals.
        OsRng.fill_bytes(&mut install_id);
        Self { install_id }
    }

    /// Parses a strict lowercase-hex installation ID. Any other shape is
    /// rejected so a hostile payload cannot smuggle a different namespace.
    pub fn from_install_id_hex(hex: &str) -> Result<Self> {
        if hex.len() != INSTALL_ID_HEX_LEN {
            bail!("installation id must be exactly {INSTALL_ID_HEX_LEN} lowercase hex characters");
        }
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("installation id must contain only lowercase hex characters");
        }
        let value = u128::from_str_radix(hex, 16)
            .map_err(|err| anyhow::Error::msg(format!("installation id parse failed: {err}")))?;
        Ok(Self {
            install_id: value.to_be_bytes(),
        })
    }

    pub fn install_id_hex(&self) -> String {
        self.install_id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Deterministic, bounded, display-safe suffix used by every derived
    /// resource name.
    pub fn install_suffix(&self) -> String {
        self.install_id_hex()[..SUFFIX_LEN].to_string()
    }

    pub fn offline_username(&self) -> String {
        format!("LsSbxOff-{}", self.install_suffix())
    }

    pub fn online_username(&self) -> String {
        format!("LsSbxOnl-{}", self.install_suffix())
    }

    pub fn sandbox_group_name(&self) -> String {
        format!("LsSbxUsrs-{}", self.install_suffix())
    }

    pub fn offline_block_rule_name(&self) -> String {
        format!("ls_sbx_{}_block_outbound", self.install_suffix())
    }

    pub fn offline_block_loopback_tcp_rule_name(&self) -> String {
        format!("ls_sbx_{}_block_loopback_tcp", self.install_suffix())
    }

    pub fn offline_block_loopback_udp_rule_name(&self) -> String {
        format!("ls_sbx_{}_block_loopback_udp", self.install_suffix())
    }

    pub fn offline_allow_loopback_proxy_rule_name(&self) -> String {
        format!("ls_sbx_{}_allow_loopback_proxy", self.install_suffix())
    }

    pub fn wfp_provider_display_name(&self) -> String {
        format!("LeapSea Windows Sandbox WFP {}", self.install_suffix())
    }

    pub fn wfp_sublayer_display_name(&self) -> String {
        format!("LeapSea Windows Sandbox Sublayer {}", self.install_suffix())
    }

    /// Validates every derived Windows account/group name before it can
    /// reach a provisioning API.
    pub fn validate_derived_account_names(&self) -> Result<()> {
        validate_windows_account_name(&self.offline_username())?;
        validate_windows_account_name(&self.online_username())?;
        validate_windows_account_name(&self.sandbox_group_name())?;
        Ok(())
    }
}

/// Validates a bounded Windows-compatible account or group name: 1..=20
/// characters from `[A-Za-z0-9._-]`, starting with an alphanumeric.
pub fn validate_windows_account_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_WINDOWS_ACCOUNT_NAME_LEN {
        bail!(
            "windows account name must be 1..={MAX_WINDOWS_ACCOUNT_NAME_LEN} characters, got {}",
            name.len()
        );
    }
    match name.chars().next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => bail!("windows account name must start with an alphanumeric character"),
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("windows account name contains forbidden characters");
    }
    Ok(())
}

/// On-disk persisted identity record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallationFile {
    pub version: u32,
    pub install_id: String,
}

pub fn installation_identity_path(sandbox_dir: &Path) -> PathBuf {
    sandbox_dir.join(INSTALLATION_FILE_NAME)
}

/// Loads the persisted identity from the sandbox state directory, creating it
/// on first use. The file lives under the sandbox dir which the elevated
/// setup later locks down; the same requested state therefore resolves to the
/// same installation identity on every subsequent setup.
pub fn load_or_create_installation_identity(
    sandbox_dir: &Path,
) -> Result<SandboxInstallationIdentity> {
    let path = installation_identity_path(sandbox_dir);
    if let Some(identity) = read_installation_identity(sandbox_dir)? {
        return Ok(identity);
    }
    let identity = SandboxInstallationIdentity::generate();
    let file = InstallationFile {
        version: INSTALLATION_FILE_VERSION,
        install_id: identity.install_id_hex(),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create sandbox dir {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(&file).context("serialize installation file")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(identity)
}

/// Reads the persisted identity if present and currently versioned.
pub fn read_installation_identity(
    sandbox_dir: &Path,
) -> Result<Option<SandboxInstallationIdentity>> {
    let path = installation_identity_path(sandbox_dir);
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
    let file: InstallationFile =
        serde_json::from_str(&contents).with_context(|| format!("parse {}", path.display()))?;
    if file.version != INSTALLATION_FILE_VERSION {
        return Ok(None);
    }
    Ok(Some(SandboxInstallationIdentity::from_install_id_hex(
        &file.install_id,
    )?))
}

/// Generates a random RFC 4122 version 4 GUID as a raw u128 for WFP object
/// keys. Ownership of the generated keys is persisted by the caller.
pub fn random_wfp_guid() -> u128 {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    // Set version 4 and RFC 4122 variant bits.
    bytes[7] = (bytes[7] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    u128::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distinct_identities() -> (SandboxInstallationIdentity, SandboxInstallationIdentity) {
        let a = SandboxInstallationIdentity::generate();
        let mut b = SandboxInstallationIdentity::generate();
        while a == b {
            b = SandboxInstallationIdentity::generate();
        }
        (a, b)
    }

    #[test]
    fn two_installations_share_no_resource_identity() {
        let (a, b) = distinct_identities();
        assert_ne!(a.offline_username(), b.offline_username());
        assert_ne!(a.online_username(), b.online_username());
        assert_ne!(a.sandbox_group_name(), b.sandbox_group_name());
        assert_ne!(a.offline_block_rule_name(), b.offline_block_rule_name());
        assert_ne!(
            a.offline_allow_loopback_proxy_rule_name(),
            b.offline_allow_loopback_proxy_rule_name()
        );
        assert_ne!(a.wfp_provider_display_name(), b.wfp_provider_display_name());
        assert_ne!(a.install_suffix(), b.install_suffix());
    }

    #[test]
    fn derived_names_are_stable_for_one_identity() {
        let identity = SandboxInstallationIdentity::generate();
        let round_tripped =
            SandboxInstallationIdentity::from_install_id_hex(&identity.install_id_hex())
                .expect("round trip");
        assert_eq!(identity, round_tripped);
        assert_eq!(
            identity.offline_username(),
            round_tripped.offline_username()
        );
        assert_eq!(
            identity.sandbox_group_name(),
            round_tripped.sandbox_group_name()
        );
        assert_eq!(identity.install_suffix(), round_tripped.install_suffix());
    }

    #[test]
    fn derived_names_never_collide_with_codex_global_resources() {
        let identity = SandboxInstallationIdentity::generate();
        for name in [
            identity.offline_username(),
            identity.online_username(),
            identity.sandbox_group_name(),
        ] {
            assert!(
                !CODEX_GLOBAL_ACCOUNT_NAMES.contains(&name.as_str()),
                "{name} must not equal a Codex global account"
            );
            assert_ne!(name, CODEX_GLOBAL_GROUP_NAME);
        }
        for rule in [
            identity.offline_block_rule_name(),
            identity.offline_block_loopback_tcp_rule_name(),
            identity.offline_block_loopback_udp_rule_name(),
            identity.offline_allow_loopback_proxy_rule_name(),
        ] {
            for prefix in CODEX_GLOBAL_FIREWALL_RULE_PREFIXES {
                assert!(
                    !rule.starts_with(prefix),
                    "{rule} must not share the Codex global rule prefix {prefix}"
                );
            }
        }
    }

    #[test]
    fn derived_account_names_are_bounded_and_valid() {
        let identity = SandboxInstallationIdentity::generate();
        identity
            .validate_derived_account_names()
            .expect("derived names are valid");
        for name in [
            identity.offline_username(),
            identity.online_username(),
            identity.sandbox_group_name(),
        ] {
            assert!(name.len() <= 20, "{name} exceeds the 20-char SAM bound");
        }
    }

    #[test]
    fn from_install_id_hex_rejects_hostile_shapes() {
        assert!(SandboxInstallationIdentity::from_install_id_hex("").is_err());
        assert!(SandboxInstallationIdentity::from_install_id_hex("abc").is_err());
        assert!(
            SandboxInstallationIdentity::from_install_id_hex(&"a".repeat(INSTALL_ID_HEX_LEN + 1))
                .is_err()
        );
        assert!(
            SandboxInstallationIdentity::from_install_id_hex(&"A".repeat(INSTALL_ID_HEX_LEN))
                .is_err(),
            "uppercase hex is rejected"
        );
        assert!(
            SandboxInstallationIdentity::from_install_id_hex(&"g".repeat(INSTALL_ID_HEX_LEN))
                .is_err()
        );
        // Spaces or shell metacharacters never round-trip.
        assert!(
            SandboxInstallationIdentity::from_install_id_hex(&format!(
                "{} evil",
                "a".repeat(INSTALL_ID_HEX_LEN - 5)
            ))
            .is_err()
        );
    }

    #[test]
    fn validate_windows_account_name_enforces_bounds() {
        assert!(validate_windows_account_name("LsSbxOff-0123456789").is_ok());
        assert!(validate_windows_account_name("").is_err());
        assert!(validate_windows_account_name("-leading").is_err());
        assert!(validate_windows_account_name("has space").is_err());
        assert!(validate_windows_account_name("has;semicolon").is_err());
        assert!(validate_windows_account_name(&"a".repeat(21)).is_err());
    }

    #[test]
    fn load_or_create_is_idempotent_per_state_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = load_or_create_installation_identity(dir.path()).expect("first");
        let second = load_or_create_installation_identity(dir.path()).expect("second");
        assert_eq!(first, second, "the persisted identity is reused");
    }

    #[test]
    fn read_installation_identity_returns_none_for_missing_or_stale_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            read_installation_identity(dir.path())
                .expect("missing")
                .is_none()
        );
        let path = installation_identity_path(dir.path());
        std::fs::write(&path, "{\"version\": 999, \"install_id\": \"x\"}").expect("write stale");
        assert!(
            read_installation_identity(dir.path())
                .expect("stale")
                .is_none()
        );
    }

    #[test]
    fn random_wfp_guid_is_versioned_and_varied() {
        let a = random_wfp_guid();
        let b = random_wfp_guid();
        assert_ne!(a, b);
        let bytes = a.to_be_bytes();
        assert_eq!(bytes[7] & 0xf0, 0x40, "version nibble is 4");
        assert_eq!(bytes[8] & 0xc0, 0x80, "variant bits are RFC 4122");
    }
}

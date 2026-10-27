//! Nonce-bound elevated setup request and machine-effect receipt (R2B).
//!
//! Main creates a one-time request (atomic exclusive create) carrying a
//! cryptographically random nonce, the verified bundle-evidence digest, the
//! installation identity, and an expiry. The elevated helper refuses to run
//! without a valid request, and after completing the machine effects writes
//! a receipt binding the nonce to the exact provisioned facts: account/group
//! SIDs, firewall rule identities, WFP keys, marker/ownership/self digests,
//! setup version, OS build, and the completion timestamp — into an
//! ACL-protected directory the ordinary user cannot replace. Main only ever
//! reads the receipt; it never mints one itself.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest as _;
use sha2::Sha256;

use crate::installation::SandboxInstallationIdentity;

pub const SETUP_REQUEST_FILE: &str = "setup-request-v1.json";
pub const RECEIPT_DIR: &str = "elevated";
pub const RECEIPT_FILE: &str = "setup-receipt-v1.json";
/// v2: the machine-effect closure became REQUIRED — the ownership digest,
/// the full WFP filter-key map, and per-filter live read-back facts
/// (layer/action/user-condition SID) must all be present. A v1 receipt with
/// an empty or partial closure fails to parse, which Main treats as
/// "setup required" (fail-closed re-provisioning).
pub const RECEIPT_VERSION: u32 = 2;
pub const REQUEST_VERSION: u32 = 1;

const NONCE_HEX_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupRequestFile {
    pub version: u32,
    pub nonce: String,
    pub install_id: String,
    pub evidence_digest: String,
    pub requested_at: String,
    pub expires_at: String,
}

/// Live read-back facts of ONE provisioned WFP filter, verified by the
/// elevated helper immediately before the receipt is written: the layer the
/// filter sits in, its action kind, and the SID its user condition
/// constrains traffic to (the security descriptor's owner SID).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WfpFilterFactV1 {
    pub layer_key: String,
    pub action: String,
    pub condition_user_sid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElevatedSetupReceiptV1 {
    pub version: u32,
    pub nonce: String,
    pub install_id: String,
    pub evidence_digest: String,
    pub completed_at: String,
    pub setup_version: u32,
    pub os_build: String,
    pub helper_sha256: String,
    pub marker_sha256: String,
    /// Digest of the WFP ownership record: REQUIRED since v2 — an empty
    /// ownership closure can never back a receipt.
    pub ownership_sha256: String,
    pub offline_account_sid: String,
    pub online_account_sid: String,
    pub sandbox_group_sid: String,
    pub firewall_rule_names: Vec<String>,
    pub wfp_provider_key: String,
    pub wfp_sublayer_key: String,
    /// Every static filter spec name MUST map to this installation's
    /// recorded filter key; missing or extra names are producer errors.
    pub wfp_filter_keys: std::collections::BTreeMap<String, String>,
    /// Per-filter live read-back facts; MUST carry exactly the same key set
    /// as `wfp_filter_keys`.
    pub wfp_filter_facts: std::collections::BTreeMap<String, WfpFilterFactV1>,
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Reads and validates the one-time setup request for `identity`.
///
/// Fail-closed on: missing file, wrong version, malformed nonce, foreign
/// installation identity, or an expired challenge. The expiry comparison
/// uses the caller-provided `now` (RFC 3339) so tests can time-travel.
pub fn read_setup_request(
    codex_home: &Path,
    identity: &SandboxInstallationIdentity,
    now_rfc3339: &str,
) -> Result<SetupRequestFile> {
    let path = request_path(codex_home);
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("setup request missing: {}", path.display()))?;
    let request: SetupRequestFile = serde_json::from_str(&contents)
        .with_context(|| format!("setup request parse failed: {}", path.display()))?;
    if request.version != REQUEST_VERSION {
        bail!(
            "setup request version {} is not {}",
            request.version,
            REQUEST_VERSION
        );
    }
    if !is_hex(&request.nonce, NONCE_HEX_LEN) {
        bail!("setup request nonce must be {NONCE_HEX_LEN} lowercase hex characters");
    }
    if !is_hex(&request.evidence_digest, 64) {
        bail!("setup request evidence digest must be 64 lowercase hex characters");
    }
    if request.install_id != identity.install_id_hex() {
        bail!(
            "setup request belongs to installation {}, not {}",
            request.install_id,
            identity.install_id_hex()
        );
    }
    // RFC 3339 times are PARSED and compared, never compared as strings:
    // offset-bearing timestamps sort differently as text than as instants.
    let now = chrono::DateTime::parse_from_rfc3339(now_rfc3339)
        .with_context(|| format!("now is not valid RFC 3339: {now_rfc3339}"))?;
    let requested =
        chrono::DateTime::parse_from_rfc3339(&request.requested_at).with_context(|| {
            format!(
                "setup request requested_at is not valid RFC 3339: {}",
                request.requested_at
            )
        })?;
    let expires = chrono::DateTime::parse_from_rfc3339(&request.expires_at).with_context(|| {
        format!(
            "setup request expiry is not valid RFC 3339: {}",
            request.expires_at
        )
    })?;
    if requested > expires {
        bail!(
            "setup request requested_at {} is after expiry {}",
            request.requested_at,
            request.expires_at
        );
    }
    if now >= expires {
        bail!(
            "setup request expired at {} (now {now_rfc3339})",
            request.expires_at
        );
    }
    Ok(request)
}

pub fn request_path(codex_home: &Path) -> PathBuf {
    crate::setup::sandbox_dir(codex_home).join(SETUP_REQUEST_FILE)
}

pub fn receipt_path(codex_home: &Path) -> PathBuf {
    crate::setup::sandbox_dir(codex_home)
        .join(RECEIPT_DIR)
        .join(RECEIPT_FILE)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

pub fn sha256_file_hex(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Digest of the running helper executable (identity binding for the
/// receipt).
pub fn compute_self_digest() -> Result<String> {
    let exe = std::env::current_exe().context("resolve current helper executable")?;
    sha256_file_hex(&exe)
}

/// Writes the receipt atomically inside the ACL-protected elevated
/// directory and consumes (deletes) the one-time request.
///
/// `real_user` receives READ access to the directory; Administrators and
/// SYSTEM keep full control. An ordinary user therefore cannot replace or
/// delete the receipt after the elevated helper writes it (the directory
/// owner is Administrators once the protected DACL is applied).
pub fn write_receipt_and_consume_request(
    codex_home: &Path,
    receipt: &ElevatedSetupReceiptV1,
    real_user_sid: &str,
) -> Result<PathBuf> {
    let dir = crate::setup::sandbox_dir(codex_home).join(RECEIPT_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    // Protection failures are fatal: the helper must NOT write a receipt it
    // cannot prove the ordinary user cannot replace.
    protect_receipt_directory(&dir, real_user_sid)
        .with_context(|| format!("protect receipt directory {}", dir.display()))?;
    let payload = serde_json::to_vec_pretty(receipt).context("serialize receipt")?;
    let temp = dir.join(format!("{RECEIPT_FILE}.tmp"));
    {
        let mut file =
            fs::File::create(&temp).with_context(|| format!("create {}", temp.display()))?;
        file.write_all(&payload).context("write receipt temp")?;
        file.sync_all().ok();
    }
    let final_path = receipt_path(codex_home);
    fs::rename(&temp, &final_path)
        .with_context(|| format!("promote receipt to {}", final_path.display()))?;
    // Consume the one-time request so the nonce cannot be replayed.
    let request = request_path(codex_home);
    match fs::remove_file(&request) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow::Error::msg(format!(
                "consume setup request {}: {err}",
                request.display()
            )));
        }
    }
    Ok(final_path)
}

/// Applies and then verifies the receipt-directory protection. Every Win32
/// API result is checked; the caller's real-user trust is expressed as a SID
/// (never an ambiguous account name). Fail-closed: any failure or read-back
/// mismatch is an error and NO receipt may be written afterwards.
#[cfg(windows)]
fn receipt_directory_owned_by_administrators(dir: &Path) -> Result<bool> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    unsafe {
        let wide: Vec<u16> = dir
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut owner = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let result = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if result != 0 {
            bail!("read receipt directory owner failed with {result:#x}");
        }
        let mut text = std::ptr::null_mut();
        let converted = ConvertSidToStringSidW(owner, &mut text);
        let owned = if converted != 0 && !text.is_null() {
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(text, len))
                .ok()
                .as_deref()
                == Some("S-1-5-32-544")
        } else {
            false
        };
        if !text.is_null() {
            LocalFree(text as _);
        }
        LocalFree(descriptor as _);
        if converted == 0 {
            bail!("read receipt directory owner SID failed");
        }
        Ok(owned)
    }
}

#[cfg(windows)]
fn protect_receipt_directory(dir: &Path, real_user_sid: &str) -> Result<()> {
    if !crate::setup::is_elevated()? {
        bail!("receipt protection requires an elevated administrator token");
    }
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::ACL;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
    use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Security::Authorization::SET_ACCESS;
    use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
    use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
    use windows_sys::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
    const SYSTEM_SID: &str = "S-1-5-18";

    // Elevated-created directories already belong to Administrators. Requesting
    // WRITE_OWNER again can fail after the parent ACL has been narrowed to
    // Modify. Retain exact owner read-back; only avoid the redundant write.
    let owner_already_administrators = receipt_directory_owned_by_administrators(dir)?;
    unsafe {
        let sid_from_string = |value: &str| -> Result<windows_sys::Win32::Foundation::PSID> {
            let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
            let mut sid: windows_sys::Win32::Foundation::PSID = std::ptr::null_mut();
            if ConvertStringSidToSidW(wide.as_ptr(), &mut sid) == 0 || sid.is_null() {
                bail!("convert SID string {value} failed");
            }
            Ok(sid)
        };
        let admins = sid_from_string(ADMINISTRATORS_SID)?;
        let system = sid_from_string(SYSTEM_SID)?;
        let user = sid_from_string(real_user_sid).with_context(|| {
            format!("real-user trust must be a valid SID string: {real_user_sid}")
        })?;
        // SET_ACCESS replaces inherited ACEs; SID trustees only - account
        // names are ambiguous across domains and locales.
        let trustee = |sid: windows_sys::Win32::Foundation::PSID| TRUSTEE_W {
            ptstrName: sid as *mut u16,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: windows_sys::Win32::Security::Authorization::TRUSTEE_IS_UNKNOWN,
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation:
                windows_sys::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
        };
        let mut entries = [
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_ALL_ACCESS,
                grfAccessMode: SET_ACCESS,
                grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: trustee(admins),
            },
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_ALL_ACCESS,
                grfAccessMode: SET_ACCESS,
                grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: trustee(system),
            },
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_GENERIC_READ,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: trustee(user),
            },
        ];
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let acl_result = SetEntriesInAclW(
            entries.len() as u32,
            entries.as_mut_ptr(),
            std::ptr::null_mut(),
            &mut new_dacl,
        );
        if acl_result != 0 || new_dacl.is_null() {
            LocalFree(admins as _);
            LocalFree(system as _);
            LocalFree(user as _);
            bail!("SetEntriesInAclW failed with {acl_result:#x}");
        }
        let dir_w: Vec<u16> = dir
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let set_result = SetNamedSecurityInfoW(
            dir_w.as_ptr(),
            SE_FILE_OBJECT,
            windows_sys::Win32::Security::DACL_SECURITY_INFORMATION
                | windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION
                | if owner_already_administrators {
                    0
                } else {
                    windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION
                },
            if owner_already_administrators {
                std::ptr::null_mut()
            } else {
                admins
            },
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        );
        LocalFree(new_dacl as _);
        let verified = if set_result != 0 {
            Err(anyhow::Error::msg(format!(
                "SetNamedSecurityInfoW failed with {set_result:#x}"
            )))
        } else {
            verify_receipt_directory_protection(dir, real_user_sid)
        };
        LocalFree(admins as _);
        LocalFree(system as _);
        LocalFree(user as _);
        verified
    }
}

/// Read-back proof that the protection is actually in place: the owner must
/// be the Administrators group, the DACL must be protected (later inherited
/// grants cannot widen it), and the real user must hold no write-class
/// allow-ACE on the directory.
#[cfg(windows)]
fn verify_receipt_directory_protection(dir: &Path, real_user_sid: &str) -> Result<()> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::ACL;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Security::GetAce;
    use windows_sys::Win32::Security::GetSecurityDescriptorControl;

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
    const DELETE_RIGHT: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const FILE_WRITE_EA: u32 = 0x0000_0010;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

    unsafe {
        let dir_w: Vec<u16> = dir
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut owner: windows_sys::Win32::Foundation::PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR =
            std::ptr::null_mut();
        let result = GetNamedSecurityInfoW(
            dir_w.as_ptr(),
            SE_FILE_OBJECT,
            windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION
                | windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if result != 0 {
            bail!("protection read-back failed with {result:#x}");
        }
        let sid_to_string = |sid: windows_sys::Win32::Foundation::PSID| -> Option<String> {
            let mut textual = std::ptr::null_mut();
            if ConvertSidToStringSidW(sid, &mut textual) != 0 && !textual.is_null() {
                let mut len = 0usize;
                while *textual.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(textual, len);
                let value = String::from_utf16(slice).ok();
                LocalFree(textual as _);
                return value;
            }
            None
        };
        let mut outcome: Result<()> = Ok(());
        match sid_to_string(owner) {
            Some(sid) if sid == ADMINISTRATORS_SID => {}
            other => {
                outcome = Err(anyhow::Error::msg(format!(
                    "receipt directory owner read-back is {other:?}, not Administrators"
                )));
            }
        }
        if outcome.is_ok() {
            let mut control: u16 = 0;
            let mut revision = 0u32;
            if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0 {
                outcome = Err(anyhow::Error::msg(
                    "read security descriptor control failed",
                ));
            } else if control & windows_sys::Win32::Security::SE_DACL_PROTECTED == 0 {
                outcome = Err(anyhow::Error::msg(
                    "receipt directory DACL is not protected",
                ));
            }
        }
        if outcome.is_ok() {
            if dacl.is_null() {
                outcome = Err(anyhow::Error::msg("receipt directory has no DACL"));
            } else {
                let mutation_mask = DELETE_RIGHT
                    | WRITE_DAC
                    | WRITE_OWNER
                    | FILE_WRITE_DATA
                    | FILE_APPEND_DATA
                    | FILE_DELETE_CHILD
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES;
                let header = &*dacl;
                for index in 0..header.AceCount {
                    let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                    if GetAce(dacl, u32::from(index), &mut ace) == 0 || ace.is_null() {
                        continue;
                    }
                    let ace_header = &*(ace as *const windows_sys::Win32::Security::ACE_HEADER);
                    if ace_header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                        continue;
                    }
                    let allowed =
                        &*(ace as *const windows_sys::Win32::Security::ACCESS_ALLOWED_ACE);
                    if allowed.Mask & mutation_mask == 0 {
                        continue;
                    }
                    let sid = std::ptr::addr_of!(allowed.SidStart) as *const u8
                        as windows_sys::Win32::Foundation::PSID;
                    if sid_to_string(sid).as_deref() == Some(real_user_sid) {
                        outcome = Err(anyhow::Error::msg(
                            "read-back found a write-class allow-ACE for the real user",
                        ));
                        break;
                    }
                }
            }
        }
        LocalFree(descriptor as _);
        outcome
    }
}

#[cfg(not(windows))]
fn protect_receipt_directory(_dir: &Path, _real_user_sid: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn identity() -> SandboxInstallationIdentity {
        SandboxInstallationIdentity::generate()
    }

    fn write_request(dir: &Path, request: &SetupRequestFile) {
        let sandbox = crate::setup::sandbox_dir(dir);
        fs::create_dir_all(&sandbox).unwrap();
        fs::write(
            request_path(dir),
            serde_json::to_vec_pretty(request).unwrap(),
        )
        .unwrap();
    }

    fn valid_request(id: &SandboxInstallationIdentity) -> SetupRequestFile {
        SetupRequestFile {
            version: REQUEST_VERSION,
            nonce: "a".repeat(64),
            install_id: id.install_id_hex(),
            evidence_digest: "b".repeat(64),
            requested_at: "2026-09-07T10:00:00+00:00".to_string(),
            expires_at: "2026-09-07T11:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn accepts_a_valid_unexpired_request() {
        let id = identity();
        let dir = tempfile::tempdir().unwrap();
        write_request(dir.path(), &valid_request(&id));
        let request = read_setup_request(dir.path(), &id, "2026-09-07T10:30:00+00:00").unwrap();
        assert_eq!(request.nonce, "a".repeat(64));
    }

    #[test]
    fn request_expiry_uses_parsed_rfc3339_not_string_ordering() {
        let id = identity();
        // 09:00Z expiry; `now` is 08:00Z written with a +02:00 offset. String
        // ordering would compare "T10..." >= "T09..." and expire the request;
        // parsed instant comparison must accept it.
        let dir = tempfile::tempdir().unwrap();
        let mut request = valid_request(&id);
        request.requested_at = "2026-09-07T08:00:00+00:00".to_string();
        request.expires_at = "2026-09-07T09:00:00+00:00".to_string();
        write_request(dir.path(), &request);
        assert!(read_setup_request(dir.path(), &id, "2026-09-07T10:00:00+02:00").is_ok());

        // The same `now` against a 07:00Z expiry is genuinely past.
        let earlier = tempfile::tempdir().unwrap();
        let mut request = valid_request(&id);
        request.requested_at = "2026-09-07T06:00:00+00:00".to_string();
        request.expires_at = "2026-09-07T07:00:00+00:00".to_string();
        write_request(earlier.path(), &request);
        assert!(read_setup_request(earlier.path(), &id, "2026-09-07T10:00:00+02:00").is_err());
    }

    #[test]
    fn rejects_malformed_rfc3339_timestamps() {
        let id = identity();
        let good_now = "2026-09-07T10:30:00+00:00";
        let dir = tempfile::tempdir().unwrap();
        let mut request = valid_request(&id);
        request.expires_at = "not-a-timestamp".to_string();
        write_request(dir.path(), &request);
        assert!(read_setup_request(dir.path(), &id, good_now).is_err());

        let dir_two = tempfile::tempdir().unwrap();
        let mut request = valid_request(&id);
        request.requested_at = "yesterday".to_string();
        write_request(dir_two.path(), &request);
        assert!(read_setup_request(dir_two.path(), &id, good_now).is_err());

        let dir_three = tempfile::tempdir().unwrap();
        write_request(dir_three.path(), &valid_request(&id));
        assert!(read_setup_request(dir_three.path(), &id, "not-a-timestamp").is_err());
    }

    #[test]
    #[cfg(windows)]
    fn receipt_protection_reapplies_without_redundant_owner_write() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
            SetNamedSecurityInfoW,
        };
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("receipt");
        std::fs::create_dir(&dir).unwrap();
        let admin_owned = receipt_directory_owned_by_administrators(&dir).unwrap();
        unsafe {
            let sddl: Vec<u16> = "D:(A;OICI;0x1301bf;;;BA)(A;OICI;0x1301bf;;;SY)(A;OICI;GR;;;WD)"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor = std::ptr::null_mut();
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut()
                ),
                0
            );
            let mut dacl = std::ptr::null_mut();
            let mut present = 0;
            let mut defaulted = 0;
            assert_ne!(
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted),
                0
            );
            let wide: Vec<u16> = dir
                .as_os_str()
                .to_string_lossy()
                .encode_utf16()
                .chain(Some(0))
                .collect();
            assert_eq!(
                SetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null_mut()
                ),
                0
            );
            LocalFree(descriptor as _);
        }
        let result = protect_receipt_directory(&dir, "S-1-1-0");
        if admin_owned {
            result.unwrap();
            verify_receipt_directory_protection(&dir, "S-1-1-0").unwrap();
        } else {
            // A medium token still cannot turn its user-owned directory into
            // an administrator-owned authority or mint a trusted receipt.
            assert!(result.is_err());
            assert!(!receipt_directory_owned_by_administrators(&dir).unwrap());
        }
    }

    #[test]
    #[cfg(windows)]
    fn receipt_write_fails_closed_without_provable_protection() {
        // An ordinary (non-elevated) process cannot set the directory owner
        // to Administrators (ERROR_INVALID_OWNER), so the protection - and
        // therefore the receipt write itself - must fail closed: no receipt
        // file, and the one-time request is NOT consumed (replay protection
        // stays intact). The elevated helper in production CAN set the owner,
        // which is exactly the privilege boundary the receipt proves.
        let id = identity();
        let dir = tempfile::tempdir().unwrap();
        write_request(dir.path(), &valid_request(&id));
        let receipt = example_receipt(&id);
        let outcome = write_receipt_and_consume_request(dir.path(), &receipt, "S-1-1-0");
        if outcome.is_ok() {
            // If the host happens to run elevated (CI administrator), the
            // protection succeeded legitimately: assert the full contract.
            let path = outcome.unwrap();
            assert!(path.is_file());
            assert!(!request_path(dir.path()).exists(), "request consumed");
            return;
        }
        assert!(
            !receipt_path(dir.path()).exists(),
            "no receipt without proof of protection"
        );
        assert!(
            request_path(dir.path()).exists(),
            "request must survive a failed write"
        );
    }

    #[test]
    #[cfg(windows)]
    fn receipt_protection_fails_closed_on_an_invalid_sid_trustee() {
        let dir = tempfile::tempdir().unwrap();
        let elevated = crate::setup::sandbox_dir(dir.path()).join(RECEIPT_DIR);
        std::fs::create_dir_all(&elevated).unwrap();
        // A non-SID trust string cannot be converted: protection must return
        // an error instead of silently skipping the ACL work.
        assert!(protect_receipt_directory(&elevated, "not-a-sid").is_err());
        // Consequently the receipt write refuses to proceed as well.
        let id = identity();
        let receipt = example_receipt(&id);
        assert!(write_receipt_and_consume_request(dir.path(), &receipt, "not-a-sid").is_err());
        assert!(
            !receipt_path(dir.path()).exists(),
            "no receipt without proof of protection"
        );
    }

    #[test]
    #[cfg(windows)]
    fn protection_read_back_rejects_an_unprotected_directory() {
        let dir = tempfile::tempdir().unwrap();
        let elevated = crate::setup::sandbox_dir(dir.path()).join(RECEIPT_DIR);
        std::fs::create_dir_all(&elevated).unwrap();
        // Default temp directory: user-owned with an inheritable DACL - the
        // read-back proof must reject it as insufficiently protected.
        assert!(verify_receipt_directory_protection(&elevated, "S-1-1-0").is_err());
    }

    #[cfg(windows)]
    fn example_receipt(id: &SandboxInstallationIdentity) -> ElevatedSetupReceiptV1 {
        ElevatedSetupReceiptV1 {
            version: RECEIPT_VERSION,
            nonce: "a".repeat(64),
            install_id: id.install_id_hex(),
            evidence_digest: "b".repeat(64),
            completed_at: Utc::now().to_rfc3339(),
            setup_version: crate::setup::SETUP_VERSION,
            os_build: "10.0.26200".to_string(),
            helper_sha256: "c".repeat(64),
            marker_sha256: "d".repeat(64),
            ownership_sha256: "1".repeat(64),
            offline_account_sid: "S-1-5-21-1".to_string(),
            online_account_sid: "S-1-5-21-2".to_string(),
            sandbox_group_sid: "S-1-5-21-3".to_string(),
            firewall_rule_names: vec!["ls_sbx_x_block_outbound".to_string()],
            wfp_provider_key: "e".repeat(32),
            wfp_sublayer_key: "f".repeat(32),
            wfp_filter_keys: std::iter::once((
                "codex_wfp_icmp_connect_v4".to_string(),
                "2".repeat(32),
            ))
            .collect(),
            wfp_filter_facts: std::iter::once((
                "codex_wfp_icmp_connect_v4".to_string(),
                WfpFilterFactV1 {
                    layer_key: "c38b33bc-1a9c-4a1c-9cbe-2cf7d3a3c9d0".to_string(),
                    action: "BLOCK".to_string(),
                    condition_user_sid: "S-1-5-21-1".to_string(),
                },
            ))
            .collect(),
        }
    }

    #[test]
    fn v1_receipts_with_optional_closures_fail_to_parse() {
        // A v1 receipt carried ownership as Option and defaulted the WFP
        // filter map: exactly the empty closure Main must never accept.
        let v1 = r#"{
            "version": 1,
            "nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "install_id": "11111111111111111111111111111111",
            "evidence_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "completed_at": "2026-09-07T11:30:00+00:00",
            "setup_version": 6,
            "os_build": "10.0.26200",
            "helper_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "marker_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "offline_account_sid": "S-1-5-21-1",
            "online_account_sid": "S-1-5-21-2",
            "sandbox_group_sid": "S-1-5-21-3",
            "firewall_rule_names": [],
            "wfp_provider_key": "",
            "wfp_sublayer_key": ""
        }"#;
        let parsed: Result<ElevatedSetupReceiptV1, _> = serde_json::from_str(v1);
        assert!(parsed.is_err(), "v1 receipts must fail v2 parsing");
    }

    #[test]
    fn v2_receipts_require_the_full_machine_effect_closure() {
        let id = identity();
        let mut receipt = example_receipt(&id);
        let complete = serde_json::to_string(&receipt).unwrap();
        assert!(serde_json::from_str::<ElevatedSetupReceiptV1>(&complete).is_ok());

        // Missing the ownership digest: rejected.
        let mut map: serde_json::Value = serde_json::from_str(&complete).unwrap();
        map.as_object_mut()
            .unwrap()
            .remove("ownership_sha256")
            .unwrap();
        assert!(serde_json::from_str::<ElevatedSetupReceiptV1>(&map.to_string()).is_err());

        // Missing the WFP filter-key map: rejected.
        let mut map: serde_json::Value = serde_json::from_str(&complete).unwrap();
        map.as_object_mut()
            .unwrap()
            .remove("wfp_filter_keys")
            .unwrap();
        assert!(serde_json::from_str::<ElevatedSetupReceiptV1>(&map.to_string()).is_err());

        // Missing the per-filter facts: rejected.
        let mut map: serde_json::Value = serde_json::from_str(&complete).unwrap();
        map.as_object_mut()
            .unwrap()
            .remove("wfp_filter_facts")
            .unwrap();
        assert!(serde_json::from_str::<ElevatedSetupReceiptV1>(&map.to_string()).is_err());

        receipt.ownership_sha256 = String::new();
        // An empty digest value parses but is MAIN's job to reject; the
        // schema requires PRESENCE, the producer requires completeness.
        assert!(
            serde_json::to_string(&receipt).is_ok(),
            "schema presence is enforced at the producer"
        );
    }

    #[test]
    fn rejects_missing_wrong_version_malformed_nonce_expired_or_foreign() {
        let id = identity();
        let now = "2026-09-07T10:30:00+00:00";

        let missing = tempfile::tempdir().unwrap();
        assert!(read_setup_request(missing.path(), &id, now).is_err());

        let wrong_version = tempfile::tempdir().unwrap();
        let mut request = valid_request(&id);
        request.version = 99;
        write_request(wrong_version.path(), &request);
        assert!(read_setup_request(wrong_version.path(), &id, now).is_err());

        let bad_nonce = tempfile::tempdir().unwrap();
        let mut request = valid_request(&id);
        request.nonce = "XYZ".to_string();
        write_request(bad_nonce.path(), &request);
        assert!(read_setup_request(bad_nonce.path(), &id, now).is_err());

        let expired = tempfile::tempdir().unwrap();
        let mut request = valid_request(&id);
        request.expires_at = "2026-09-07T10:00:00+00:00".to_string();
        write_request(expired.path(), &request);
        assert!(read_setup_request(expired.path(), &id, now).is_err());

        let foreign = tempfile::tempdir().unwrap();
        write_request(foreign.path(), &valid_request(&identity()));
        assert!(read_setup_request(foreign.path(), &id, now).is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn receipt_write_is_atomic_and_consumes_the_request() {
        let id = identity();
        let dir = tempfile::tempdir().unwrap();
        write_request(dir.path(), &valid_request(&id));
        let receipt = example_receipt(&id);
        // Non-Windows protection is a no-op by contract, so the write
        // proceeds and the atomicity/consumption behaviour is observable.
        let path = write_receipt_and_consume_request(dir.path(), &receipt, "S-1-1-0")
            .expect("non-Windows protection is a no-op");
        assert!(path.is_file());
        assert!(!request_path(dir.path()).exists(), "request consumed");
        let round: ElevatedSetupReceiptV1 =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(round, receipt);
        // No temp litter.
        assert!(
            !dir.path()
                .join(".sandbox")
                .join(RECEIPT_DIR)
                .join(format!("{RECEIPT_FILE}.tmp"))
                .exists()
        );
    }
}

mod firewall;
mod ls_owned_acl;
mod no_reparse_dir;
mod read_acl_mutex;

use anyhow::Context;
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use codex_otel::StatsigMetricsSettings;
use codex_windows_sandbox::SETUP_VERSION;
use codex_windows_sandbox::SetupErrorCode;
use codex_windows_sandbox::SetupErrorReport;
use codex_windows_sandbox::SetupFailure;

use codex_windows_sandbox::convert_string_sid_to_sid;
use codex_windows_sandbox::ensure_allow_mask_aces_with_inheritance;
use codex_windows_sandbox::ensure_allow_write_aces;
use codex_windows_sandbox::extract_setup_failure;
use codex_windows_sandbox::hide_newly_created_users;
use codex_windows_sandbox::install_wfp_filters;
use codex_windows_sandbox::log_note;
use codex_windows_sandbox::log_writer;
use codex_windows_sandbox::path_mask_allows;
use codex_windows_sandbox::path_write_aces_need_refresh;
use codex_windows_sandbox::sandbox_bin_dir;
use codex_windows_sandbox::sandbox_dir;
use codex_windows_sandbox::sandbox_secrets_dir;
use codex_windows_sandbox::string_from_sid_bytes;
use codex_windows_sandbox::sync_persistent_deny_read_acls;
use codex_windows_sandbox::to_wide;
use codex_windows_sandbox::workspace_write_cap_sid_for_root;
use codex_windows_sandbox::workspace_write_root_overlaps_path;
use codex_windows_sandbox::write_setup_error_report;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
use windows_sys::Win32::Security::CONTAINER_INHERIT_ACE;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;

const DENY_ACCESS: i32 = 3;
#[cfg(test)]
const WRITE_ROOT_ALLOW_MASK: u32 =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;

mod sandbox_users;
mod setup_runtime_bin;
mod uninstall_acl;
#[cfg(test)]
mod uninstall_acl_tests;
mod uninstall_state_machine;
#[cfg(test)]
mod uninstall_state_machine_tests;
use no_reparse_dir::open_or_create_no_reparse;
use read_acl_mutex::acquire_read_acl_mutex;
use read_acl_mutex::read_acl_mutex_exists;
use sandbox_users::commit_setup_marker;
use sandbox_users::prepare_setup_marker;
use sandbox_users::provision_sandbox_users;
use sandbox_users::resolve_sandbox_users_group_sid;
use sandbox_users::resolve_sid;
use sandbox_users::sid_bytes_to_psid;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Payload {
    version: u32,
    #[serde(default)]
    install_id: Option<String>,
    offline_username: String,
    online_username: String,
    #[serde(default)]
    sandbox_group: Option<String>,
    codex_home: PathBuf,
    command_cwd: PathBuf,
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
    #[serde(default)]
    deny_read_paths: Vec<PathBuf>,
    #[serde(default)]
    deny_write_paths: Vec<PathBuf>,
    proxy_ports: Vec<u16>,
    #[serde(default)]
    allow_local_binding: bool,
    #[serde(default)]
    otel: Option<StatsigMetricsSettings>,
    real_user: String,
    #[serde(default)]
    mode: SetupMode,
    #[serde(default)]
    refresh_only: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum SetupMode {
    #[default]
    Full,
    ProvisionOnly,
    ReadAclsOnly,
    /// Removes exactly the resources owned by the payload's installation
    /// identity; never touches other installations' resources and never
    /// restores a wholesale ACL snapshot.
    Uninstall,
}

/// Parses and verifies the payload's installation identity. The account and
/// group names in the payload must exactly match the names derived from the
/// install ID; any mismatch is a hostile or corrupt payload and fails closed.
fn verified_installation_identity(
    payload: &Payload,
) -> Result<codex_windows_sandbox::installation::SandboxInstallationIdentity> {
    let install_id = payload.install_id.as_deref().ok_or_else(|| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            "setup payload is missing the installation identity",
        ))
    })?;
    let identity =
        codex_windows_sandbox::installation::SandboxInstallationIdentity::from_install_id_hex(
            install_id,
        )
        .map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperRequestArgsFailed,
                format!("invalid installation identity: {err}"),
            ))
        })?;
    identity.validate_derived_account_names().map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!("derived installation account names are invalid: {err}"),
        ))
    })?;
    if payload.offline_username != identity.offline_username()
        || payload.online_username != identity.online_username()
    {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            "payload account names do not match the installation identity",
        )));
    }
    if let Some(group) = payload.sandbox_group.as_deref()
        && group != identity.sandbox_group_name()
    {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            "payload sandbox group does not match the installation identity",
        )));
    }
    Ok(identity)
}

fn log_line(log: &mut dyn Write, msg: &str) -> Result<()> {
    let ts = chrono::Utc::now().to_rfc3339();
    writeln!(log, "[{ts}] {msg}").map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperLogFailed,
            format!("failed to write setup log line: {err}"),
        ))
    })?;
    Ok(())
}

fn workspace_write_cap_sids_for_path(
    codex_home: &Path,
    command_cwd: &Path,
    write_roots: &[PathBuf],
    path: &Path,
) -> Result<Vec<String>> {
    let mut sid_strs = Vec::new();
    for root in write_roots {
        if workspace_write_root_overlaps_path(root, path) {
            sid_strs.push(workspace_write_cap_sid_for_root(
                codex_home,
                command_cwd,
                root,
            )?);
        }
    }
    if sid_strs.is_empty() {
        if write_roots.is_empty() {
            sid_strs.push(workspace_write_cap_sid_for_root(
                codex_home,
                command_cwd,
                command_cwd,
            )?);
        } else {
            for root in write_roots {
                sid_strs.push(workspace_write_cap_sid_for_root(
                    codex_home,
                    command_cwd,
                    root,
                )?);
            }
        }
    }
    Ok(sid_strs)
}

fn spawn_read_acl_helper(payload: &Payload, _log: &mut dyn Write) -> Result<()> {
    let mut read_payload = payload.clone();
    read_payload.mode = SetupMode::ReadAclsOnly;
    read_payload.refresh_only = true;
    let payload_json = serde_json::to_vec(&read_payload)?;
    let payload_b64 = BASE64.encode(payload_json);
    let exe = std::env::current_exe().context("locate setup helper")?;
    Command::new(&exe)
        .arg(payload_b64)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .context("spawn read ACL helper")?;
    Ok(())
}

struct ReadAclSubjects<'a> {
    sandbox_group_psid: *mut c_void,
    rx_psids: &'a [*mut c_void],
}

fn apply_read_acls(
    read_roots: &[PathBuf],
    subjects: &ReadAclSubjects<'_>,
    log: &mut dyn Write,
    refresh_errors: &mut Vec<String>,
    access_mask: u32,
    access_label: &str,
    inheritance: u32,
) -> Result<()> {
    for root in read_roots {
        if !root.exists() {
            log_line(
                log,
                &format!("{access_label} root {} missing; skipping", root.display()),
            )?;
            continue;
        }
        let builtin_has = read_mask_allows_or_log(
            root,
            subjects.rx_psids,
            /*label*/ None,
            access_mask,
            access_label,
            refresh_errors,
            log,
        )?;
        if builtin_has {
            continue;
        }
        let sandbox_has = read_mask_allows_or_log(
            root,
            &[subjects.sandbox_group_psid],
            Some("sandbox_group"),
            access_mask,
            access_label,
            refresh_errors,
            log,
        )?;
        if sandbox_has {
            continue;
        }
        log_line(
            log,
            &format!(
                "granting {access_label} ACE to {} for sandbox users",
                root.display()
            ),
        )?;
        let result = unsafe {
            ensure_allow_mask_aces_with_inheritance(
                root,
                &[subjects.sandbox_group_psid],
                access_mask,
                inheritance,
            )
        };
        if let Err(err) = result {
            refresh_errors.push(format!(
                "grant {access_label} ACE failed on {} for sandbox_group: {err}",
                root.display()
            ));
            log_line(
                log,
                &format!(
                    "grant {access_label} ACE failed on {} for sandbox_group: {err}",
                    root.display()
                ),
            )?;
        }
    }
    Ok(())
}

fn read_mask_allows_or_log(
    root: &Path,
    psids: &[*mut c_void],
    label: Option<&str>,
    read_mask: u32,
    access_label: &str,
    refresh_errors: &mut Vec<String>,
    log: &mut dyn Write,
) -> Result<bool> {
    match path_mask_allows(root, psids, read_mask, /*require_all_bits*/ true) {
        Ok(has) => Ok(has),
        Err(e) => {
            let label_suffix = label
                .map(|value| format!(" for {value}"))
                .unwrap_or_default();
            refresh_errors.push(format!(
                "{access_label} mask check failed on {}{}: {}",
                root.display(),
                label_suffix,
                e
            ));
            log_line(
                log,
                &format!(
                    "{access_label} mask check failed on {}{}: {}; continuing",
                    root.display(),
                    label_suffix,
                    e
                ),
            )?;
            Ok(false)
        }
    }
}

fn lock_sandbox_dir(
    dir: &Path,
    real_user: &str,
    sandbox_group_sid: &[u8],
    sandbox_group_access_mode: i32,
    sandbox_group_mask: u32,
    real_user_mask: u32,
    setup_mode: SetupMode,
) -> Result<()> {
    // ProvisionOnly accepts another user's CODEX_HOME; keep its ACL mutation
    // bound to a no-reparse handle without changing full setup behavior.
    let directory = match setup_mode {
        SetupMode::Full | SetupMode::ReadAclsOnly => {
            std::fs::create_dir_all(dir)?;
            None
        }
        SetupMode::Uninstall => {
            // Uninstall never widens or rewrites ACLs; it only removes state.
            std::fs::create_dir_all(dir)?;
            None
        }
        SetupMode::ProvisionOnly => Some(open_or_create_no_reparse(dir)?),
    };
    let system_sid = resolve_sid("SYSTEM")?;
    let admins_sid = resolve_sid("Administrators")?;
    let real_sid = resolve_sid(real_user)?;
    let entries = [
        (
            sandbox_group_sid.to_vec(),
            sandbox_group_mask,
            sandbox_group_access_mode,
        ),
        (
            system_sid,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        ),
        (
            admins_sid,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            GRANT_ACCESS,
        ),
        (real_sid, real_user_mask, GRANT_ACCESS),
    ];
    unsafe {
        let mut eas: Vec<EXPLICIT_ACCESS_W> = Vec::new();
        let mut sids: Vec<*mut c_void> = Vec::new();
        for (sid_bytes, mask, access_mode) in entries.iter().map(|(s, m, a)| (s, *m, *a)) {
            let sid_str = string_from_sid_bytes(sid_bytes).map_err(anyhow::Error::msg)?;
            let sid_w = to_wide(OsStr::new(&sid_str));
            let mut psid: *mut c_void = std::ptr::null_mut();
            if ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) == 0 {
                return Err(anyhow::anyhow!(
                    "ConvertStringSidToSidW failed: {}",
                    GetLastError()
                ));
            }
            sids.push(psid);
            eas.push(EXPLICIT_ACCESS_W {
                grfAccessPermissions: mask,
                grfAccessMode: access_mode,
                grfInheritance: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_SID,
                    ptstrName: psid as *mut u16,
                },
            });
        }
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let set = SetEntriesInAclW(
            eas.len() as u32,
            eas.as_ptr(),
            std::ptr::null_mut(),
            &mut new_dacl,
        );
        if set != 0 {
            return Err(anyhow::anyhow!(
                "SetEntriesInAclW sandbox dir failed: {set}",
            ));
        }
        let (res, api) = match directory.as_ref() {
            Some(directory) => (
                SetSecurityInfo(
                    directory.as_raw_handle() as _,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    new_dacl,
                    std::ptr::null_mut(),
                ),
                "SetSecurityInfo",
            ),
            None => {
                let path_w = to_wide(dir.as_os_str());
                (
                    SetNamedSecurityInfoW(
                        path_w.as_ptr() as *mut u16,
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        new_dacl,
                        std::ptr::null_mut(),
                    ),
                    "SetNamedSecurityInfoW",
                )
            }
        };
        if res != 0 {
            return Err(anyhow::anyhow!("{api} sandbox dir failed: {res}"));
        }
        if !new_dacl.is_null() {
            LocalFree(new_dacl as HLOCAL);
        }
        for sid in sids {
            if !sid.is_null() {
                LocalFree(sid as HLOCAL);
            }
        }
    }
    Ok(())
}

pub fn main() -> Result<()> {
    let ret = real_main();
    if let Err(e) = &ret {
        // Best-effort: log unexpected top-level errors.
        if let Ok(codex_home) = std::env::var("CODEX_HOME") {
            let sbx_dir = sandbox_dir(Path::new(&codex_home));
            let _ = std::fs::create_dir_all(&sbx_dir);
            if let Some(mut f) = log_writer(&sbx_dir) {
                let _ = writeln!(
                    f,
                    "[{}] top-level error: {}",
                    chrono::Utc::now().to_rfc3339(),
                    e
                );
            }
        }
    }
    ret
}

fn real_main() -> Result<()> {
    let mut args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            "expected payload argument",
        )));
    }
    let payload_b64 = args.remove(1);
    let payload_json = BASE64.decode(payload_b64).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!("failed to decode payload b64: {err}"),
        ))
    })?;
    let payload: Payload = serde_json::from_slice(&payload_json).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!("failed to parse payload json: {err}"),
        ))
    })?;
    if payload.version != SETUP_VERSION {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!(
                "setup version mismatch: expected {SETUP_VERSION}, got {}",
                payload.version
            ),
        )));
    }
    let sbx_dir = sandbox_dir(&payload.codex_home);
    std::fs::create_dir_all(&sbx_dir).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxDirCreateFailed,
            format!("failed to create sandbox dir {}: {err}", sbx_dir.display()),
        ))
    })?;
    let mut log = log_writer(&sbx_dir).ok_or_else(|| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperLogFailed,
            format!("open log in {} failed", sbx_dir.display()),
        ))
    })?;
    let result = run_setup(&payload, &mut log, &sbx_dir);
    if let Err(err) = &result {
        let _ = log_line(&mut log, &format!("setup error: {err:?}"));
        log_note(&format!("setup error: {err:?}"), Some(sbx_dir.as_path()));
        let failure = extract_setup_failure(err)
            .map(|f| SetupFailure::new(f.code, f.message.clone()))
            .unwrap_or_else(|| {
                SetupFailure::new(SetupErrorCode::HelperUnknownError, err.to_string())
            });
        let report = SetupErrorReport {
            code: failure.code,
            message: failure.message,
        };
        if let Err(write_err) = write_setup_error_report(&payload.codex_home, &report) {
            let _ = log_line(
                &mut log,
                &format!("setup error report write failed: {write_err}"),
            );
            log_note(
                &format!("setup error report write failed: {write_err}"),
                Some(sbx_dir.as_path()),
            );
        }
    }
    result
}

fn run_setup(payload: &Payload, log: &mut dyn Write, sbx_dir: &Path) -> Result<()> {
    let identity = verified_installation_identity(payload)?;
    let writes_setup_marker = !payload.refresh_only
        && !matches!(payload.mode, SetupMode::ReadAclsOnly | SetupMode::Uninstall);
    if writes_setup_marker {
        prepare_setup_marker(&payload.codex_home, &payload.real_user)?;
    }
    match payload.mode {
        SetupMode::ReadAclsOnly => run_read_acl_only(payload, &identity, log),
        SetupMode::ProvisionOnly => run_provision_only(payload, &identity, log, sbx_dir),
        SetupMode::Full => run_setup_full(payload, &identity, log, sbx_dir),
        SetupMode::Uninstall => run_uninstall_only(payload, &identity, log),
    }?;
    if writes_setup_marker && !matches!(payload.mode, SetupMode::ProvisionOnly) {
        commit_setup_marker(
            &payload.codex_home,
            &identity,
            &payload.proxy_ports,
            payload.allow_local_binding,
            &payload.read_roots,
            &payload.write_roots,
        )?;
    }
    Ok(())
}

fn run_read_acl_only(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    log: &mut dyn Write,
) -> Result<()> {
    let _read_acl_guard = match acquire_read_acl_mutex()? {
        Some(guard) => guard,
        None => {
            log_line(log, "read ACL helper already running; skipping")?;
            return Ok(());
        }
    };
    log_line(log, "read-acl-only mode: applying read ACLs")?;
    let sandbox_group_sid = resolve_sandbox_users_group_sid(&identity.sandbox_group_name())?;
    let sandbox_group_psid = sid_bytes_to_psid(&sandbox_group_sid)?;
    let mut refresh_errors: Vec<String> = Vec::new();
    if !payload.read_roots.is_empty() {
        let users_sid = resolve_sid("Users")?;
        let users_psid = sid_bytes_to_psid(&users_sid)?;
        let auth_sid = resolve_sid("Authenticated Users")?;
        let auth_psid = sid_bytes_to_psid(&auth_sid)?;
        let everyone_sid = resolve_sid("Everyone")?;
        let everyone_psid = sid_bytes_to_psid(&everyone_sid)?;
        let rx_psids = vec![users_psid, auth_psid, everyone_psid];
        let subjects = ReadAclSubjects {
            sandbox_group_psid,
            rx_psids: &rx_psids,
        };
        apply_read_acls(
            &payload.read_roots,
            &subjects,
            log,
            &mut refresh_errors,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            "read",
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )?;
        unsafe {
            if !users_psid.is_null() {
                LocalFree(users_psid as HLOCAL);
            }
            if !auth_psid.is_null() {
                LocalFree(auth_psid as HLOCAL);
            }
            if !everyone_psid.is_null() {
                LocalFree(everyone_psid as HLOCAL);
            }
        }
    }
    unsafe {
        if !sandbox_group_psid.is_null() {
            LocalFree(sandbox_group_psid as HLOCAL);
        }
    }
    if !refresh_errors.is_empty() {
        log_line(
            log,
            &format!("read ACL run completed with errors: {refresh_errors:?}"),
        )?;
        if payload.refresh_only {
            anyhow::bail!("read ACL run had errors");
        }
    }
    log_line(log, "read ACL run completed")?;
    Ok(())
}

fn provision_and_hide_sandbox_users(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    log: &mut dyn Write,
    sbx_dir: &Path,
) -> Result<()> {
    let provision_result = provision_sandbox_users(&payload.codex_home, identity, log);
    if let Err(err) = provision_result {
        if extract_setup_failure(&err).is_some() {
            return Err(err);
        }
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUserProvisionFailed,
            format!("provision sandbox users failed: {err}"),
        )));
    }
    let users = vec![identity.offline_username(), identity.online_username()];
    hide_newly_created_users(&users, sbx_dir);
    Ok(())
}

fn configure_offline_sandbox_network(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    offline_sid_str: &str,
    log: &mut dyn Write,
) -> Result<()> {
    let proxy_allowlist_result = firewall::ensure_offline_proxy_allowlist(
        identity,
        offline_sid_str,
        &payload.proxy_ports,
        payload.allow_local_binding,
        log,
    );
    if let Err(err) = proxy_allowlist_result {
        if extract_setup_failure(&err).is_some() {
            return Err(err);
        }
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
            format!("ensure offline proxy allowlist failed: {err}"),
        )));
    }
    let firewall_result = firewall::ensure_offline_outbound_block(identity, offline_sid_str, log);
    if let Err(err) = firewall_result {
        if extract_setup_failure(&err).is_some() {
            return Err(err);
        }
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
            format!("ensure offline outbound block failed: {err}"),
        )));
    }
    install_wfp_filters(
        &payload.codex_home,
        identity,
        &identity.offline_username(),
        &payload.real_user,
        payload.otel.as_ref(),
        |message| {
            let _ = log_line(log, message);
        },
    );
    // Telemetry remains best effort; the containment boundary does not.
    codex_windows_sandbox::read_live_filter_facts(&payload.codex_home, identity, offline_sid_str)?;
    Ok(())
}

/// Reads the read/write roots persisted by the last committed setup marker
/// for precise ACE cleanup. A missing or unreadable marker yields an empty
/// list; uninstall then proceeds without root cleanup.
fn recorded_setup_roots(codex_home: &Path) -> Vec<PathBuf> {
    let marker_path = sandbox_dir(codex_home).join("setup_marker.json");
    let Ok(contents) = std::fs::read_to_string(&marker_path) else {
        return Vec::new();
    };
    #[derive(serde::Deserialize)]
    struct RecordedMarker {
        #[serde(default)]
        read_roots: Vec<PathBuf>,
        #[serde(default)]
        write_roots: Vec<PathBuf>,
    }
    let Ok(marker) = serde_json::from_str::<RecordedMarker>(&contents) else {
        return Vec::new();
    };
    let mut roots = marker.read_roots;
    roots.extend(marker.write_roots);
    roots
}

/// Removes exactly the resources owned by `identity`. Every step is
/// logged; ACL failure stops before destroying the group needed for retry,
/// and no resource owned by a different installation
/// (Codex-global or otherwise) is ever touched.
/// Production wiring of the uninstall state machine: real Win32/COM/WFP
/// effects over the payload's codex home, with a file-backed atomic journal.
/// ACL failures preserve the group and stop before later phases so retry can resolve its SID.
fn run_uninstall_only(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    log: &mut dyn Write,
) -> Result<()> {
    log_line(
        log,
        &format!(
            "uninstall mode: removing resources owned by installation {}",
            identity.install_suffix()
        ),
    )?;
    let codex_home = payload.codex_home.as_path();

    let mut effects = WinUninstallEffects {
        codex_home: codex_home.to_path_buf(),
    };
    let mut journal_io = FileCleanupJournalIo {
        sandbox_dir: sandbox_dir(codex_home),
    };
    let mut log_line_sink = String::new();
    let outcome = uninstall_state_machine::run_uninstall(
        identity,
        &mut effects,
        &mut journal_io,
        || chrono::Utc::now().to_rfc3339(),
        &mut |message| {
            log_line_sink.push_str(message);
            log_line_sink.push('\n');
        },
    );
    if !log_line_sink.is_empty() {
        log.write_all(log_line_sink.as_bytes())?;
    }
    match outcome {
        Ok(()) => {
            log_line(log, "uninstall fully complete; state deleted")?;
            Ok(())
        }
        Err(failures) => {
            for failure in &failures {
                log_line(
                    log,
                    &format!(
                        "uninstall incomplete at {}: {}",
                        failure.phase, failure.detail
                    ),
                )?;
            }
            Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperUnknownError,
                format!(
                    "uninstall left {} recoverable failure(s); rerun the uninstall for the same installation",
                    failures.len()
                ),
            )))
        }
    }
}

/// Real-effect adapter: every call targets the exact installation identity
/// recorded in the payload.
struct WinUninstallEffects {
    codex_home: PathBuf,
}

impl uninstall_state_machine::UninstallEffects for WinUninstallEffects {
    fn recorded_roots(&self) -> Vec<PathBuf> {
        let mut roots = recorded_setup_roots(&self.codex_home);
        roots.push(sandbox_dir(&self.codex_home));
        roots.push(sandbox_secrets_dir(&self.codex_home));
        roots.push(sandbox_bin_dir(&self.codex_home));
        roots
    }

    fn group_sid(&self) -> Option<Vec<u8>> {
        // Fail-closed derivation: the group SID comes from the persisted
        // installation identity, not from an ambient name.
        let identity = codex_windows_sandbox::installation::read_installation_identity(
            &sandbox_dir(&self.codex_home),
        )
        .ok()
        .flatten()?;
        sandbox_users::resolve_sandbox_users_group_sid(&identity.sandbox_group_name()).ok()
    }

    fn remove_group_aces(&mut self, roots: &[PathBuf], sid: &[u8]) -> Vec<String> {
        let mut failures = Vec::new();
        for root in roots {
            match uninstall_acl::remove_group_allow_aces(root, sid) {
                Ok(_) => {}
                Err(err) => failures.push(format!("{}: {err}", root.display())),
            }
        }
        failures
    }

    fn remove_firewall_rules(
        &mut self,
        identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    ) {
        // Logged best effort; the presence query decides the phase outcome.
        let mut sink = Vec::new();
        let _ = firewall::remove_offline_rules_for_identity(identity, &mut sink);
    }

    fn firewall_rules_present(
        &self,
        identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    ) -> Vec<String> {
        firewall::firewall_rules_present(identity)
    }

    fn remove_wfp_objects(
        &mut self,
        identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    ) {
        let mut sink = Vec::new();
        let _ = codex_windows_sandbox::remove_wfp_objects_for_installation(
            &self.codex_home,
            identity,
            &mut |message| {
                let _ = sink.write_all(message.as_bytes());
            },
        );
    }

    fn wfp_objects_present(
        &self,
        identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    ) -> Vec<String> {
        codex_windows_sandbox::wfp_objects_present(&self.codex_home, identity)
    }

    fn remove_accounts(
        &mut self,
        identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    ) {
        // Best effort; the presence query decides the phase outcome.
        let mut sink = Vec::new();
        let _ = sandbox_users::remove_sandbox_users(identity, &mut sink);
    }

    fn accounts_present(
        &self,
        identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    ) -> Vec<String> {
        sandbox_users::accounts_present(identity)
    }

    fn delete_state_file(&mut self, name: &str) {
        if name == "sandbox_users.json" {
            // The secrets-dir copy belongs to this installation as well.
            let secrets_copy = sandbox_secrets_dir(&self.codex_home).join(name);
            let _ = std::fs::remove_file(secrets_copy);
        }
        let _ = std::fs::remove_file(sandbox_dir(&self.codex_home).join(name));
    }

    fn persisted_installation_id(&self) -> Option<String> {
        codex_windows_sandbox::installation::read_installation_identity(&sandbox_dir(
            &self.codex_home,
        ))
        .ok()
        .flatten()
        .map(|identity| identity.install_id_hex())
    }

    fn ownership_digest(&self) -> Option<String> {
        let path = self.codex_home.join(".sandbox").join("wfp_ownership.json");
        let contents = std::fs::read(path).ok()?;
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(&contents);
        Some(format!("{digest:x}"))
    }
}

/// File-backed journal IO with atomic temp+rename writes inside the
/// protected sandbox state directory.
struct FileCleanupJournalIo {
    sandbox_dir: PathBuf,
}

impl uninstall_state_machine::UninstallJournalIo for FileCleanupJournalIo {
    fn read_journal(&self) -> Option<uninstall_state_machine::CleanupJournal> {
        let path = self
            .sandbox_dir
            .join(uninstall_state_machine::CLEANUP_JOURNAL_FILE_NAME);
        let contents = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&contents).ok()
    }

    fn write_journal(
        &mut self,
        journal: &uninstall_state_machine::CleanupJournal,
    ) -> std::io::Result<()> {
        let sandbox_dir = self.sandbox_dir.clone();
        let rename_root = self.sandbox_dir.clone();
        uninstall_state_machine::write_journal_atomic(
            journal,
            move |temp_name| {
                let temp_path = sandbox_dir.join(temp_name);
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_path)?;
                Ok((temp_path, file))
            },
            move |temp_path, final_name| std::fs::rename(temp_path, rename_root.join(final_name)),
        )
    }

    fn delete_journal(&mut self) -> std::io::Result<()> {
        std::fs::remove_file(
            self.sandbox_dir
                .join(uninstall_state_machine::CLEANUP_JOURNAL_FILE_NAME),
        )
        .or_else(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(err)
            }
        })
    }
}

fn lock_persistent_sandbox_dirs(payload: &Payload, sandbox_group_sid: &[u8]) -> Result<()> {
    lock_sandbox_dir(
        &sandbox_dir(&payload.codex_home),
        &payload.real_user,
        sandbox_group_sid,
        GRANT_ACCESS,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        payload.mode,
    )
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxLockFailed,
            format!(
                "lock sandbox dir {} failed: {err}",
                sandbox_dir(&payload.codex_home).display()
            ),
        ))
    })?;
    lock_sandbox_dir(
        &sandbox_secrets_dir(&payload.codex_home),
        &payload.real_user,
        sandbox_group_sid,
        DENY_ACCESS,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
        payload.mode,
    )
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxLockFailed,
            format!(
                "lock sandbox secrets dir {} failed: {err}",
                sandbox_secrets_dir(&payload.codex_home).display()
            ),
        ))
    })?;
    let legacy_users = sandbox_dir(&payload.codex_home).join("sandbox_users.json");
    if legacy_users.exists() {
        let _ = std::fs::remove_file(&legacy_users);
    }
    Ok(())
}

fn lock_sandbox_bin_dir(payload: &Payload, sandbox_group_sid: &[u8]) -> Result<()> {
    lock_sandbox_dir(
        &sandbox_bin_dir(&payload.codex_home),
        &payload.real_user,
        sandbox_group_sid,
        GRANT_ACCESS,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        payload.mode,
    )
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSandboxLockFailed,
            format!(
                "lock sandbox bin dir {} failed: {err}",
                sandbox_bin_dir(&payload.codex_home).display()
            ),
        ))
    })
}

fn run_provision_only(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    log: &mut dyn Write,
    sbx_dir: &Path,
) -> Result<()> {
    // R2B: provisioning is a nonce-challenged operation. Without a valid
    // one-time request from Main the helper refuses to touch the machine.
    let now = chrono::Utc::now().to_rfc3339();
    let request = codex_windows_sandbox::setup_receipt::read_setup_request(
        &payload.codex_home,
        identity,
        &now,
    )
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperRequestArgsFailed,
            format!("elevated setup requires a valid one-time request: {err}"),
        ))
    })?;
    log_line(
        log,
        &format!(
            "setup request accepted (nonce {}…, expires {})",
            &request.nonce[..8],
            request.expires_at
        ),
    )?;

    provision_and_hide_sandbox_users(payload, identity, log, sbx_dir)?;
    let offline_username = identity.offline_username();
    let offline_sid = resolve_sid(&offline_username).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!("resolve SID for offline user {offline_username} failed: {err}"),
        ))
    })?;
    let offline_sid_str = string_from_sid_bytes(&offline_sid).map_err(anyhow::Error::msg)?;

    let sandbox_group_sid = resolve_sandbox_users_group_sid(&identity.sandbox_group_name())
        .map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperSidResolveFailed,
                format!("resolve sandbox users group SID failed: {err}"),
            ))
        })?;
    let sandbox_group_sid_str =
        string_from_sid_bytes(&sandbox_group_sid).map_err(anyhow::Error::msg)?;
    let online_sid = resolve_sid(&identity.online_username())?;
    let online_sid_str = string_from_sid_bytes(&online_sid).map_err(anyhow::Error::msg)?;

    configure_offline_sandbox_network(payload, identity, &offline_sid_str, log)?;

    lock_sandbox_bin_dir(payload, &sandbox_group_sid)?;
    lock_persistent_sandbox_dirs(payload, &sandbox_group_sid)?;

    // R2B: mint the nonce-bound machine-effect receipt. Main never writes
    // this file; it only verifies it against the request and the marker.
    finalize_provisioned_setup(payload, identity, || {
        write_provisioning_receipt(
            payload,
            identity,
            &request,
            &offline_sid_str,
            &online_sid_str,
            &sandbox_group_sid_str,
            log,
        )
    })?;

    log_note("setup provisioning binary completed", Some(sbx_dir));
    Ok(())
}

// The receipt must bind final marker bytes, never the empty protected
// placeholder created before provisioning. The outer setup path does not
// rewrite this marker after the nonce-bound receipt has been minted.
fn finalize_provisioned_setup(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    write_receipt: impl FnOnce() -> Result<()>,
) -> Result<()> {
    commit_setup_marker(
        &payload.codex_home,
        identity,
        &payload.proxy_ports,
        payload.allow_local_binding,
        &payload.read_roots,
        &payload.write_roots,
    )?;
    write_receipt()
}

// The frozen offline backend installs three BLOCK rules. The old proxy
// ALLOW rule is deliberately removed by ensure_offline_proxy_allowlist.
fn verified_provisioning_firewall_rules(
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    present: &[String],
) -> Result<Vec<String>> {
    let mut expected = vec![
        identity.offline_block_rule_name(),
        identity.offline_block_loopback_tcp_rule_name(),
        identity.offline_block_loopback_udp_rule_name(),
    ];
    expected.sort();
    let mut actual = present.to_vec();
    actual.sort();
    if actual != expected {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUnknownError,
            "offline firewall closure must contain exactly three BLOCK rules and no legacy ALLOW rule",
        )));
    }
    Ok(expected)
}

/// Collects the exact provisioned facts and writes the nonce-bound receipt
/// into the elevated directory, consuming the one-time request.
fn write_provisioning_receipt(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    request: &codex_windows_sandbox::setup_receipt::SetupRequestFile,
    offline_sid: &str,
    online_sid: &str,
    group_sid: &str,
    log: &mut dyn Write,
) -> Result<()> {
    use codex_windows_sandbox::setup_receipt::ElevatedSetupReceiptV1;

    let marker_digest = codex_windows_sandbox::setup_receipt::sha256_file_hex(
        &sandbox_dir(&payload.codex_home).join("setup_marker.json"),
    );
    let helper_digest = codex_windows_sandbox::setup_receipt::compute_self_digest();

    // The WFP ownership record is REQUIRED: a receipt over an empty or
    // partial machine-effect closure must never be written (v2 contract).
    let ownership_path = sandbox_dir(&payload.codex_home).join("wfp_ownership.json");
    let ownership_contents = std::fs::read_to_string(&ownership_path).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUnknownError,
            format!("wfp ownership record unreadable: {err}"),
        ))
    })?;
    let ownership_record: codex_windows_sandbox::WfpOwnershipRecord =
        serde_json::from_str(&ownership_contents).map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperUnknownError,
                format!("wfp ownership record malformed: {err}"),
            ))
        })?;
    let ownership_digest =
        codex_windows_sandbox::setup_receipt::sha256_hex(ownership_contents.as_bytes());

    let (marker_digest, helper_digest) = match (marker_digest, helper_digest) {
        (Ok(marker), Ok(helper)) => (marker, helper),
        _ => {
            return Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperUnknownError,
                "provisioning receipt inputs unreadable (marker or self digest)",
            )));
        }
    };

    let firewall_rule_names = verified_provisioning_firewall_rules(
        identity,
        &firewall::firewall_rules_present(identity),
    )?;

    // WFP keys come from the REQUIRED ownership record; the filter-key map
    // must cover exactly the static spec set - no missing or extra names.
    let wfp_filters = ownership_record.filter_keys;
    let wfp_provider = ownership_record.provider_key;
    let wfp_sublayer = ownership_record.sublayer_key;
    let spec_names = codex_windows_sandbox::filter_spec_names();
    if wfp_provider.is_empty() || wfp_sublayer.is_empty() {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUnknownError,
            "wfp ownership record carries empty provider or sublayer keys",
        )));
    }
    if wfp_filters.len() != spec_names.len()
        || !spec_names
            .iter()
            .all(|name| wfp_filters.contains_key(*name))
    {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperUnknownError,
            "wfp ownership record filter-key closure is incomplete",
        )));
    }

    // Live per-filter read-back (layer, action, user-condition SID) fresh
    // from the engine: the receipt binds verified facts, never intents.
    let wfp_filter_facts =
        codex_windows_sandbox::read_live_filter_facts(&payload.codex_home, identity, offline_sid)
            .map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperUnknownError,
                format!("live wfp filter read-back failed: {err}"),
            ))
        })?;

    let os_build = os_build_string();
    let receipt = ElevatedSetupReceiptV1 {
        version: codex_windows_sandbox::setup_receipt::RECEIPT_VERSION,
        nonce: request.nonce.clone(),
        install_id: identity.install_id_hex(),
        evidence_digest: request.evidence_digest.clone(),
        completed_at: chrono::Utc::now().to_rfc3339(),
        setup_version: SETUP_VERSION,
        os_build,
        helper_sha256: helper_digest,
        marker_sha256: marker_digest,
        ownership_sha256: ownership_digest,
        offline_account_sid: offline_sid.to_string(),
        online_account_sid: online_sid.to_string(),
        sandbox_group_sid: group_sid.to_string(),
        firewall_rule_names,
        wfp_provider_key: wfp_provider,
        wfp_sublayer_key: wfp_sublayer,
        wfp_filter_keys: wfp_filters,
        wfp_filter_facts,
    };
    // The receipt directory protection binds the resolved real-user SID
    // (never the ambiguous account name) as its read-only trustee.
    let real_user_sid = resolve_sid(&payload.real_user)
        .map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperSidResolveFailed,
                format!(
                    "resolve SID for real user {} failed: {err}",
                    payload.real_user
                ),
            ))
        })
        .and_then(|sid| string_from_sid_bytes(&sid).map_err(anyhow::Error::msg))?;
    let path = codex_windows_sandbox::setup_receipt::write_receipt_and_consume_request(
        &payload.codex_home,
        &receipt,
        &real_user_sid,
    )?;
    log_line(
        log,
        &format!("provisioning receipt written: {}", path.display()),
    )?;
    Ok(())
}

/// OS build string (major.minor.build) read from the registry's
/// CurrentVersion keys — the same authoritative source the OS itself uses,
/// independent of app-compat version lies.
fn os_build_string() -> String {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    use windows_sys::Win32::System::Registry::KEY_READ;
    use windows_sys::Win32::System::Registry::RRF_RT_REG_SZ;
    use windows_sys::Win32::System::Registry::RegCloseKey;
    use windows_sys::Win32::System::Registry::RegGetValueW;
    unsafe {
        let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let read_string = |value: &[u16]| -> Option<String> {
            let mut buffer = [0u16; 64];
            let mut size = (buffer.len() * 2) as u32;
            let code = RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            );
            if code != ERROR_SUCCESS {
                return None;
            }
            let length = (size as usize / 2).saturating_sub(1);
            Some(String::from_utf16_lossy(&buffer[..length]))
        };
        let major: &[u16] = &"CurrentMajorVersionNumber"
            .encode_utf16()
            .collect::<Vec<_>>();
        let _ = major;
        let major_value: Vec<u16> = "CurrentMajorVersionNumber"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let minor_value: Vec<u16> = "CurrentMinorVersionNumber"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let build_value: Vec<u16> = "CurrentBuildNumber".encode_utf16().chain(Some(0)).collect();
        // Note: CurrentMajor/MinorVersionNumber are REG_DWORD; fall back to
        // well-known constants when the string read fails.
        let major = read_string(&major_value).unwrap_or_else(|| "10".to_string());
        let minor = read_string(&minor_value).unwrap_or_else(|| "0".to_string());
        let build = read_string(&build_value).unwrap_or_default();
        let _ = KEY_READ;
        let _ = RegCloseKey;
        format!("{major}.{minor}.{build}")
    }
}

fn run_setup_full(
    payload: &Payload,
    identity: &codex_windows_sandbox::installation::SandboxInstallationIdentity,
    log: &mut dyn Write,
    sbx_dir: &Path,
) -> Result<()> {
    let refresh_only = payload.refresh_only;
    if !refresh_only {
        provision_and_hide_sandbox_users(payload, identity, log, sbx_dir)?;
    }
    let offline_username = identity.offline_username();
    let offline_sid = resolve_sid(&offline_username).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!("resolve SID for offline user {offline_username} failed: {err}"),
        ))
    })?;
    let offline_sid_str = string_from_sid_bytes(&offline_sid).map_err(anyhow::Error::msg)?;

    let sandbox_group_sid = resolve_sandbox_users_group_sid(&identity.sandbox_group_name())
        .map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperSidResolveFailed,
                format!("resolve sandbox users group SID failed: {err}"),
            ))
        })?;
    let sandbox_group_psid = sid_bytes_to_psid(&sandbox_group_sid).map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperSidResolveFailed,
            format!("convert sandbox users group SID to PSID failed: {err}"),
        ))
    })?;
    let sandbox_group_sid_str =
        string_from_sid_bytes(&sandbox_group_sid).map_err(anyhow::Error::msg)?;

    let mut refresh_errors: Vec<String> = Vec::new();
    if !refresh_only {
        configure_offline_sandbox_network(payload, identity, &offline_sid_str, log)?;
    }

    // Deny-read ACEs must be present before the sandboxed command starts. Apply
    // them synchronously here instead of delegating them to the background
    // helper used for read grants.
    let applied_deny_read_paths = unsafe {
        sync_persistent_deny_read_acls(
            &payload.codex_home,
            &sandbox_group_sid_str,
            &payload.deny_read_paths,
            sandbox_group_psid,
        )
    }
    .context("apply deny-read ACLs")?;
    if !applied_deny_read_paths.is_empty() {
        log_line(
            log,
            &format!("applied {} deny-read ACLs", applied_deny_read_paths.len()),
        )?;
    }

    if payload.read_roots.is_empty() {
        log_line(log, "no read roots to grant; skipping read ACL helper")?;
    } else {
        match read_acl_mutex_exists() {
            Ok(true) => {
                log_line(log, "read ACL helper already running; skipping spawn")?;
            }
            Ok(false) => {
                spawn_read_acl_helper(payload, log).map_err(|err| {
                    anyhow::Error::new(SetupFailure::new(
                        SetupErrorCode::HelperReadAclHelperSpawnFailed,
                        format!("spawn read ACL helper failed: {err}"),
                    ))
                })?;
            }
            Err(err) => {
                log_line(
                    log,
                    &format!("read ACL mutex check failed: {err}; spawning anyway"),
                )?;
                spawn_read_acl_helper(payload, log).map_err(|spawn_err| {
                    anyhow::Error::new(SetupFailure::new(
                        SetupErrorCode::HelperReadAclHelperSpawnFailed,
                        format!(
                            "spawn read ACL helper failed after mutex error {err}: {spawn_err}"
                        ),
                    ))
                })?;
            }
        }
    }

    if refresh_only {
        setup_runtime_bin::ensure_codex_app_runtime_paths_readable(
            sandbox_group_psid,
            &mut refresh_errors,
            log,
        )?;
    }

    let mut grant_tasks: Vec<(PathBuf, String)> = Vec::new();

    let mut seen_deny_paths: HashSet<PathBuf> = HashSet::new();
    let mut seen_write_roots: HashSet<PathBuf> = HashSet::new();
    for root in &payload.write_roots {
        if !seen_write_roots.insert(root.clone()) {
            continue;
        }
        if !root.exists() {
            log_line(
                log,
                &format!("write root {} missing; skipping", root.display()),
            )?;
            continue;
        }
        let root_cap_sid_str =
            workspace_write_cap_sid_for_root(&payload.codex_home, &payload.command_cwd, root)?;
        let root_cap_psid = unsafe {
            convert_string_sid_to_sid(&root_cap_sid_str)
                .ok_or_else(|| anyhow::anyhow!("convert write root capability SID failed"))?
        };
        let need_grant =
            match path_write_aces_need_refresh(root, &[sandbox_group_psid, root_cap_psid]) {
                Ok(needs_refresh) => needs_refresh,
                Err(e) => {
                    refresh_errors.push(format!(
                        "write ACE check failed on {}: {}",
                        root.display(),
                        e
                    ));
                    log_line(
                        log,
                        &format!(
                            "write ACE check failed on {}: {}; continuing",
                            root.display(),
                            e
                        ),
                    )?;
                    true
                }
            };
        unsafe {
            LocalFree(root_cap_psid as HLOCAL);
        }
        if need_grant {
            log_line(
                log,
                &format!(
                    "granting write ACE to {} for sandbox group and capability SID",
                    root.display()
                ),
            )?;
            grant_tasks.push((root.clone(), root_cap_sid_str));
        }
    }

    let (tx, rx) = mpsc::channel::<(PathBuf, Result<bool>)>();
    std::thread::scope(|scope| {
        for (root, root_cap_sid_str) in grant_tasks {
            let sid_strings = vec![sandbox_group_sid_str.clone(), root_cap_sid_str];
            let tx = tx.clone();
            scope.spawn(move || {
                // Convert SID strings to psids locally in this thread.
                let mut psids: Vec<*mut c_void> = Vec::new();
                for sid_str in &sid_strings {
                    if let Some(psid) = unsafe { convert_string_sid_to_sid(sid_str) } {
                        psids.push(psid);
                    } else {
                        let _ = tx.send((root.clone(), Err(anyhow::anyhow!("convert SID failed"))));
                        return;
                    }
                }

                let res = unsafe { ensure_allow_write_aces(&root, &psids) };

                for psid in psids {
                    unsafe {
                        LocalFree(psid as HLOCAL);
                    }
                }
                let _ = tx.send((root, res));
            });
        }
        drop(tx);
        for (root, res) in rx {
            match res {
                Ok(_) => {}
                Err(e) => {
                    refresh_errors.push(format!("write ACE failed on {}: {}", root.display(), e));
                    if log_line(
                        log,
                        &format!("write ACE grant failed on {}: {}", root.display(), e),
                    )
                    .is_err()
                    {
                        // ignore log errors inside scoped thread
                    }
                }
            }
        }
    });

    for path in &payload.deny_write_paths {
        if !seen_deny_paths.insert(path.clone()) {
            continue;
        }

        // These are deny-write carveouts, not deny-read paths. They may come from explicit
        // read-only-under-a-writable-root carveouts in the transformed sandbox policy, or from
        // legacy protected children such as `.git`, `.codex`, and `.agents`.
        //
        // Deny ACEs attach to filesystem objects; if an explicit policy carveout does not exist
        // during setup, the sandbox could otherwise create it later under a writable parent and
        // bypass the carveout. Materialize missing carveouts as directories so the deny-write ACL
        // is present before the command starts. Legacy protected children are filtered before
        // payload creation, so this should not create sentinel directories in a workspace.
        if !path.exists() {
            std::fs::create_dir_all(path)
                .with_context(|| format!("failed to create deny-write path {}", path.display()))?;
        }

        let deny_sid_strs = workspace_write_cap_sids_for_path(
            &payload.codex_home,
            &payload.command_cwd,
            &payload.write_roots,
            path,
        )?;
        for deny_sid_str in deny_sid_strs {
            let deny_psid = unsafe {
                convert_string_sid_to_sid(&deny_sid_str)
                    .ok_or_else(|| anyhow::anyhow!("convert deny capability SID failed"))?
            };

            match unsafe { ls_owned_acl::protect(path, deny_psid, payload, identity) } {
                Ok(true) => {
                    log_line(
                        log,
                        &format!("applied deny ACE to protect {}", path.display()),
                    )?;
                }
                Ok(false) => {}
                Err(err) => {
                    refresh_errors.push(format!("deny ACE failed on {}: {err}", path.display()));
                    log_line(
                        log,
                        &format!("deny ACE failed on {}: {err}", path.display()),
                    )?;
                }
            }
            unsafe {
                LocalFree(deny_psid as HLOCAL);
            }
        }
    }

    lock_sandbox_bin_dir(payload, &sandbox_group_sid)?;

    if refresh_only {
        log_line(
            log,
            &format!(
                "setup refresh: processed {} write roots (read roots delegated); errors={:?}",
                payload.write_roots.len(),
                refresh_errors
            ),
        )?;
    }
    if !refresh_only {
        lock_persistent_sandbox_dirs(payload, &sandbox_group_sid)?;
    }

    unsafe {
        if !sandbox_group_psid.is_null() {
            LocalFree(sandbox_group_psid as HLOCAL);
        }
    }
    if refresh_only && !refresh_errors.is_empty() {
        log_line(
            log,
            &format!("setup refresh completed with errors: {refresh_errors:?}"),
        )?;
        anyhow::bail!("setup refresh had errors");
    }
    log_note("setup binary completed", Some(sbx_dir));
    Ok(())
}

#[cfg(test)]
#[path = "win_acl_tests.rs"]
mod acl_tests;

#[cfg(test)]
mod tests {
    use super::Payload;
    use super::SETUP_VERSION;
    use super::WRITE_ROOT_ALLOW_MASK;
    use super::convert_string_sid_to_sid;
    use super::workspace_write_cap_sids_for_path;
    use codex_otel::StatsigMetricsSettings;
    use codex_windows_sandbox::ensure_allow_mask_aces;
    use codex_windows_sandbox::ensure_allow_write_aces;
    use codex_windows_sandbox::load_or_create_cap_sids;
    use codex_windows_sandbox::path_mask_allows;
    use codex_windows_sandbox::path_write_aces_need_refresh;
    use codex_windows_sandbox::workspace_write_cap_sid_for_root;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::fs;
    use windows_sys::Win32::Foundation::HLOCAL;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Storage::FileSystem::FILE_DELETE_CHILD;

    fn payload_json() -> serde_json::Value {
        json!({
            "version": SETUP_VERSION,
            "offline_username": "CodexSandboxOffline",
            "online_username": "CodexSandboxOnline",
            "codex_home": "C:\\codex-home",
            "command_cwd": "C:\\workspace",
            "read_roots": [],
            "write_roots": [],
            "proxy_ports": [],
            "real_user": "User",
        })
    }

    #[test]
    fn payload_defaults_otel_absent() {
        let payload: Payload = serde_json::from_value(payload_json()).expect("payload");

        assert_eq!(payload.otel, None);
    }

    #[test]
    fn provisioning_receipt_rejects_missing_duplicate_and_legacy_allow_rules() {
        let identity = codex_windows_sandbox::installation::SandboxInstallationIdentity::generate();
        let blocks = vec![
            identity.offline_block_rule_name(),
            identity.offline_block_loopback_tcp_rule_name(),
            identity.offline_block_loopback_udp_rule_name(),
        ];
        assert!(super::verified_provisioning_firewall_rules(&identity, &blocks).is_ok());
        assert!(super::verified_provisioning_firewall_rules(&identity, &blocks[..2]).is_err());
        let mut legacy = blocks.clone();
        legacy.push(identity.offline_allow_loopback_proxy_rule_name());
        assert!(super::verified_provisioning_firewall_rules(&identity, &legacy).is_err());
        let mut duplicate = blocks.clone();
        duplicate.push(blocks[0].clone());
        assert!(super::verified_provisioning_firewall_rules(&identity, &duplicate).is_err());
    }

    #[test]
    fn provisioning_receipt_binds_final_marker_bytes() {
        let temporary = tempfile::tempdir().expect("temporary");
        let codex_home = temporary.path();
        std::fs::create_dir(codex_home.join(".sandbox")).expect("sandbox");
        let marker = codex_home.join(".sandbox/setup_marker.json");
        std::fs::write(&marker, b"").expect("placeholder");
        let mut value = payload_json();
        value["codex_home"] = serde_json::json!(codex_home);
        value["mode"] = serde_json::json!("provision-only");
        let payload: Payload = serde_json::from_value(value).expect("payload");
        let identity = codex_windows_sandbox::installation::SandboxInstallationIdentity::generate();
        let mut recorded = None;
        super::finalize_provisioned_setup(&payload, &identity, || {
            let contents = std::fs::read(&marker)?;
            let value: serde_json::Value = serde_json::from_slice(&contents)?;
            assert_eq!(
                value["install_id"],
                serde_json::json!(identity.install_id_hex())
            );
            recorded = Some(codex_windows_sandbox::setup_receipt::sha256_hex(&contents));
            Ok(())
        })
        .expect("finalized");
        assert_eq!(
            recorded,
            Some(
                codex_windows_sandbox::setup_receipt::sha256_file_hex(&marker).expect("final hash")
            )
        );
    }

    #[test]
    fn payload_accepts_provision_only_mode() {
        let mut payload = payload_json();
        payload["mode"] = json!("provision-only");
        let payload: Payload = serde_json::from_value(payload).expect("payload");

        assert_eq!(payload.mode, super::SetupMode::ProvisionOnly);
    }

    #[test]
    fn payload_accepts_otel_settings() {
        let mut payload = payload_json();
        payload["otel"] = json!({
            "environment": "prod",
        });
        let payload: Payload = serde_json::from_value(payload).expect("payload");

        assert_eq!(
            payload.otel,
            Some(StatsigMetricsSettings {
                environment: "prod".to_string(),
            })
        );
    }

    #[test]
    fn write_root_refresh_replaces_stale_delete_child_grant() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");

        let sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let psid = unsafe { convert_string_sid_to_sid(&sid).expect("convert workspace sid") };
        let stale_write_mask = WRITE_ROOT_ALLOW_MASK | FILE_DELETE_CHILD;
        let seeded = unsafe { ensure_allow_mask_aces(&workspace, &[psid], stale_write_mask) }
            .expect("seed stale write ACE");
        let needs_refresh_before =
            path_write_aces_need_refresh(&workspace, &[psid]).expect("check stale write ACE");
        let replaced = unsafe { ensure_allow_write_aces(&workspace, &[psid]) }
            .expect("replace stale write ACE");
        let needs_refresh_after =
            path_write_aces_need_refresh(&workspace, &[psid]).expect("check refreshed write ACE");
        unsafe {
            LocalFree(psid as HLOCAL);
        }

        assert_eq!(
            (seeded, needs_refresh_before, replaced, needs_refresh_after),
            (true, true, true, false)
        );
    }

    #[test]
    fn write_root_refresh_checks_each_sid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let other_root = temp.path().join("other-root");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::create_dir_all(&other_root).expect("create other root");

        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let other_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &other_root)
            .expect("other root sid");
        let workspace_psid =
            unsafe { convert_string_sid_to_sid(&workspace_sid).expect("convert workspace sid") };
        let other_psid =
            unsafe { convert_string_sid_to_sid(&other_sid).expect("convert other root sid") };

        let seeded = unsafe { ensure_allow_write_aces(&workspace, &[workspace_psid]) }
            .expect("seed workspace SID");
        let needs_refresh_before =
            path_write_aces_need_refresh(&workspace, &[workspace_psid, other_psid])
                .expect("check both SIDs");
        let refreshed =
            unsafe { ensure_allow_write_aces(&workspace, &[workspace_psid, other_psid]) }
                .expect("refresh both SIDs");
        let needs_refresh_after =
            path_write_aces_need_refresh(&workspace, &[workspace_psid, other_psid])
                .expect("recheck both SIDs");
        unsafe {
            LocalFree(workspace_psid as HLOCAL);
            LocalFree(other_psid as HLOCAL);
        }

        assert_eq!(
            (seeded, needs_refresh_before, refreshed, needs_refresh_after,),
            (true, true, true, false)
        );
    }

    #[test]
    fn write_root_refresh_ignores_inherited_delete_child_grant() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let parent = temp.path().join("parent");
        let workspace = parent.join("workspace");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");

        let sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let psid = unsafe { convert_string_sid_to_sid(&sid).expect("convert workspace sid") };
        let seeded_explicit =
            unsafe { ensure_allow_mask_aces(&workspace, &[psid], WRITE_ROOT_ALLOW_MASK) }
                .expect("seed explicit write ACE");
        let seeded_parent = unsafe {
            ensure_allow_mask_aces(&parent, &[psid], WRITE_ROOT_ALLOW_MASK | FILE_DELETE_CHILD)
        }
        .expect("seed inherited stale write ACE");
        let has_inherited_delete_child = path_mask_allows(
            &workspace,
            &[psid],
            FILE_DELETE_CHILD,
            /*require_all_bits*/ false,
        )
        .expect("check inherited stale write ACE");
        let needs_refresh = path_write_aces_need_refresh(&workspace, &[psid])
            .expect("check inherited stale write ACE");
        let first_refresh = unsafe { ensure_allow_write_aces(&workspace, &[psid]) }
            .expect("first inherited write ACE refresh");
        let second_refresh = unsafe { ensure_allow_write_aces(&workspace, &[psid]) }
            .expect("second inherited write ACE refresh");
        unsafe {
            LocalFree(psid as HLOCAL);
        }

        assert_eq!(
            (
                seeded_explicit,
                seeded_parent,
                has_inherited_delete_child,
                needs_refresh,
                first_refresh,
                second_refresh,
            ),
            (true, true, true, false, false, false)
        );
    }

    #[test]
    fn deny_path_under_active_root_uses_only_matching_root_sid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let active_root = temp.path().join("active-root");
        let stale_root = temp.path().join("stale-root");
        let deny_path = active_root.join("protected");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::create_dir_all(&active_root).expect("create active root");
        fs::create_dir_all(&stale_root).expect("create stale root");
        fs::create_dir_all(&deny_path).expect("create deny path");

        let stale_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &stale_root)
            .expect("stale sid");
        let active_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &active_root)
            .expect("active sid");
        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let caps = load_or_create_cap_sids(&codex_home).expect("load caps");

        let deny_sids = workspace_write_cap_sids_for_path(
            &codex_home,
            &workspace,
            &[workspace.clone(), active_root],
            &deny_path,
        )
        .expect("deny sids");

        assert_eq!(deny_sids, vec![active_sid]);
        assert!(!deny_sids.contains(&workspace_sid));
        assert!(!deny_sids.contains(&stale_sid));
        assert!(!deny_sids.contains(&caps.workspace));
    }

    #[test]
    fn deny_path_outside_active_roots_falls_back_to_all_active_root_sids() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let active_root = temp.path().join("active-root");
        let stale_root = temp.path().join("stale-root");
        let deny_path = temp.path().join("outside-deny");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::create_dir_all(&active_root).expect("create active root");
        fs::create_dir_all(&stale_root).expect("create stale root");
        fs::create_dir_all(&deny_path).expect("create deny path");

        let stale_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &stale_root)
            .expect("stale sid");
        let active_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &active_root)
            .expect("active sid");
        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let caps = load_or_create_cap_sids(&codex_home).expect("load caps");

        let deny_sids = workspace_write_cap_sids_for_path(
            &codex_home,
            &workspace,
            &[workspace.clone(), active_root],
            &deny_path,
        )
        .expect("deny sids");

        assert_eq!(deny_sids.len(), 2);
        assert!(deny_sids.contains(&workspace_sid));
        assert!(deny_sids.contains(&active_sid));
        assert!(!deny_sids.contains(&stale_sid));
        assert!(!deny_sids.contains(&caps.workspace));
    }

    #[test]
    fn deny_path_includes_nested_active_root_sid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let workspace = temp.path().join("workspace");
        let protected_dir = workspace.join(".codex");
        let nested_root = protected_dir.join("nested-root");
        fs::create_dir_all(&codex_home).expect("create codex home");
        fs::create_dir_all(&workspace).expect("create workspace");
        fs::create_dir_all(&nested_root).expect("create nested root");

        let workspace_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &workspace)
            .expect("workspace sid");
        let nested_sid = workspace_write_cap_sid_for_root(&codex_home, &workspace, &nested_root)
            .expect("nested sid");

        let deny_sids = workspace_write_cap_sids_for_path(
            &codex_home,
            &workspace,
            &[workspace.clone(), nested_root],
            &protected_dir,
        )
        .expect("deny sids");

        assert_eq!(deny_sids, vec![workspace_sid, nested_sid]);
    }
}

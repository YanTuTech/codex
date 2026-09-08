//! Repair deny ACLs on objects created by this installation, without new grants.
use super::Payload;
use super::no_reparse_dir::open_existing_no_reparse;
use super::sandbox_users::read_persisted_secrets_if_matching;
use super::sandbox_users::resolve_sid;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use codex_windows_sandbox::add_deny_write_ace_to_handle;
use codex_windows_sandbox::installation::SandboxInstallationIdentity;
use codex_windows_sandbox::to_wide;
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::ImpersonateLoggedOnUser;
use windows_sys::Win32::Security::IsValidSid;
use windows_sys::Win32::Security::LOGON32_LOGON_INTERACTIVE;
use windows_sys::Win32::Security::LOGON32_PROVIDER_DEFAULT;
use windows_sys::Win32::Security::LogonUserW;
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

fn owner(handle: &OwnedHandle) -> Result<Vec<u8>> {
    let mut descriptor = std::ptr::null_mut();
    let mut owner = std::ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            raw(handle),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let result = if code != 0 {
        Err(std::io::Error::from_raw_os_error(code as i32).into())
    } else if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        Err(anyhow::anyhow!("invalid ACL owner"))
    } else {
        Ok(unsafe {
            std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize).to_vec()
        })
    };
    if !descriptor.is_null() {
        unsafe {
            LocalFree(descriptor as HLOCAL);
        }
    }
    result
}

fn file_id(handle: &OwnedHandle) -> Result<(u32, u32, u32)> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { GetFileInformationByHandle(raw(handle), &mut info) } != 0,
        "cannot read ACL object identity"
    );
    ensure!(
        info.nNumberOfLinks == 1,
        "ACL repair rejects hard-linked objects"
    );
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

fn matching_account(owner: &[u8], offline: &[u8], online: &[u8]) -> Result<usize> {
    ensure!(
        !owner.is_empty() && !offline.is_empty() && !online.is_empty() && offline != online,
        "invalid installation account SIDs"
    );
    if owner == offline {
        Ok(0)
    } else if owner == online {
        Ok(1)
    } else {
        bail!("ACL owner is not a current installation account")
    }
}

struct Impersonation;
impl Impersonation {
    fn begin(token: &OwnedHandle) -> Result<Self> {
        let mut previous = 0;
        if unsafe {
            windows_sys::Win32::System::Threading::OpenThreadToken(
                windows_sys::Win32::System::Threading::GetCurrentThread(),
                windows_sys::Win32::Security::TOKEN_QUERY,
                1,
                &mut previous,
            )
        } != 0
        {
            drop(unsafe { OwnedHandle::from_raw_handle(previous as *mut c_void) });
            bail!("ACL repair refuses an existing impersonation context");
        }
        ensure!(
            unsafe { GetLastError() } == windows_sys::Win32::Foundation::ERROR_NO_TOKEN,
            "cannot verify host thread identity"
        );
        if unsafe { ImpersonateLoggedOnUser(raw(token)) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot impersonate installation owner");
        }
        Ok(Self)
    }
}
impl Drop for Impersonation {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

/// Caller provides a policy-derived path and valid capability SID.
pub(super) unsafe fn protect(
    path: &Path,
    capability: *mut c_void,
    payload: &Payload,
    identity: &SandboxInstallationIdentity,
) -> Result<bool> {
    match open_existing_no_reparse(path, READ_CONTROL | WRITE_DAC) {
        Ok(handle) => {
            file_id(&handle)?;
            return unsafe { add_deny_write_ace_to_handle(raw(&handle), capability) };
        }
        Err(error) => {
            let denied = error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.raw_os_error() == Some(5))
            });
            if !denied {
                return Err(error);
            }
        }
    }
    ensure!(
        payload
            .write_roots
            .iter()
            .any(|root| codex_windows_sandbox::workspace_write_root_contains_path(root, path)),
        "ACL repair target is outside writable roots"
    );
    let pinned = open_existing_no_reparse(path, READ_CONTROL)?;
    let expected_file = file_id(&pinned)?;
    let expected_owner = owner(&pinned)?;
    let offline_name = identity.offline_username();
    let online_name = identity.online_username();
    let offline_sid = resolve_sid(&offline_name)?;
    let online_sid = resolve_sid(&online_name)?;
    let account = matching_account(&expected_owner, &offline_sid, &online_sid)?;
    let (offline_password, online_password) =
        read_persisted_secrets_if_matching(&payload.codex_home, &offline_name, &online_name)
            .context("current installation credentials unavailable for ACL repair")?;
    let (username, password) = if account == 0 {
        (&offline_name, &offline_password)
    } else {
        (&online_name, &online_password)
    };
    let user_w = to_wide(username);
    let mut password_w = to_wide(password);
    let domain = to_wide(".");
    let mut token = 0;
    let logged_on = unsafe {
        LogonUserW(
            user_w.as_ptr(),
            domain.as_ptr(),
            password_w.as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    let logon_error = if logged_on == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    password_w.fill(0);
    if logged_on == 0 {
        return Err(std::io::Error::from_raw_os_error(logon_error as i32))
            .context("installation owner logon failed");
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as *mut c_void) };
    let result = {
        let _impersonation = Impersonation::begin(&token)?;
        let handle = open_existing_no_reparse(path, READ_CONTROL | WRITE_DAC)?;
        ensure!(
            file_id(&handle)? == expected_file,
            "ACL object replaced before repair"
        );
        ensure!(
            owner(&handle)? == expected_owner,
            "ACL owner changed before repair"
        );
        unsafe { add_deny_write_ace_to_handle(raw(&handle), capability) }
    };
    codex_windows_sandbox::log_note(
        "ACL recovery: matched installation owner; scoped deny propagation finished; host identity restored",
        Some(&payload.codex_home.join(".sandbox")),
    );
    result
}

#[cfg(test)]
#[path = "ls_owned_acl_tests.rs"]
mod tests;

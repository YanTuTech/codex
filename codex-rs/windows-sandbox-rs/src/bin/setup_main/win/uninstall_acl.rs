//! Precise ACE removal for sandbox uninstall.
//!
//! Uninstall removes only the allow ACEs whose trustee is this
//! installation's sandbox group (or a capability SID minted under its state
//! root) from the roots the setup marker recorded. The rest of each DACL is
//! rebuilt verbatim; no wholesale ACL snapshot is ever restored, so user
//! changes made after setup survive uninstall.

use std::ffi::OsStr;
use std::ffi::c_void;
use std::path::Path;

use anyhow::Result;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::ACL_REVISION;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AddAce;
use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::EqualSid;
use windows_sys::Win32::Security::GetAce;
use windows_sys::Win32::Security::GetAclInformation;
use windows_sys::Win32::Security::InitializeAcl;

use codex_windows_sandbox::to_wide;

/// Replacement DACL backed by an owned buffer. The Windows ACL APIs work on
/// raw pointers, so the buffer must outlive every call that receives the
/// pointer; this type makes that lifetime explicit instead of returning a
/// pointer into dropped stack storage (a use-after-free in the previous
/// revision).
pub struct OwnedAcl {
    buffer: Vec<u8>,
}

impl OwnedAcl {
    fn as_mut_ptr(&mut self) -> *mut ACL {
        self.buffer.as_mut_ptr() as *mut ACL
    }
}

/// Removes every allow ACE granted to `group_sid` from the DACL of `path`.
/// Deny ACEs and every ACE belonging to other trustees are copied unchanged.
pub fn remove_group_allow_aces(path: &Path, group_sid: &[u8]) -> Result<bool> {
    unsafe {
        let path_w = to_wide(OsStr::new(path));
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: *mut c_void = std::ptr::null_mut();
        let result = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if result != ERROR_SUCCESS {
            anyhow::bail!("GetNamedSecurityInfoW({}) failed: {result}", path.display());
        }
        let cleanup = |sd: *mut c_void| {
            if !sd.is_null() {
                LocalFree(sd as _);
            }
        };
        if dacl.is_null() {
            cleanup(sd);
            return Ok(false);
        }
        let mut rebuilt = rebuild_dacl_without_group(dacl, group_sid);
        let outcome = match rebuilt {
            Ok(Some(ref mut new_dacl)) => {
                let set_result = SetNamedSecurityInfoW(
                    path_w.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    new_dacl.as_mut_ptr(),
                    std::ptr::null_mut(),
                );
                if set_result != 0 {
                    Err(anyhow::anyhow!(
                        "SetNamedSecurityInfoW({}) failed: {set_result}",
                        path.display()
                    ))
                } else {
                    Ok(true)
                }
            }
            Ok(None) => Ok(false),
            Err(err) => Err(err),
        };
        cleanup(sd);
        outcome
    }
}

unsafe fn rebuild_dacl_without_group(dacl: *mut ACL, group_sid: &[u8]) -> Result<Option<OwnedAcl>> {
    unsafe {
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        if GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            2, // AclSizeInformation
        ) == 0
        {
            anyhow::bail!("GetAclInformation failed");
        }

        // Size the replacement ACL like the original: it can only shrink, so the
        // original byte budget is a safe upper bound.
        let acl_bytes = info.AclBytesInUse as usize;
        let mut buffer = vec![0u8; acl_bytes.max(64)];
        let new_acl = buffer.as_mut_ptr() as *mut ACL;
        if InitializeAcl(new_acl, acl_bytes as u32, ACL_REVISION) == 0 {
            anyhow::bail!("InitializeAcl failed");
        }

        let group_psid = group_sid.as_ptr() as *mut c_void;
        let mut removed = false;
        for index in 0..info.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            if GetAce(dacl, index, &mut ace) == 0 {
                anyhow::bail!("GetAce({index}) failed");
            }
            // ACCESS_ALLOWED_ACE layout: header (type, flags, size), Mask, SidStart.
            let ace_ptr = ace as *const u8;
            let ace_type = *ace_ptr;
            let ace_size = *((ace_ptr.add(2)) as *const u16) as usize;
            let sid_start = ace_ptr.add(8) as *mut c_void;
            let is_allow_for_group = ace_type == 0 /* ACCESS_ALLOWED_ACE_TYPE */
            && EqualSid(sid_start, group_psid) != 0;
            if is_allow_for_group {
                removed = true;
                continue;
            }
            if AddAce(new_acl, ACL_REVISION, u32::MAX, ace, ace_size as u32) == 0 {
                anyhow::bail!("AddAce({index}) failed");
            }
        }
        if removed {
            Ok(Some(OwnedAcl { buffer }))
        } else {
            Ok(None)
        }
    }
}

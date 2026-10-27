//! Bounded parsing of the single ALE_USER_ID match trustee.
use super::pwstr_to_string;
use anyhow::Result;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTRL_MATCH_FILTER, FWP_BYTE_BLOB,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, GetAce, IsValidSid, SE_SELF_RELATIVE, SECURITY_DESCRIPTOR_RELATIVE,
    SID,
};

pub(super) fn condition_user_sid(blob: &FWP_BYTE_BLOB) -> Result<String> {
    use std::mem::{offset_of, size_of};
    if blob.data.is_null() || (blob.size as usize) < size_of::<SECURITY_DESCRIPTOR_RELATIVE>() {
        anyhow::bail!("missing user security descriptor");
    }
    unsafe {
        let descriptor = &*blob.data.cast::<SECURITY_DESCRIPTOR_RELATIVE>();
        let offset = descriptor.Dacl as usize;
        let size = blob.size as usize;
        if descriptor.Control & SE_SELF_RELATIVE == 0
            || offset < size_of::<SECURITY_DESCRIPTOR_RELATIVE>()
            || offset > size
            || size - offset < size_of::<ACL>()
        {
            anyhow::bail!("invalid user condition DACL offset");
        }
        let acl = blob.data.add(offset).cast::<ACL>();
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if (*acl).AceCount != 1
            || usize::from((*acl).AclSize) > size - offset
            || usize::from((*acl).AclSize) < size_of::<ACL>() + sid_offset + 8
        {
            anyhow::bail!("user condition must contain exactly one bounded match ACE");
        }
        let mut raw_ace = null_mut();
        if GetAce(acl, 0, &mut raw_ace) == 0 || raw_ace.is_null() {
            anyhow::bail!("cannot read user match ACE");
        }
        let ace = &*raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        if ace.Header.AceType != 0
            || ace.Mask != FWP_ACTRL_MATCH_FILTER
            || usize::from(ace.Header.AceSize) > usize::from((*acl).AclSize) - size_of::<ACL>()
            || usize::from(ace.Header.AceSize) < sid_offset + 8
        {
            anyhow::bail!("invalid user match ACE");
        }
        let trustee = std::ptr::addr_of!(ace.SidStart).cast::<SID>();
        if 8 + 4 * usize::from((*trustee).SubAuthorityCount)
            > usize::from(ace.Header.AceSize) - sid_offset
            || IsValidSid(trustee as *mut core::ffi::c_void) == 0
        {
            anyhow::bail!("invalid match trustee SID");
        }
        let mut text = null_mut();
        if ConvertSidToStringSidW(trustee as *mut core::ffi::c_void, &mut text) == 0
            || text.is_null()
        {
            anyhow::bail!("cannot render user SID");
        }
        let sid = pwstr_to_string(text);
        LocalFree(text as HLOCAL);
        Ok(sid)
    }
}

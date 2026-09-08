//! Read-only access for the unelevated Host to its own WFP evidence.

use anyhow::Result;
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTRL_READ;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;

pub(super) struct LsReadbackSecurity {
    pub(super) descriptor: PSECURITY_DESCRIPTOR,
}

impl LsReadbackSecurity {
    pub(super) fn for_reader(reader: &str) -> Result<Self> {
        let sid = crate::winutil::resolve_sid(reader)?;
        let sid = crate::winutil::string_from_sid_bytes(&sid).map_err(anyhow::Error::msg)?;
        // Administrators own the objects. The Host gets READ only, never
        // DELETE, WRITE_DAC, WRITE_OWNER, ADD_LINK, or container permissions.
        let sddl = crate::to_wide(format!(
            "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;{FWPM_ACTRL_READ:#x};;;{sid})"
        ));
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { descriptor })
    }
}

impl Drop for LsReadbackSecurity {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.descriptor as HLOCAL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    };

    #[test]
    fn reader_is_not_owner_and_only_receives_wfp_read() {
        let descriptor = LsReadbackSecurity::for_reader("Everyone").expect("reader descriptor");
        let reader = crate::winutil::resolve_sid("Everyone").expect("reader SID");
        let admins = crate::winutil::resolve_sid("Administrators").expect("owner SID");
        unsafe {
            let mut owner = std::ptr::null_mut();
            let mut defaulted = 0;
            assert_ne!(
                GetSecurityDescriptorOwner(descriptor.descriptor, &mut owner, &mut defaulted),
                0
            );
            assert_ne!(EqualSid(owner, admins.as_ptr() as *mut _), 0);
            let mut acl = std::ptr::null_mut();
            let mut present = 0;
            assert_ne!(
                GetSecurityDescriptorDacl(
                    descriptor.descriptor,
                    &mut present,
                    &mut acl,
                    &mut defaulted
                ),
                0
            );
            assert_ne!(present, 0);
            let mut rights = Vec::new();
            for index in 0..u32::from((*acl).AceCount) {
                let mut raw = std::ptr::null_mut();
                assert_ne!(GetAce(acl, index, &mut raw), 0);
                let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                let sid = std::ptr::addr_of!(ace.SidStart) as *mut _;
                if EqualSid(sid, reader.as_ptr() as *mut _) != 0 {
                    rights.push(ace.Mask);
                }
            }
            assert_eq!(rights, vec![FWPM_ACTRL_READ]);
        }
    }

    #[test]
    fn unknown_reader_does_not_fall_back_to_broad_access() {
        assert!(LsReadbackSecurity::for_reader("LsMissingReader-8ea20a0f").is_err());
    }
}

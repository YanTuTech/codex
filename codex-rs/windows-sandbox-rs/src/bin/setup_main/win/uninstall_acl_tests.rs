//! Regression tests for the uninstall ACL surgery. The previous revision
//! returned a naked pointer into a dropped buffer (a use-after-free); the
//! owned-buffer revision must both survive the Windows ACL calls and remove
//! exactly the targeted trustee's allow ACEs while preserving every other
//! ACE.

use super::resolve_sid;
use super::uninstall_acl::remove_group_allow_aces;

/// Reads the DACL of `path` and returns the set of trustee SIDs holding
/// ACCESS_ALLOWED ACEs.
fn allowed_trustees(path: &std::path::Path) -> Vec<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::ACL;
    use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Security::GetAce;
    use windows_sys::Win32::Security::GetAclInformation;

    unsafe {
        let path_w: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
        let code = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        assert_eq!(code, ERROR_SUCCESS, "GetNamedSecurityInfoW failed: {code}");
        let mut trustees = Vec::new();
        if !dacl.is_null() {
            let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                2,
            );
            for index in 0..info.AceCount {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, index, &mut ace) == 0 {
                    break;
                }
                let ace_ptr = ace as *const u8;
                let ace_type = *ace_ptr;
                if ace_type != 0 {
                    continue;
                }
                let sid_start = ace_ptr.add(8) as *mut core::ffi::c_void;
                let mut sid_string: *mut u16 = std::ptr::null_mut();
                ConvertSidToStringSidW(sid_start, &mut sid_string);
                if sid_string.is_null() {
                    continue;
                }
                let mut length = 0usize;
                while *sid_string.add(length) != 0 {
                    length += 1;
                }
                let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, length));
                LocalFree(sid_string as _);
                trustees.push(text);
            }
        }
        LocalFree(sd as _);
        trustees
    }
}

#[test]
fn removes_only_the_targeted_group_allow_aces() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("victim.txt");
    std::fs::write(&file, b"content").expect("write victim");

    // Grant two distinct trustees allow ACEs: "Everyone" plays the targeted
    // sandbox group, "Users" must survive the surgery.
    let everyone = resolve_sid("Everyone").expect("resolve Everyone SID");
    let users = resolve_sid("Users").expect("resolve Users SID");
    grant_allow_ace(&file, &everyone);
    grant_allow_ace(&file, &users);

    let before = allowed_trustees(&file);
    assert!(
        before.iter().any(|sid| sid.starts_with("S-1-1-0")),
        "Everyone ACE present"
    );
    assert!(
        before.iter().any(|sid| sid.starts_with("S-1-5-32-545")),
        "Users ACE present"
    );

    let removed = remove_group_allow_aces(&file, &everyone).expect("remove group ACEs");
    assert!(removed, "the targeted ACE removal must report a change");

    let after = allowed_trustees(&file);
    assert!(
        !after.iter().any(|sid| sid.starts_with("S-1-1-0")),
        "Everyone ACE must be gone; DACL now: {after:?}"
    );
    assert!(
        after.iter().any(|sid| sid.starts_with("S-1-5-32-545")),
        "Users ACE must survive; DACL now: {after:?}"
    );
}

#[test]
fn removing_an_absent_trustee_is_a_no_op() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("plain.txt");
    std::fs::write(&file, b"content").expect("write plain");
    let before = allowed_trustees(&file);
    let users = resolve_sid("Users").expect("resolve Users SID");
    // "Users" may already hold an inherited ACE; use a trustee we did not
    // grant explicitly: the Guests group.
    let guests = resolve_sid("Guests").expect("resolve Guests SID");
    let _ = users;
    let removed = remove_group_allow_aces(&file, &guests).expect("no-op removal");
    assert!(!removed, "no explicit ACE means no rewrite");
    let after = allowed_trustees(&file);
    assert_eq!(before, after, "DACL must be byte-identical");
}

/// Adds an explicit ACCESS_ALLOWED ACE for `sid` via SetEntriesInAclW.
fn grant_allow_ace(path: &std::path::Path, sid: &[u8]) {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
    use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
    use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
    use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    unsafe {
        use super::sandbox_users::sid_bytes_to_psid;
        use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
        // Read the existing DACL so the grant merges instead of replacing.
        let path_w0: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut existing: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
        let mut sd0: *mut core::ffi::c_void = std::ptr::null_mut();
        let code = GetNamedSecurityInfoW(
            path_w0.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut existing,
            std::ptr::null_mut(),
            &mut sd0,
        );
        assert_eq!(code, 0, "read existing DACL failed: {code}");
        let psid = sid_bytes_to_psid(sid).expect("sid to psid");
        let trustee = TRUSTEE_W {
            ptstrName: psid as *mut u16,
            TrusteeType: TRUSTEE_IS_SID,
            ..std::mem::zeroed()
        };
        let entries = [EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: trustee,
        }];
        let mut new_dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
        let result = SetEntriesInAclW(1, entries.as_ptr(), existing, &mut new_dacl);
        assert_eq!(result, 0, "SetEntriesInAclW failed: {result}");
        let path_w: Vec<u16> = path
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let set = SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        );
        LocalFree(new_dacl as _);
        LocalFree(psid);
        LocalFree(sd0 as _);
        assert_eq!(set, 0, "SetNamedSecurityInfoW failed: {set}");
    }
}

#[test]
fn missing_recorded_acl_roots_are_already_absent() {
    let temp = tempfile::tempdir().expect("temporary root");
    let sid = resolve_sid("Everyone").expect("test trustee");
    for path in [
        temp.path().join("missing"),
        temp.path().join("missing").join("child"),
    ] {
        assert!(
            !remove_group_allow_aces(&path, &sid).expect("an absent object has no ACE to remove")
        );
    }
}

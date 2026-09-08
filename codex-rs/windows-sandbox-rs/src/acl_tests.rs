use super::acl_api_result;
use pretty_assertions::assert_eq;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

#[test]
fn deny_ace_update_failure_is_an_error() {
    let path = std::path::Path::new(r"C:\world-writable");
    let error = acl_api_result(path, "SetNamedSecurityInfoW", ERROR_ACCESS_DENIED)
        .expect_err("access denied must not look like an already-present ACE");

    assert_eq!(
        error.to_string(),
        r"SetNamedSecurityInfoW failed for C:\world-writable: 5"
    );
}

#[test]
fn deny_write_still_allows_read_on_existing_file() {
    use std::ffi::c_void;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Foundation::HLOCAL;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::CreateRestrictedToken;
    use windows_sys::Win32::Security::ImpersonateLoggedOnUser;
    use windows_sys::Win32::Security::RevertToSelf;
    use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
    use windows_sys::Win32::Security::TOKEN_ASSIGN_PRIMARY;
    use windows_sys::Win32::Security::TOKEN_DUPLICATE;
    use windows_sys::Win32::Security::TOKEN_IMPERSONATE;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("canary");
    std::fs::write(&file, b"original").unwrap();
    let sid = unsafe { crate::convert_string_sid_to_sid("S-1-5-12") }.unwrap();
    unsafe { super::add_allow_ace(&file, sid) }.unwrap();
    let handle = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .open(&file)
        .unwrap();
    unsafe { super::add_deny_write_ace_to_handle(handle.as_raw_handle() as HANDLE, sid) }.unwrap();
    drop(handle);
    let mut primary = 0;
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE,
                &mut primary,
            )
        },
        0
    );
    let primary = unsafe { OwnedHandle::from_raw_handle(primary as *mut c_void) };
    let restricted_sid = SID_AND_ATTRIBUTES {
        Sid: sid,
        Attributes: 0,
    };
    let mut restricted = 0;
    assert_ne!(
        unsafe {
            CreateRestrictedToken(
                primary.as_raw_handle() as HANDLE,
                0x01 | 0x04 | 0x08,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &restricted_sid,
                &mut restricted,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    let restricted = unsafe { OwnedHandle::from_raw_handle(restricted as *mut c_void) };
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    let (read, write) = {
        assert_ne!(
            unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle() as HANDLE) },
            0
        );
        let _restore = Restore;
        (std::fs::read(&file), std::fs::write(&file, b"forbidden"))
    };
    drop(restricted);
    unsafe {
        LocalFree(sid as HLOCAL);
    }
    assert_eq!(read.unwrap(), b"original");
    assert_eq!(
        write.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(std::fs::read(file).unwrap(), b"original");
}

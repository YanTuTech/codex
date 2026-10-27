use super::*;

#[test]
fn rejects_foreign_and_ambiguous_owner_before_loading_credentials() {
    assert!(matching_account(&[3], &[1], &[2]).is_err());
    assert!(matching_account(&[1], &[1], &[1]).is_err());
    assert!(matching_account(&[], &[1], &[2]).is_err());
    assert_eq!(matching_account(&[1], &[1], &[2]).unwrap(), 0);
    assert_eq!(matching_account(&[2], &[1], &[2]).unwrap(), 1);
}

#[test]
fn existing_open_never_creates_a_missing_object() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(open_existing_no_reparse(&missing, READ_CONTROL).is_err());
    assert!(!missing.exists());
}

#[test]
fn pinned_object_cannot_be_renamed_and_hardlinks_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("file");
    std::fs::write(&file, b"canary").unwrap();
    let pinned = open_existing_no_reparse(&file, READ_CONTROL).unwrap();
    assert!(!owner(&pinned).unwrap().is_empty());
    assert!(std::fs::rename(&file, root.path().join("replaced")).is_err());
    let expected = file_id(&pinned).unwrap();
    assert_eq!(file_id(&pinned).unwrap(), expected);
    drop(pinned);
    std::fs::hard_link(&file, root.path().join("link")).unwrap();
    let linked = open_existing_no_reparse(&file, READ_CONTROL).unwrap();
    assert!(file_id(&linked).is_err());
}

#[test]
fn existing_open_rejects_junction_ancestors() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    let alias = root.path().join("alias");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("file"), b"canary").unwrap();
    let result = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&alias)
        .arg(&target)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(open_existing_no_reparse(&alias.join("file"), READ_CONTROL).is_err());
    std::fs::remove_dir(alias).unwrap();
}

#[test]
fn invalid_token_cannot_enter_impersonation_scope() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("file");
    std::fs::write(&file, b"canary").unwrap();
    let file_handle = open_existing_no_reparse(&file, READ_CONTROL).unwrap();
    assert!(Impersonation::begin(&file_handle).is_err());
    assert_eq!(std::fs::read(file).unwrap(), b"canary");
}

#[test]
fn impersonation_rejects_nesting_and_restores_host_on_error() {
    use windows_sys::Win32::Security::TOKEN_DUPLICATE;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::System::Threading::GetCurrentThread;
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    use windows_sys::Win32::System::Threading::OpenThreadToken;
    let mut token = 0;
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut token,
            )
        },
        0
    );
    let token = unsafe { OwnedHandle::from_raw_handle(token as *mut c_void) };
    let failure = (|| -> Result<()> {
        let _scope = Impersonation::begin(&token)?;
        assert!(Impersonation::begin(&token).is_err());
        let mut thread_token = 0;
        assert_ne!(
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) },
            0
        );
        drop(unsafe { OwnedHandle::from_raw_handle(thread_token as *mut c_void) });
        bail!("injected failure after impersonation")
    })();
    assert!(failure.is_err());
    let mut thread_token = 0;
    assert_eq!(
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) },
        0
    );
    assert_eq!(
        unsafe { GetLastError() },
        windows_sys::Win32::Foundation::ERROR_NO_TOKEN
    );
}

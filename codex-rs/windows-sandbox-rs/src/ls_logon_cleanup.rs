//! Exact cleanup of the two installation-owned Winlogon visibility values.

use crate::installation::SandboxInstallationIdentity;
use anyhow::Result;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, RegCloseKey, RegDeleteValueW,
    RegOpenKeyExW, RegQueryValueExW,
};

struct LsUserListKey(HKEY);
impl Drop for LsUserListKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn open_userlist(access: u32) -> Result<Option<LsUserListKey>> {
    let path = crate::to_wide(crate::hide_users::USERLIST_KEY_PATH);
    let mut key = 0;
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, access, &mut key) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        anyhow::bail!("open UserList failed: {status}");
    }
    Ok(Some(LsUserListKey(key)))
}

fn present_values(key: HKEY, names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter_map(|name| {
            let wide = crate::to_wide(name);
            let mut size = 0;
            let mut kind = 0;
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    wide.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            (status != ERROR_FILE_NOT_FOUND).then(|| format!("winlogon:{name}"))
        })
        .collect()
}

fn remove_values(key: HKEY, names: &[String]) -> Result<()> {
    for name in names {
        let wide = crate::to_wide(name);
        let status = unsafe { RegDeleteValueW(key, wide.as_ptr()) };
        if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
            anyhow::bail!("remove UserList value {name} failed: {status}");
        }
    }
    Ok(())
}

/// Removes only this identity's visibility values, never the shared key.
pub fn remove_installation_logon_entries(identity: &SandboxInstallationIdentity) -> Result<()> {
    if let Some(key) = open_userlist(KEY_SET_VALUE)? {
        remove_values(
            key.0,
            &[identity.offline_username(), identity.online_username()],
        )?;
    }
    Ok(())
}

/// Query failures remain visible and cannot be interpreted as absence.
pub fn installation_logon_entries_present(identity: &SandboxInstallationIdentity) -> Vec<String> {
    match open_userlist(KEY_QUERY_VALUE) {
        Ok(Some(key)) => present_values(
            key.0,
            &[identity.offline_username(), identity.online_username()],
        ),
        Ok(None) => Vec::new(),
        Err(_) => vec!["winlogon:query-failed".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_DWORD, RegCreateKeyExW, RegDeleteTreeW,
        RegSetValueExW,
    };

    struct TestKey {
        key: HKEY,
        path: Vec<u16>,
    }
    impl Drop for TestKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.key);
                RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr());
            }
        }
    }

    #[test]
    fn cleanup_preserves_unrelated_values_and_is_idempotent() {
        let identity = SandboxInstallationIdentity::generate();
        let path = crate::to_wide(format!(
            r"Software\LeapSeaSandboxTest-{}",
            identity.install_id_hex()
        ));
        let mut key = 0;
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_ALL_ACCESS,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, 0);
        let _guard = TestKey { key, path };
        let owned = vec![identity.offline_username(), identity.online_username()];
        let unrelated = vec!["unrelated-test-value".to_string()];
        for name in owned.iter().chain(&unrelated) {
            let name = crate::to_wide(name);
            let value = 0_u32;
            assert_eq!(
                unsafe {
                    RegSetValueExW(
                        key,
                        name.as_ptr(),
                        0,
                        REG_DWORD,
                        (&value as *const u32).cast(),
                        4,
                    )
                },
                0
            );
        }
        assert_eq!(present_values(key, &owned).len(), 2);
        remove_values(key, &owned).expect("remove only owned values");
        assert!(present_values(key, &owned).is_empty());
        assert_eq!(
            present_values(key, &unrelated),
            vec!["winlogon:unrelated-test-value"]
        );
        remove_values(key, &owned).expect("idempotent removal");
    }
}

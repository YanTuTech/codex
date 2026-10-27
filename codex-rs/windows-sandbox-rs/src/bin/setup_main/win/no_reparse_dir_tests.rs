use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::Result;
use pretty_assertions::assert_eq;
use windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE;
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

use super::is_disk_volume;
use super::local_path_nt_path;
use super::open_existing_no_reparse;
use super::open_or_create_no_reparse;

fn create_directory_junction(target: &Path, alias: &Path) -> Result<()> {
    let output = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(alias)
        .arg(target)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[test]
fn creates_and_opens_plain_directory_leaf() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join(".sandbox-bin");

    drop(open_or_create_no_reparse(&directory)?);
    let _handle = open_or_create_no_reparse(&directory)?;

    assert!(directory.is_dir());
    Ok(())
}

#[test]
fn drive_paths_resolve_only_the_volume_alias() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().canonicalize()?;
    let root = directory
        .ancestors()
        .last()
        .expect("absolute path has a root");
    let ordinary = root
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_owned();
    let drive: Vec<_> = ordinary.encode_utf16().take(2).chain(Some(0)).collect();
    let mut device = vec![0; 32_768];
    if unsafe { QueryDosDeviceW(drive.as_ptr(), device.as_mut_ptr(), device.len() as u32) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    device.truncate(
        device
            .iter()
            .position(|unit| *unit == 0)
            .expect("NUL-terminated device"),
    );
    assert!(is_disk_volume(&device));
    for path in [root, Path::new(&ordinary)] {
        for suffix in ["", "missing-no-reparse-test"] {
            let mut expected = device.clone();
            expected.extend(format!(r"\{suffix}").encode_utf16());
            expected.push(0);
            assert_eq!(local_path_nt_path(&path.join(suffix))?, expected);
        }
        drop(open_existing_no_reparse(path, FILE_TRAVERSE)?);
    }
    Ok(())
}

#[test]
fn disk_volume_mapping_excludes_other_devices_and_subpaths() {
    for accepted in [
        r"\Device\HarddiskVolume0",
        r"\Device\HarddiskVolume1",
        r"\device\harddiskvolume123",
    ] {
        assert!(is_disk_volume(&accepted.encode_utf16().collect::<Vec<_>>()));
    }
    for rejected in [
        r"\Device\NamedPipe",
        r"\Device\NamedPipe\pipe",
        r"\Device\HarddiskVolume",
        r"\Device\HarddiskVolume1\directory",
        r"\Device\HarddiskVolume1suffix",
        r"\Device\HarddiskVolumeShadowCopy1",
        r"\Device\CdRom0",
        r"\??\C:\directory",
    ] {
        assert!(
            !is_disk_volume(&rejected.encode_utf16().collect::<Vec<_>>()),
            "accepted {rejected}"
        );
    }
}

#[test]
fn rejects_final_directory_junction() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let target = temporary.path().join("target");
    let alias = temporary.path().join(".sandbox-bin");
    fs::create_dir(&target)?;
    create_directory_junction(&target, &alias)?;

    let _ =
        open_or_create_no_reparse(&alias).expect_err("final directory junction must be rejected");
    fs::remove_dir(&alias)?;
    Ok(())
}

#[test]
fn rejects_ancestor_directory_junction() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let target_home = temporary.path().join("target-home");
    let alias_home = temporary.path().join("linked-home");
    fs::create_dir(&target_home)?;
    fs::create_dir(target_home.join(".sandbox-bin"))?;
    create_directory_junction(&target_home, &alias_home)?;

    let _ = open_or_create_no_reparse(&alias_home.join(".sandbox-bin"))
        .expect_err("ancestor directory junction must be rejected");
    fs::remove_dir(&alias_home)?;
    Ok(())
}

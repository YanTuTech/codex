//! Native command-line regressions; no sandbox setup or machine resources.

#![allow(clippy::expect_used)] // Test setup failures must fail the native regression.

use super::argv_to_command_line;
use pretty_assertions::assert_eq;
use std::os::windows::process::CommandExt;
use std::process::Command;

#[test]
fn cmd_script_preserves_quoted_unicode_and_space_paths() {
    let root = tempfile::tempdir().expect("temporary workspace");
    let workspace = root.path().join("中文 workspace");
    std::fs::create_dir(&workspace).expect("workspace");
    let exe = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join("cmd.exe");
    let script = ">\"中文 文件.txt\" echo ls-nonce&& type \"中文 文件.txt\"";
    let argv = vec![
        exe.to_string_lossy().into_owned(),
        "/d".into(),
        "/c".into(),
        script.into(),
    ];
    let line = argv_to_command_line(&argv);
    let prefix = super::quote_windows_arg(&argv[0]);
    let output = Command::new(&exe)
        .raw_arg(
            line.strip_prefix(&format!("{prefix} "))
                .expect("command tail"),
        )
        .current_dir(&workspace)
        .creation_flags(0x08000000)
        .output()
        .expect("launch cmd");
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert_eq!(
        std::fs::read(workspace.join("中文 文件.txt")).expect("artifact"),
        b"ls-nonce\r\n"
    );
    assert_eq!(output.stdout, b"ls-nonce\r\n");
}

#[test]
fn cmd_script_preserves_quoted_executable_and_redirection() {
    let workspace = tempfile::tempdir().expect("workspace");
    let exe = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join("cmd.exe");
    let script = format!(
        "\"{}\" /d /c echo nested>\"nested file.txt\"",
        exe.display()
    );
    let argv = vec![
        "CMD.EXE".into(),
        "/D".into(),
        "/S".into(),
        "/C".into(),
        script,
    ];
    let line = argv_to_command_line(&argv);
    let output = Command::new(&exe)
        .raw_arg(line.strip_prefix("CMD.EXE ").expect("command tail"))
        .current_dir(workspace.path())
        .creation_flags(0x08000000)
        .output()
        .expect("launch cmd");
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    assert_eq!(
        std::fs::read(workspace.path().join("nested file.txt")).expect("artifact"),
        b"nested\r\n"
    );
}

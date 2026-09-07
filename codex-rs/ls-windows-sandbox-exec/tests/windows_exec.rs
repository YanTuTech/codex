//! CLI and runner-contract tests for `ls-windows-sandbox-exec`.
//!
//! The runner contract is frozen: exactly one canonical workspace root, one
//! canonical sandbox state directory, an optional positive `--timeout-ms`,
//! and the command after `--`. Anything else — writable-root overrides,
//! policy JSON, network flags, environment overrides — must be rejected as
//! unknown arguments, and every runner-own failure must be a single
//! `LS_WINDOWS_SANDBOX_UNAVAILABLE:<reason>` stderr line with exit 250.
//!
//! The `containment_matrix` module additionally runs the native Windows
//! containment matrix against the real sandbox.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

const RUNNER_FAILURE_EXIT_CODE: i32 = 250;
const RUNNER_FAILURE_MARKER: &str = "LS_WINDOWS_SANDBOX_UNAVAILABLE";
const TIMEOUT_EXIT_CODE: i32 = 124;

fn runner() -> &'static str {
    env!("CARGO_BIN_EXE_ls-windows-sandbox-exec")
}

#[allow(clippy::unwrap_used)] // test scaffolding: a failed spawn is the assertion
fn run_runner(args: &[&str]) -> Output {
    Command::new(runner()).args(args).output().unwrap()
}

fn assert_runner_failure(output: &Output, expected_fragment: &str) {
    assert_eq!(
        output.status.code(),
        Some(RUNNER_FAILURE_EXIT_CODE),
        "runner-own failures must exit 250; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stderr.trim_end_matches(['\n', '\r']);
    assert!(
        line.starts_with(&format!("{RUNNER_FAILURE_MARKER}:")),
        "failure output must be a single {RUNNER_FAILURE_MARKER} line; got: {stderr:?}"
    );
    // Exactly one stderr line: no embedded newline before the trailing one.
    let trimmed = stderr.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "failure reason must stay on a single line; got: {stderr:?}"
    );
    assert!(
        line.contains(expected_fragment),
        "failure reason must mention {expected_fragment:?}; got: {line:?}"
    );
}

/// A canonical temporary directory usable as `--workspace-root`.
#[allow(clippy::unwrap_used)] // test scaffolding: a failed tempdir is the assertion
fn canonical_temp_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let canonical = dunce::canonicalize(dir.path()).unwrap();
    (dir, canonical)
}

fn root_and_home() -> (tempfile::TempDir, PathBuf, tempfile::TempDir, PathBuf) {
    let (workspace, workspace_root) = canonical_temp_dir();
    let (home, codex_home) = canonical_temp_dir();
    (workspace, workspace_root, home, codex_home)
}

fn valid_prefix(workspace_root: &Path, codex_home: &Path) -> Vec<String> {
    vec![
        "--workspace-root".to_string(),
        workspace_root.as_os_str().to_string_lossy().to_string(),
        "--codex-home".to_string(),
        codex_home.as_os_str().to_string_lossy().to_string(),
    ]
}

#[test]
fn missing_workspace_root_flag_is_rejected() {
    let (_home, codex_home) = canonical_temp_dir();
    let args = [
        "--codex-home".to_string(),
        codex_home.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--workspace-root");
}

#[test]
fn missing_codex_home_flag_is_rejected() {
    let (_workspace, workspace_root) = canonical_temp_dir();
    let args = [
        "--workspace-root".to_string(),
        workspace_root.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--codex-home");
}

#[test]
fn missing_separator_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let args = [
        "--workspace-root".to_string(),
        workspace_root.to_string_lossy().to_string(),
        "--codex-home".to_string(),
        codex_home.to_string_lossy().to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "separator");
}

#[test]
fn duplicate_workspace_root_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--workspace-root".to_string());
    args.push(workspace_root.to_string_lossy().to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "duplicate");
}

#[test]
fn duplicate_codex_home_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--codex-home".to_string());
    args.push(codex_home.to_string_lossy().to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "duplicate");
}

#[test]
fn duplicate_timeout_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--timeout-ms".to_string());
    args.push("1000".to_string());
    args.push("--timeout-ms".to_string());
    args.push("2000".to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "duplicate");
}

#[test]
fn relative_workspace_root_is_rejected() {
    let (_home, codex_home) = canonical_temp_dir();
    let args = [
        "--workspace-root".to_string(),
        "relative-nonexistent-root".to_string(),
        "--codex-home".to_string(),
        codex_home.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--workspace-root");
}

#[test]
fn missing_workspace_root_directory_is_rejected() {
    let outer = tempfile::tempdir().unwrap();
    let missing = outer.path().join("does-not-exist");
    let (_home, codex_home) = canonical_temp_dir();
    let args = [
        "--workspace-root".to_string(),
        missing.to_string_lossy().to_string(),
        "--codex-home".to_string(),
        codex_home.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--workspace-root");
}

#[test]
fn file_workspace_root_is_rejected() {
    let outer = tempfile::tempdir().unwrap();
    let file_path = outer.path().join("a-file");
    std::fs::write(&file_path, b"x").unwrap();
    let file_path = dunce::canonicalize(&file_path).unwrap();
    let (_home, codex_home) = canonical_temp_dir();
    let args = [
        "--workspace-root".to_string(),
        file_path.to_string_lossy().to_string(),
        "--codex-home".to_string(),
        codex_home.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--workspace-root");
}

#[test]
fn non_canonical_workspace_root_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    // A path with `..` and `.` components is absolute and existing but not
    // canonical: the runner must reject it so the sandbox policy never
    // contains aliased components.
    let non_canonical = workspace_root.join("sub").join("..").join(".");
    let args = [
        "--workspace-root".to_string(),
        non_canonical.to_string_lossy().to_string(),
        "--codex-home".to_string(),
        codex_home.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "canonical");
}

#[test]
fn missing_codex_home_directory_is_rejected() {
    let outer = tempfile::tempdir().unwrap();
    let missing = outer.path().join("state-does-not-exist");
    let (_workspace, workspace_root) = canonical_temp_dir();
    let args = [
        "--workspace-root".to_string(),
        workspace_root.to_string_lossy().to_string(),
        "--codex-home".to_string(),
        missing.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--codex-home");
}

#[test]
fn file_codex_home_is_rejected() {
    let outer = tempfile::tempdir().unwrap();
    let file_path = outer.path().join("state-file");
    std::fs::write(&file_path, b"x").unwrap();
    let file_path = dunce::canonicalize(&file_path).unwrap();
    let (_workspace, workspace_root) = canonical_temp_dir();
    let args = [
        "--workspace-root".to_string(),
        workspace_root.to_string_lossy().to_string(),
        "--codex-home".to_string(),
        file_path.to_string_lossy().to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--codex-home");
}

#[test]
fn empty_command_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "command");
}

#[test]
fn zero_timeout_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--timeout-ms".to_string());
    args.push("0".to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--timeout-ms");
}

#[test]
fn non_numeric_timeout_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--timeout-ms".to_string());
    args.push("soon".to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--timeout-ms");
}

#[test]
fn overflow_timeout_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--timeout-ms".to_string());
    args.push("99999999999999999999999999".to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--timeout-ms");
}

#[test]
fn maximum_u64_timeout_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--timeout-ms".to_string());
    args.push(u64::MAX.to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--timeout-ms");
}

#[test]
fn workspace_and_codex_home_must_be_disjoint() {
    let (_workspace, workspace_root) = canonical_temp_dir();
    let output = run_runner(&[
        "--workspace-root",
        workspace_root.to_string_lossy().as_ref(),
        "--codex-home",
        workspace_root.to_string_lossy().as_ref(),
        "--",
        "cmd",
    ]);
    assert_runner_failure(&output, "overlap");

    let nested_home = workspace_root.join("state");
    std::fs::create_dir(&nested_home).unwrap();
    let nested_home = dunce::canonicalize(nested_home).unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace_root.to_string_lossy().as_ref(),
        "--codex-home",
        nested_home.to_string_lossy().as_ref(),
        "--",
        "cmd",
    ]);
    assert_runner_failure(&output, "overlap");
}

#[test]
fn unknown_flag_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--verbose".to_string());
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "unknown argument");
}

#[test]
fn arbitrary_policy_and_root_flags_are_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    for hostile in [
        "--write-root",
        "--read-root",
        "--writable-roots",
        "--network",
        "--sandbox-policy",
        "--sandbox-policy-file",
        "--set",
        "--danger-full-access",
    ] {
        let mut args = valid_prefix(&workspace_root, &codex_home);
        args.push(hostile.to_string());
        args.push("value".to_string());
        args.push("--".to_string());
        args.push("cmd".to_string());
        let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_runner_failure(&output, "unknown argument");
    }
}

#[test]
fn missing_flag_value_is_rejected() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let args = [
        "--workspace-root".to_string(),
        workspace_root.to_string_lossy().to_string(),
        "--codex-home".to_string(),
        codex_home.to_string_lossy().to_string(),
        "--timeout-ms".to_string(),
        "--".to_string(),
        "cmd".to_string(),
    ];
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "--timeout-ms");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn non_windows_host_fails_closed_even_with_valid_arguments() {
    let (_workspace, workspace_root, _home, codex_home) = root_and_home();
    let mut args = valid_prefix(&workspace_root, &codex_home);
    args.push("--".to_string());
    args.push("cmd".to_string());
    let output = run_runner(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_runner_failure(&output, "Windows");
}

/// Native Windows containment matrix (Task 4).
///
/// Every case uses a fresh temporary workspace plus a separate external
/// target that sits outside the workspace and the runner-managed TEMP/TMP
/// root. Network probes are manual observations, not hard-containment
/// assertions for the RestrictedToken backend.
#[cfg(target_os = "windows")]
mod containment_matrix {
    use super::*;
    use std::time::Duration;
    use std::time::Instant;

    /// A fresh workspace plus an external target directory outside every
    /// writable root. The sandbox state directory is a single shared
    /// installation identity for the whole matrix: the first fixture
    /// completes the product-scoped elevated setup once (one administrator
    /// consent), and every subsequent test reuses it, matching the plan's
    /// "fresh product-scoped installation identity" qualification setup.
    struct Fixture {
        _base: tempfile::TempDir,
        workspace: PathBuf,
        codex_home: PathBuf,
        external_dir: PathBuf,
        external_file: PathBuf,
    }

    /// Shared installation home, stable for this test binary run.
    static SHARED_INSTALL_HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    #[allow(clippy::unwrap_used)] // test scaffolding: a failed fixture is the assertion
    fn shared_installation_home() -> PathBuf {
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().parent().unwrap().to_path_buf());
        let home = local.join(format!("ls-sbx-qual-install-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let canonical = dunce::canonicalize(&home).unwrap();
        // The runner rejects an overlapping --workspace-root/--codex-home, so
        // the warm-up spawn uses a SIBLING directory as its workspace root.
        let warmup_workspace = local.join(format!("ls-sbx-qual-warmup-{}", std::process::id()));
        std::fs::create_dir_all(&warmup_workspace).unwrap();
        let warmup_canonical = dunce::canonicalize(&warmup_workspace).unwrap();
        // Warm the installation exactly once, inside the lock: the first
        // sandboxed spawn performs the elevated setup (one UAC consent per
        // matrix run) and concurrent fixtures must not race a second setup.
        SHARED_INSTALL_HOME
            .get_or_init(|| {
                let warm = Command::new(runner())
                    .args([
                        "--workspace-root",
                        warmup_canonical.to_string_lossy().as_ref(),
                        "--codex-home",
                        canonical.to_string_lossy().as_ref(),
                        "--",
                        "cmd",
                        "/c",
                        "exit 0",
                    ])
                    .output()
                    .unwrap();
                assert_eq!(
                    warm.status.code(),
                    Some(0),
                    "shared installation warm-up failed; stderr: {}",
                    String::from_utf8_lossy(&warm.stderr)
                );
                canonical.clone()
            })
            .clone()
    }

    #[allow(clippy::unwrap_used)] // test scaffolding: a failed fixture is the assertion
    impl Fixture {
        fn new() -> Fixture {
            let local = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().parent().unwrap().to_path_buf());
            let base = tempfile::TempDir::new_in(&local).unwrap();
            let workspace = base.path().join("workspace");
            let external_dir = base.path().join("target");
            std::fs::create_dir(&workspace).unwrap();
            std::fs::create_dir(&external_dir).unwrap();
            let external_file = external_dir.join("victim.txt");
            std::fs::write(&external_file, b"original").unwrap();
            let workspace = dunce::canonicalize(&workspace).unwrap();
            let codex_home = shared_installation_home();
            let external_dir = dunce::canonicalize(&external_dir).unwrap();
            let external_file = dunce::canonicalize(&external_file).unwrap();
            // The matrix scripts redirect to unquoted paths, so every fixture
            // path must be space-free for cmd.exe.
            for path in [&workspace, &codex_home, &external_dir, &external_file] {
                assert!(
                    !path.to_string_lossy().contains(' '),
                    "fixture path must not contain spaces: {}",
                    path.display()
                );
            }
            Fixture {
                workspace,
                codex_home,
                external_dir,
                external_file,
                _base: base,
            }
        }

        /// Windows-style temp root for the `TEMP`/`TMP` writable root of the
        /// frozen profile. Test hosts launched from POSIX-style shells (for
        /// example Git Bash, where `TEMP=/tmp`) would otherwise hand the
        /// runner a path `cmd.exe` cannot use.
        fn windows_temp_root() -> PathBuf {
            std::env::var_os("LOCALAPPDATA")
                .map(|local| PathBuf::from(local).join("Temp"))
                .filter(|candidate| candidate.is_dir())
                .unwrap_or_else(std::env::temp_dir)
        }

        fn run(&self, args: &[&str]) -> Output {
            let mut all = vec![
                "--workspace-root".to_string(),
                self.workspace.to_string_lossy().to_string(),
                "--codex-home".to_string(),
                self.codex_home.to_string_lossy().to_string(),
            ];
            all.extend(args.iter().map(std::string::ToString::to_string));
            let temp_root = Self::windows_temp_root();
            Command::new(runner())
                .args(&all)
                .env("TEMP", &temp_root)
                .env("TMP", &temp_root)
                .output()
                .unwrap()
        }

        fn run_cmd(&self, script: &str) -> Output {
            self.run(&["--", "cmd", "/c", script])
        }

        fn external_unchanged(&self) -> bool {
            std::fs::read(&self.external_file).unwrap() == b"original"
        }
    }

    fn assert_external_denied(output: &Output, fixture: &Fixture, context: &str) {
        assert!(
            output.status.code().is_some_and(|code| code != 0),
            "{context}: write attempt must fail; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            fixture.external_unchanged(),
            "{context}: external target must stay untouched"
        );
    }

    // ---- Positive behavior -------------------------------------------------

    #[test]
    fn workspace_lifecycle_operations_succeed() {
        let fixture = Fixture::new();
        let output =
            fixture.run_cmd("echo one > a.txt && echo two > a.txt && ren a.txt b.txt && del b.txt");
        assert_eq!(output.status.code(), Some(0));
        assert!(!fixture.workspace.join("b.txt").exists());
        assert!(!fixture.workspace.join("a.txt").exists());
    }

    #[test]
    fn runner_managed_temp_root_writes_succeed() {
        let fixture = Fixture::new();
        let output = fixture.run_cmd("echo scratch > %TEMP%\\ls-sbx-matrix-scratch.txt");
        println!(
            "temp-write exit={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "writes into the Codex-qualified TEMP root must succeed"
        );
    }

    #[test]
    fn caller_temp_environment_cannot_widen_the_write_boundary() {
        let fixture = Fixture::new();
        let output = Command::new(runner())
            .args([
                "--workspace-root",
                fixture.workspace.to_string_lossy().as_ref(),
                "--codex-home",
                fixture.codex_home.to_string_lossy().as_ref(),
                "--",
                "cmd",
                "/c",
                &format!("echo tampered > {}", fixture.external_file.display()),
            ])
            .env("TEMP", &fixture.external_dir)
            .env("TMP", &fixture.external_dir)
            .output()
            .unwrap();
        assert_external_denied(&output, &fixture, "caller TEMP/TMP write");
    }

    #[test]
    fn system_file_reads_succeed() {
        let fixture = Fixture::new();
        let output = fixture.run_cmd("type C:\\Windows\\win.ini > NUL");
        assert_eq!(
            output.status.code(),
            Some(0),
            "reads outside the workspace root must stay allowed"
        );
    }

    #[test]
    fn stdout_stderr_and_exit_codes_are_forwarded() {
        let fixture = Fixture::new();
        let out = fixture.run_cmd("echo hello-from-sandbox");
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("hello-from-sandbox"));

        let err = fixture.run_cmd("echo err-line 1>&2");
        assert!(String::from_utf8_lossy(&err.stderr).contains("err-line"));

        let code = fixture.run_cmd("exit 42");
        assert_eq!(
            code.status.code(),
            Some(42),
            "real exit codes must be forwarded"
        );
    }

    // ---- Filesystem boundaries ---------------------------------------------

    #[test]
    fn sibling_directory_write_denied() {
        let fixture = Fixture::new();
        let output = fixture.run_cmd(&format!(
            "echo tampered > {}",
            fixture.external_file.display()
        ));
        assert_external_denied(&output, &fixture, "sibling write");
    }

    #[test]
    fn parent_directory_write_denied() {
        let fixture = Fixture::new();
        let parent_victim = fixture
            .workspace
            .parent()
            .unwrap()
            .join("parent-victim.txt");
        let output = fixture.run_cmd(&format!("echo tampered > {}", parent_victim.display()));
        assert!(
            output.status.code().is_some_and(|code| code != 0),
            "parent-of-workspace writes must be denied"
        );
        assert!(
            !parent_victim.exists(),
            "parent-of-workspace writes must not land"
        );
    }

    #[test]
    fn git_and_agents_metadata_stay_read_only() {
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.workspace.join(".git")).unwrap();
        std::fs::write(
            fixture.workspace.join(".git").join("HEAD"),
            b"ref: refs/heads/main",
        )
        .unwrap();
        std::fs::create_dir(fixture.workspace.join(".agents")).unwrap();
        std::fs::write(fixture.workspace.join(".agents").join("notes"), b"kept").unwrap();

        let git_write = fixture.run_cmd("echo tampered > .git\\HEAD");
        assert!(
            git_write.status.code().is_some_and(|code| code != 0),
            ".git writes must be denied"
        );
        assert_eq!(
            std::fs::read(fixture.workspace.join(".git").join("HEAD")).unwrap(),
            b"ref: refs/heads/main"
        );

        let agents_write = fixture.run_cmd("echo tampered > .agents\\notes");
        assert!(
            agents_write.status.code().is_some_and(|code| code != 0),
            ".agents writes must be denied"
        );
        assert_eq!(
            std::fs::read(fixture.workspace.join(".agents").join("notes")).unwrap(),
            b"kept"
        );

        // Reads must be retained even though writes are denied.
        let git_read = fixture.run_cmd("type .git\\HEAD");
        assert_eq!(git_read.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&git_read.stdout).contains("refs/heads/main"));
    }

    #[test]
    fn relative_cwd_escape_denied() {
        let fixture = Fixture::new();
        let escape = fixture.workspace.parent().unwrap().join("escaped.txt");
        let output = fixture.run_cmd("echo escaped > ..\\escaped.txt");
        assert!(
            output.status.code().is_some_and(|code| code != 0),
            "relative .. escape must be denied"
        );
        assert!(!escape.exists(), "relative .. escape must not land outside");
    }

    #[test]
    fn workspace_root_passed_through_a_junction_is_rejected() {
        let fixture = Fixture::new();
        let alias = fixture.workspace.parent().unwrap().join("workspace-alias");
        let mklink = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&alias)
            .arg(&fixture.workspace)
            .output()
            .unwrap();
        assert!(
            mklink.status.success(),
            "junction creation must work unelevated"
        );
        let output = run_runner(&[
            "--workspace-root",
            alias.to_string_lossy().as_ref(),
            "--codex-home",
            fixture.codex_home.to_string_lossy().as_ref(),
            "--",
            "cmd",
            "/c",
            "echo hi",
        ]);
        assert_runner_failure(&output, "canonical");
        let _ = std::fs::remove_dir(&alias);
    }

    #[test]
    fn junction_inside_workspace_to_external_write_denied() {
        let fixture = Fixture::new();
        let link = fixture.workspace.join("link");
        let mklink = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&fixture.external_dir)
            .output()
            .unwrap();
        assert!(mklink.status.success());
        let output = fixture.run_cmd("echo tampered > link\\victim.txt");
        assert_external_denied(&output, &fixture, "junction write");
        let _ = std::fs::remove_dir(&link);
    }

    #[test]
    fn verbatim_device_path_escape_denied() {
        let fixture = Fixture::new();
        let verbatim = format!("\\\\?\\{}", fixture.external_file.display());
        let output = fixture.run_cmd(&format!("echo tampered > {verbatim}"));
        assert_external_denied(&output, &fixture, "verbatim-path write");
    }

    #[test]
    fn alternate_data_stream_on_external_file_denied() {
        let fixture = Fixture::new();
        let target = fixture.external_file.display();
        let output = fixture.run_cmd(&format!("echo tampered > {target}:hidden"));
        assert_external_denied(&output, &fixture, "ADS write");
    }

    #[test]
    fn eight_point_three_alias_escape_denied() {
        let fixture = Fixture::new();
        let probe = Command::new("cmd")
            .args(["/c", "for", "%I", "in"])
            .arg(format!("(\"{}\")", fixture.external_dir.display()))
            .args(["do", "@echo", "%~sI"])
            .output()
            .unwrap();
        let short = String::from_utf8_lossy(&probe.stdout).trim().to_string();
        if short.is_empty()
            || short.eq_ignore_ascii_case(&fixture.external_dir.display().to_string())
        {
            // 8.3 alias generation is disabled on this volume; the alias
            // escape class cannot be exercised here.
            println!(
                "skipped: no 8.3 alias available for {}",
                fixture.external_dir.display()
            );
            return;
        }
        let output = fixture.run_cmd(&format!("echo tampered > {short}\\victim.txt"));
        assert_external_denied(&output, &fixture, "8.3-alias write");
    }

    // ---- Process tree and network -------------------------------------------

    #[test]
    fn child_and_grandchild_inherit_containment() {
        let fixture = Fixture::new();
        let victim = fixture.external_file.display().to_string();
        let nested = fixture.run_cmd(&format!("cmd /c \"echo tampered > {victim}\""));
        assert_external_denied(&nested, &fixture, "nested cmd write");

        let started = fixture.run_cmd(&format!("start /wait cmd /c \"echo tampered > {victim}\""));
        println!(
            "start-wait exit={:?} stdout={} stderr={}",
            started.status.code(),
            String::from_utf8_lossy(&started.stdout),
            String::from_utf8_lossy(&started.stderr)
        );
        // `start` needs a console window station the restricted token may not
        // provide, so it may fail without an exit code signal; the containment
        // invariant is that the external target stays untouched either way.
        assert!(
            fixture.external_unchanged(),
            "start /wait write: external target must stay untouched"
        );
    }

    #[test]
    fn background_descendant_is_terminated_when_the_root_command_exits() {
        let fixture = Fixture::new();
        let launcher = fixture.workspace.join("launch-background.cmd");
        std::fs::write(
            &launcher,
            "@echo off\r\nstart \"\" /b cmd /c \"ping -n 4 127.0.0.1 ^> NUL ^& echo survived ^> background-survived.txt\"\r\nexit /b 0\r\n",
        )
        .unwrap();
        let started = Instant::now();
        let output = fixture.run_cmd("launch-background.cmd");
        assert_eq!(output.status.code(), Some(0));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "background descendants must not hold runner output open"
        );
        std::thread::sleep(Duration::from_secs(5));
        assert!(
            !fixture.workspace.join("background-survived.txt").exists(),
            "a background descendant survived the one-shot runner"
        );
    }

    #[test]
    fn timeout_terminates_process_tree_and_exits_124() {
        let fixture = Fixture::new();
        let ping_count = |label: &str| -> usize {
            let listing = Command::new("tasklist")
                .args(["/NH", "/FI", "IMAGENAME eq PING.EXE"])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&listing.stdout).to_lowercase();
            let count = text.matches("ping.exe").count();
            println!("{label}: {count} standing ping.exe processes");
            count
        };
        let before = ping_count("before");
        let started = Instant::now();
        let output = fixture.run(&[
            "--timeout-ms",
            "2000",
            "--",
            "cmd",
            "/c",
            "ping -n 30 127.0.0.1 > NUL",
        ]);
        let elapsed = started.elapsed();
        assert_eq!(
            output.status.code(),
            Some(TIMEOUT_EXIT_CODE),
            "timeout must exit 124"
        );
        assert!(
            elapsed.as_secs() < 15,
            "timeout must fire promptly, took {elapsed:?}"
        );
        let after = ping_count("after");
        assert!(
            after <= before,
            "no sandboxed descendant may survive the timeout kill (before={before}, after={after})"
        );
    }

    #[test]
    fn manual_loopback_network_observation() {
        let fixture = Fixture::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Connect from inside the sandbox while the host test process listens.
        let workspace = fixture.workspace.to_string_lossy().to_string();
        let codex_home = fixture.codex_home.to_string_lossy().to_string();
        let writer = std::thread::spawn(move || {
            let output = Command::new(runner())
                .args([
                    "--workspace-root",
                    workspace.as_str(),
                    "--codex-home",
                    codex_home.as_str(),
                    "--",
                    "cmd",
                    "/c",
                    &format!("curl.exe --noproxy * -s -m 5 telnet://127.0.0.1:{port}"),
                ])
                .output()
                .unwrap();
            (
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).to_string(),
            )
        });
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = false;
        while Instant::now() < deadline {
            if listener.accept().is_ok() {
                seen = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let (exit_code, stderr) = writer.join().unwrap();
        println!(
            "loopback observation: sandbox connect {} the host listener (curl exit {exit_code:?}, stderr {stderr:?})",
            if seen { "REACHED" } else { "was refused by" }
        );
        // Qualification record for this host: even loopback TCP connect is
        // refused inside the restricted-token sandbox, which is stricter than
        // the macOS Seatbelt restricted policy (loopback allowed). A change
        // of this outcome on a future host must trigger re-qualification.
        assert!(
            !seen,
            "unexpected loopback reachability; re-qualification required"
        );
    }

    #[test]
    fn manual_external_network_observation() {
        let fixture = Fixture::new();
        // Raw TCP to a well-known anycast address, no DNS involved. The
        // restricted policy must not let the connection complete.
        let tcp = fixture
            .run_cmd("curl.exe --noproxy * -s -m 6 -o NUL -w \"%{http_code}\" https://1.1.1.1");
        let stdout = String::from_utf8_lossy(&tcp.stdout).to_string();
        assert!(
            !stdout.contains("200") && !stdout.contains("301") && !stdout.contains("302"),
            "external TCP must not complete inside the sandbox; got: {stdout}"
        );
        // DNS-dependent fetch: with a working resolver and network this would
        // succeed; under the restricted policy the name must not resolve to a
        // usable connection (curl exit 6/7/28 class, never an HTTP success).
        let dns = fixture
            .run_cmd("curl.exe --noproxy * -s -m 6 -o NUL -w \"%{http_code}\" https://example.org");
        let dns_stdout = String::from_utf8_lossy(&dns.stdout).to_string();
        assert!(
            !dns_stdout.contains("200")
                && !dns_stdout.contains("301")
                && !dns_stdout.contains("302"),
            "DNS-dependent external fetch must not complete inside the sandbox; got: {dns_stdout}"
        );
    }

    // ---- Environment and secrets ---------------------------------------------

    #[test]
    fn provider_secret_env_not_observable() {
        let fixture = Fixture::new();
        let spawn_sandboxed = |script: &'static str| {
            Command::new(runner())
                .args([
                    "--workspace-root",
                    fixture.workspace.to_string_lossy().as_ref(),
                    "--codex-home",
                    fixture.codex_home.to_string_lossy().as_ref(),
                    "--",
                    "cmd",
                    "/c",
                    script,
                ])
                .env("OPENCODE_API_KEY", "canary-opencode-value")
                .env("DEEPSEEK_API_KEY", "canary-deepseek-value")
                .output()
                .unwrap()
        };

        // Each probe runs as its own invocation: cmd chains `&` segments into
        // the first `if` body, so separate scripts keep the probes exact.
        let opencode = spawn_sandboxed("if defined OPENCODE_API_KEY echo LEAK-OPENCODE");
        let opencode_out = String::from_utf8_lossy(&opencode.stdout).to_string();
        assert!(
            !opencode_out.contains("LEAK-OPENCODE"),
            "provider canary leaked: {opencode_out}"
        );

        let deepseek = spawn_sandboxed("if defined DEEPSEEK_API_KEY echo LEAK-DEEPSEEK");
        let deepseek_out = String::from_utf8_lossy(&deepseek.stdout).to_string();
        assert!(
            !deepseek_out.contains("LEAK-DEEPSEEK"),
            "auth canary leaked: {deepseek_out}"
        );

        // Elevated backend: network confinement is kernel-enforced (WFP);
        // the restricted-token environment marker must NOT be present, and
        // no dead-proxy variable may masquerade as the boundary.
        let marker = spawn_sandboxed("echo NONET=%SBX_NONET_ACTIVE%");
        let marker_out = String::from_utf8_lossy(&marker.stdout).to_string();
        assert!(
            !marker_out.contains("NONET=1"),
            "elevated backend must not rely on the restricted-token env marker; got: {marker_out:?}"
        );
        let proxies = spawn_sandboxed(
            "if defined HTTP_PROXY echo PROXY-HTTP & if defined HTTPS_PROXY echo PROXY-HTTPS",
        );
        let proxies_out = String::from_utf8_lossy(&proxies.stdout).to_string();
        assert!(
            !proxies_out.contains("PROXY-HTTP") && !proxies_out.contains("PROXY-HTTPS"),
            "no proxy environment may be observable inside the sandbox; got: {proxies_out:?}"
        );

        // Canary values must never appear in any captured output.
        let all = format!("{opencode_out}{deepseek_out}{marker_out}");
        assert!(
            !all.contains("canary-opencode-value") && !all.contains("canary-deepseek-value"),
            "canary values must never appear in output"
        );
    }

    // ---- Elevated qualification matrix (Task 4) ---------------------------

    /// Runs a tool with arguments inside the sandbox and returns the output,
    /// with every proxy variable cleared so network outcomes prove the
    /// kernel boundary rather than environment behavior.
    #[allow(clippy::unwrap_used)] // test scaffolding: a failed spawn is the assertion
    fn run_tool(fixture: &Fixture, tool: &str, args: &[&str]) -> Output {
        let mut all = vec![
            "--workspace-root".to_string(),
            fixture.workspace.to_string_lossy().to_string(),
            "--codex-home".to_string(),
            fixture.codex_home.to_string_lossy().to_string(),
            "--".to_string(),
        ];
        all.push(tool.to_string());
        all.extend(args.iter().map(std::string::ToString::to_string));
        Command::new(runner())
            .args(&all)
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .output()
            .unwrap()
    }

    #[test]
    fn powershell_command_host_qualification() {
        let fixture = Fixture::new();
        let output = run_tool(
            &fixture,
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Set-Content -Path ps-ok.txt -Value ok; Get-Content ps-ok.txt",
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "powershell must run; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            stdout.contains("ok"),
            "powershell output forwarded: {stdout:?}"
        );
    }

    #[test]
    fn python_command_host_qualification() {
        let fixture = Fixture::new();
        let output = run_tool(
            &fixture,
            "python",
            &[
                "-c",
                "from pathlib import Path; Path('py-ok.txt').write_text('ok', encoding='utf-8'); print(Path('py-ok.txt').read_text(encoding='utf-8'))",
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "python must run; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(stdout.contains("ok"), "python output forwarded: {stdout:?}");
    }

    #[test]
    fn node_command_host_qualification() {
        let fixture = Fixture::new();
        let script = "const fs = require('fs'); fs.writeFileSync('node-ok.txt', 'ok'); process.stdout.write(fs.readFileSync('node-ok.txt', 'utf8'));";
        let output = run_tool(&fixture, "node", &["-e", script]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "node must run; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(stdout.contains("ok"), "node output forwarded: {stdout:?}");
    }

    #[test]
    fn git_command_host_qualification() {
        let fixture = Fixture::new();
        let init = run_tool(&fixture, "git", &["init", "."]);
        assert_eq!(
            init.status.code(),
            Some(0),
            "git init must run; stderr: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let status = run_tool(&fixture, "git", &["status", "--porcelain"]);
        assert_eq!(status.status.code(), Some(0));
    }

    #[test]
    fn cjk_and_space_paths_round_trip() {
        let fixture = Fixture::new();
        let output = fixture.run_cmd("echo hi > \"\u{4e2d}\u{6587} \u{6587}\u{4ef6}.txt\" && type \"\u{4e2d}\u{6587} \u{6587}\u{4ef6}.txt\"");
        assert_eq!(
            output.status.code(),
            Some(0),
            "CJK + space filename must round-trip; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cjk_name = format!("{} {}.txt", "\u{4e2d}\u{6587}", "\u{6587}\u{4ef6}");
        assert!(fixture.workspace.join(cjk_name).exists());
    }

    #[test]
    fn nonzero_exit_code_is_forwarded() {
        let fixture = Fixture::new();
        let output = run_tool(&fixture, "cmd", &["/c", "exit 42"]);
        assert_eq!(output.status.code(), Some(42));
    }

    #[test]
    fn large_bounded_output_is_forwarded() {
        let fixture = Fixture::new();
        let output = fixture.run_cmd(
            "for /l %i in (1,1,32768) do @echo 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "large output run must succeed; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.len() > 1024 * 1024,
            "large output must be forwarded; got {} bytes",
            output.stdout.len()
        );
    }

    #[test]
    fn external_read_canary_is_denied() {
        let fixture = Fixture::new();
        let victim = fixture.external_file.to_string_lossy().to_string();
        let code = format!(
            "import sys; data = open(r'{victim}', 'rb').read(); sys.exit(0 if data == b'original' else 3)"
        );
        let read = run_tool(&fixture, "python", &["-c", &code]);
        assert_ne!(
            read.status.code(),
            Some(0),
            "external read canary must be denied; stdout: {} stderr: {}",
            String::from_utf8_lossy(&read.stdout),
            String::from_utf8_lossy(&read.stderr)
        );
    }

    #[test]
    fn python_raw_socket_and_dns_are_denied() {
        let fixture = Fixture::new();
        let tcp = run_tool(
            &fixture,
            "python",
            &[
                "-c",
                "import socket; s = socket.create_connection(('1.1.1.1', 443), timeout=5); s.close(); print('CONNECTED')",
            ],
        );
        let tcp_out = String::from_utf8_lossy(&tcp.stdout).to_string();
        assert!(
            !tcp_out.contains("CONNECTED"),
            "raw TCP must be kernel-denied; got: {tcp_out:?}"
        );
        let dns = run_tool(
            &fixture,
            "python",
            &[
                "-c",
                "import socket; socket.create_connection(('example.org', 443), timeout=5); print('DNS-CONNECTED')",
            ],
        );
        let dns_out = String::from_utf8_lossy(&dns.stdout).to_string();
        assert!(
            !dns_out.contains("DNS-CONNECTED"),
            "DNS-dependent connect must be kernel-denied; got: {dns_out:?}"
        );
    }

    #[test]
    fn child_grandchild_network_is_denied() {
        let fixture = Fixture::new();
        let script = "import subprocess, sys; out = subprocess.run([sys.executable, '-c', \"import socket; socket.create_connection(('1.1.1.1', 443), timeout=4); print('GC-CONNECTED')\"], capture_output=True, text=True); sys.stdout.write(out.stdout)";
        let output = run_tool(&fixture, "python", &["-c", script]);
        let out = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            !out.contains("GC-CONNECTED"),
            "grandchild network must be kernel-denied; got: {out:?}"
        );
    }

    #[test]
    fn setup_rerun_is_idempotent_for_the_installation() {
        let fixture = Fixture::new();
        let marker = fixture
            .codex_home
            .join(".sandbox")
            .join("setup_marker.json");
        let before = std::fs::read(&marker).unwrap();
        let output = fixture.run_cmd("echo warm > warm.txt");
        assert_eq!(output.status.code(), Some(0));
        let after = std::fs::read(&marker).unwrap();
        if before != after {
            let parse_field = |bytes: &[u8]| -> String {
                let text = String::from_utf8_lossy(bytes).to_string();
                text.lines()
                    .find(|line| line.contains("\"install_id\""))
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            assert_eq!(
                parse_field(&before),
                parse_field(&after),
                "setup rerun must keep the same installation identity"
            );
        }
    }
}

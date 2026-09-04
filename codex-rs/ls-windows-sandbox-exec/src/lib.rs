//! `ls-windows-sandbox-exec` is the Windows runner shell that executes a
//! single command inside a Codex-managed Windows sandbox on behalf of
//! LeapSea's managed runtime.
//!
//! The runner delegates filesystem, token, process-tree, and network-policy
//! projection to the shared `codex-windows-sandbox` implementation; this crate
//! never hand-writes token, ACL, Job Object, or WFP policy. It accepts exactly
//! one canonical workspace root and a fixed `workspace-write` profile. The
//! RestrictedToken backend's network posture is environment-soft rather than
//! a kernel boundary, so callers must not treat it as hard network isolation.
//!
//! Runner-own failures (argument errors, unusable roots, spawn errors, or a
//! missing sandbox prerequisite) print a single
//! `LS_WINDOWS_SANDBOX_UNAVAILABLE:<reason>` line to stderr and exit with
//! [`RUNNER_FAILURE_EXIT_CODE`]. The command is never executed without a
//! sandbox, and a failed sandbox launch never falls back to unsandboxed host
//! execution.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_utils_absolute_path::AbsolutePathBuf;

/// Exit code used exclusively for runner-own failures. A sandboxed command
/// that fails on its own forwards its real exit code instead.
pub const RUNNER_FAILURE_EXIT_CODE: i32 = 250;
/// Exit code used when the runner killed the sandboxed command because it
/// exceeded `--timeout-ms` (matching the conventional `timeout(1)` code).
pub const TIMEOUT_EXIT_CODE: i32 = 124;
/// Stderr marker prefix for runner-own failures:
/// `LS_WINDOWS_SANDBOX_UNAVAILABLE:<reason>`.
pub const RUNNER_FAILURE_MARKER: &str = "LS_WINDOWS_SANDBOX_UNAVAILABLE";
/// Exit code forwarded when the sandboxed process dies without a reported
/// exit code (matching the conventional `1`-shell fallback style of the
/// macOS runner's 255).
pub const NO_EXIT_CODE: i32 = 255;

/// Upper bound for the single-line failure reason so a hostile input cannot
/// produce an unbounded stderr blob.
const MAX_FAILURE_REASON_CHARS: usize = 400;
/// Long-running commands should use the product's durable async execution
/// path. Bounding this value also prevents `Instant + Duration` overflow.
const MAX_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
/// Grace period while reaping the sandbox process tree after a timeout kill
/// before the runner gives up waiting on stragglers and exits 124 anyway.
const TIMEOUT_REAP_GRACE: Duration = Duration::from_secs(5);

/// Environment variables copied from the caller into the sandboxed command.
/// This is a fixed allowlist of non-secret command-host fields; everything
/// else (provider credentials, auth stores, Electron user-data paths, and any
/// other parent environment content) is dropped.
const PRESERVED_ENV_KEYS: &[(&str, &str)] = &[
    ("PATH", "PATH"),
    ("PATHEXT", "PATHEXT"),
    ("SYSTEMROOT", "SystemRoot"),
    ("WINDIR", "WINDIR"),
];

/// The internally selected Windows sandbox level for the frozen filesystem
/// write/process contract. No automatic fallback to the elevated backend
/// exists; hard network and restricted-read isolation require a separately
/// provisioned elevated path.
#[cfg(target_os = "windows")]
pub fn selected_windows_sandbox_level() -> WindowsSandboxLevel {
    WindowsSandboxLevel::RestrictedToken
}

/// Parsed runner inputs that do not depend on the command being executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSandboxExecOptions {
    /// The one writable workspace root. It must already be canonical
    /// (absolute, existing, a directory, and free of symlink/junction or
    /// `..` components) so the sandbox policy never contains aliased path
    /// components. It is also the working directory of the sandboxed command.
    pub workspace_root: PathBuf,
    /// Sandbox state directory (Codex-qualified). Same canonical-directory
    /// contract as [`Self::workspace_root`].
    pub codex_home: PathBuf,
    /// Optional wall-clock limit after which the runner kills the sandboxed
    /// command's whole process tree and exits with [`TIMEOUT_EXIT_CODE`].
    pub timeout_ms: Option<u64>,
}

/// Everything the runner needs to spawn the sandboxed command. Built once
/// from the validated options; the session request derives from this plan and
/// cannot be widened afterwards.
#[derive(Debug)]
pub struct WindowsSandboxLaunchPlan {
    /// Exactly one materialized writable workspace root.
    pub workspace_roots: Vec<AbsolutePathBuf>,
    /// Fixed Codex managed `workspace-write` profile. Its Restricted network
    /// projection is environment-soft on this backend.
    pub permission_profile: PermissionProfile,
    /// Validated sandbox state directory.
    pub codex_home: PathBuf,
    /// The sandboxed command argv.
    pub command: Vec<String>,
    /// Working directory of the sandboxed command: the canonical workspace
    /// root.
    pub cwd: PathBuf,
    /// Filtered environment (fixed allowlist only).
    pub env: Vec<(String, String)>,
    /// Runner-created temporary directory: the only TEMP/TMP writable root.
    pub command_temp_root: PathBuf,
    /// Explicit defense-in-depth carveouts from every writable capability.
    pub deny_write_paths: Vec<AbsolutePathBuf>,
    /// Runner-enforced wall-clock limit.
    pub timeout_ms: Option<u64>,
    /// Owns the temporary directory for the complete sandbox session.
    _command_temp: tempfile::TempDir,
}

/// Parses the frozen CLI grammar:
/// `--workspace-root <dir> --codex-home <dir> [--timeout-ms <n>] -- <command>...`
///
/// Syntax only; filesystem validation happens in
/// [`build_launch_plan`]. No other flag exists on purpose:
/// writable roots, policy JSON, network mode, and environment overrides are
/// not caller-settable.
pub fn parse_cli(raw_args: &[String]) -> Result<WindowsSandboxExecOptions, String> {
    let separator_index = raw_args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| "missing `--` separator before the command".to_string())?;
    let flags = &raw_args[..separator_index];
    let command = &raw_args[separator_index + 1..];
    if command.is_empty() {
        return Err("missing command after `--`".to_string());
    }

    let mut workspace_root: Option<String> = None;
    let mut codex_home: Option<String> = None;
    let mut timeout_ms: Option<u64> = None;

    let mut index = 0;
    while index < flags.len() {
        let flag = flags[index].as_str();
        match flag {
            "--workspace-root" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                replace_once(&mut workspace_root, value, flag)?;
            }
            "--codex-home" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                replace_once(&mut codex_home, value, flag)?;
            }
            "--timeout-ms" => {
                let value = next_flag_value(flags, &mut index, flag)?;
                if timeout_ms.is_some() {
                    return Err(format!("duplicate flag {flag}"));
                }
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid value for {flag}: `{value}` ({err})"))?;
                if parsed == 0 || parsed > MAX_TIMEOUT_MS {
                    return Err(format!(
                        "invalid value for {flag}: `{parsed}` (must be between 1 and {MAX_TIMEOUT_MS})"
                    ));
                }
                timeout_ms = Some(parsed);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }

    let workspace_root =
        workspace_root.ok_or_else(|| "missing required flag --workspace-root <dir>".to_string())?;
    let codex_home =
        codex_home.ok_or_else(|| "missing required flag --codex-home <dir>".to_string())?;
    Ok(WindowsSandboxExecOptions {
        workspace_root: PathBuf::from(workspace_root),
        codex_home: PathBuf::from(codex_home),
        timeout_ms,
    })
}

fn next_flag_value<'a>(
    flags: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a String, String> {
    let value = flags
        .get(*index + 1)
        .ok_or_else(|| format!("missing value for {flag}"))?;
    *index += 2;
    Ok(value)
}

fn replace_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate flag {flag}"));
    }
    *slot = Some(value);
    Ok(())
}

/// The command argv is everything after the `--` separator.
pub fn command_from_args(raw_args: &[String]) -> Result<Vec<String>, String> {
    let separator_index = raw_args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| "missing `--` separator before the command".to_string())?;
    let command: Vec<String> = raw_args[separator_index + 1..].to_vec();
    if command.is_empty() {
        return Err("missing command after `--`".to_string());
    }
    Ok(command)
}

/// Validates that `value` is a canonical directory: absolute, existing, a
/// directory, and equal to its own canonical form (no `..`, symlink, or
/// junction components). Returns the validated canonical path.
pub fn validate_canonical_directory(value: &Path, flag: &str) -> Result<PathBuf, String> {
    if !value.is_absolute() {
        return Err(format!(
            "{flag} must be an absolute directory, got `{}`",
            value.display()
        ));
    }
    let canonical = dunce::canonicalize(value)
        .map_err(|err| format!("{flag} is not accessible: {} ({err})", value.display()))?;
    if !canonical.is_dir() {
        return Err(format!(
            "{flag} must be a directory, got `{}`",
            canonical.display()
        ));
    }
    if canonical != value {
        return Err(format!(
            "{flag} must be a canonical directory: `{}` resolves to `{}`",
            value.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}

/// Builds the runner-internal launch plan from validated options. This is
/// the only place the fixed profile is chosen: one canonical workspace root,
/// Codex managed `workspace-write`, a runner-owned TEMP/TMP root, the fixed
/// environment allowlist, and no override knobs at all.
pub fn build_launch_plan<I, K, V>(
    options: &WindowsSandboxExecOptions,
    command: &[String],
    parent_vars: I,
) -> Result<WindowsSandboxLaunchPlan, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    if command.is_empty() {
        return Err("missing command after `--`".to_string());
    }
    // Re-validate at launch-plan time so the policy root is the canonical
    // on-disk identity, narrowing the validation-to-launch window.
    let workspace_root = validate_canonical_directory(&options.workspace_root, "--workspace-root")?;
    let codex_home = validate_canonical_directory(&options.codex_home, "--codex-home")?;
    if paths_overlap(&workspace_root, &codex_home) {
        return Err("--workspace-root and --codex-home must not overlap".to_string());
    }
    let temp_parent = codex_home
        .parent()
        .ok_or_else(|| "--codex-home must have a parent directory".to_string())?;
    let command_temp = tempfile::Builder::new()
        .prefix("ls-windows-sandbox-command-")
        .tempdir_in(temp_parent)
        .map_err(|err| format!("cannot create the managed command temp directory: {err}"))?;
    let command_temp_root = validate_canonical_directory(command_temp.path(), "managed TEMP")?;
    if paths_overlap(&workspace_root, &command_temp_root)
        || paths_overlap(&codex_home, &command_temp_root)
    {
        return Err(
            "managed TEMP must not overlap the workspace or sandbox state root".to_string(),
        );
    }
    let absolute_root = AbsolutePathBuf::from_absolute_path(&workspace_root)
        .map_err(|err| format!("--workspace-root is not absolute: {err}"))?;
    let denied_codex_home = AbsolutePathBuf::from_absolute_path(&codex_home)
        .map_err(|err| format!("--codex-home is not absolute: {err}"))?;
    let mut env = filtered_environment_from(parent_vars);
    let managed_temp = command_temp_root.to_string_lossy().into_owned();
    env.push(("TEMP".to_string(), managed_temp.clone()));
    env.push(("TMP".to_string(), managed_temp));
    Ok(WindowsSandboxLaunchPlan {
        workspace_roots: vec![absolute_root],
        permission_profile: PermissionProfile::workspace_write(),
        codex_home,
        command: command.to_vec(),
        cwd: workspace_root,
        env,
        command_temp_root,
        deny_write_paths: vec![denied_codex_home],
        timeout_ms: options.timeout_ms,
        _command_temp: command_temp,
    })
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

/// Filters the parent environment down to the fixed allowlist. Non-UTF-8
/// entries are dropped fail-closed. There is no caller escape hatch: the
/// frozen grammar has no `--set`.
pub fn filtered_environment_from<I, K, V>(parent_vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    parent_vars
        .into_iter()
        .filter_map(|(key, value)| {
            let key = key.as_ref().to_str()?;
            let value = value.as_ref().to_str()?;
            PRESERVED_ENV_KEYS
                .iter()
                .find(|(candidate, _)| key.eq_ignore_ascii_case(candidate))
                .map(|(_, canonical)| ((*canonical).to_string(), value.to_string()))
        })
        .collect()
}

/// Flattens a failure reason into one bounded single line: newlines become
/// spaces and over-long reasons are truncated.
pub fn flatten_failure_reason(reason: &str) -> String {
    let flattened = reason.replace(['\n', '\r'], " ");
    if flattened.chars().count() <= MAX_FAILURE_REASON_CHARS {
        return flattened;
    }
    let truncated: String = flattened
        .chars()
        .take(MAX_FAILURE_REASON_CHARS - 3)
        .collect();
    format!("{truncated}...")
}

/// Launches `command` inside the sandbox described by `options` and returns
/// the sandboxed command's real exit code. Runner-own errors come back as
/// `Err(reason)`; the caller exits 250 and never falls back to unsandboxed
/// execution.
pub async fn run_sandboxed<I, K, V>(
    options: &WindowsSandboxExecOptions,
    command: &[String],
    parent_vars: I,
) -> Result<i32, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let plan = build_launch_plan(options, command, parent_vars)?;
    execute_plan(&plan).await
}

#[cfg(target_os = "windows")]
mod windows_backend {
    use super::*;
    use codex_windows_sandbox::WindowsSandboxProxySettingsMode;
    use codex_windows_sandbox::WindowsSandboxSessionRequest;

    /// Builds the Codex session request from the launch plan with every
    /// widening knob pinned shut: no read/write root overrides, no deny-list
    /// overrides, no proxy or network elevation, no private desktop, and no
    /// backend-enforced timeout (the runner enforces its own 124 semantics).
    pub fn build_session_request(
        plan: &WindowsSandboxLaunchPlan,
    ) -> WindowsSandboxSessionRequest<'_> {
        const NO_DENY_PATHS: &[AbsolutePathBuf] = &[];
        WindowsSandboxSessionRequest {
            permission_profile: &plan.permission_profile,
            workspace_roots: &plan.workspace_roots,
            codex_home: &plan.codex_home,
            command: plan.command.clone(),
            cwd: &plan.cwd,
            env_map: plan
                .env
                .iter()
                .cloned()
                .collect::<HashMap<String, String>>(),
            windows_sandbox_level: super::selected_windows_sandbox_level(),
            proxy_enforced: false,
            network_proxy_restricting_sid: None,
            proxy_settings_mode: WindowsSandboxProxySettingsMode::default(),
            timeout_ms: None,
            read_roots_override: None,
            read_roots_include_platform_defaults: false,
            write_roots_override: None,
            deny_read_paths_override: NO_DENY_PATHS,
            deny_write_paths_override: &plan.deny_write_paths,
            tty: false,
            stdin_open: false,
            use_private_desktop: false,
            preserve_descendants_on_root_exit: false,
        }
    }

    /// Spawns the sandboxed session through the Codex unified spawner, then
    /// streams stdout/stderr to the runner's own streams and waits for the
    /// real exit code, enforcing the runner-owned timeout.
    pub async fn execute_plan(plan: &WindowsSandboxLaunchPlan) -> Result<i32, String> {
        let request = build_session_request(plan);
        let spawned = codex_windows_sandbox::spawn_windows_sandbox_session_for_level(request)
            .await
            .map_err(|err| format!("spawn-failed: {err}"))?;
        let codex_utils_pty::SpawnedProcess {
            session,
            stdout_rx,
            stderr_rx,
            exit_rx,
        } = spawned;
        let stdout_pump = tokio::spawn(pump(stdout_rx, tokio::io::stdout()));
        let stderr_pump = tokio::spawn(pump(stderr_rx, tokio::io::stderr()));

        let mut exit_rx = exit_rx;
        let outcome = match plan.timeout_ms {
            Some(ms) => {
                let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
                tokio::select! {
                    code = &mut exit_rx => Ok(code),
                    _ = tokio::time::sleep_until(deadline) => Err(()),
                }
            }
            None => Ok((&mut exit_rx).await),
        };
        match outcome {
            Ok(Ok(code)) => {
                // This runner represents one synchronous tool execution. A
                // background descendant must not outlive it or keep inherited
                // output handles open indefinitely.
                session.terminate();
                finish_pump(stdout_pump).await;
                finish_pump(stderr_pump).await;
                Ok(code)
            }
            Ok(Err(_)) => {
                // The session ended without reporting an exit code; forward a
                // conventional non-zero command failure, not a runner failure.
                session.terminate();
                finish_pump(stdout_pump).await;
                finish_pump(stderr_pump).await;
                Ok(NO_EXIT_CODE)
            }
            Err(()) => {
                // Kill the whole sandbox job/process tree, then wait until the
                // death is observed so the runner never reports the timeout
                // before cleanup has completed.
                session.terminate();
                let _ = tokio::time::timeout(TIMEOUT_REAP_GRACE, &mut exit_rx).await;
                let _ = tokio::time::timeout(TIMEOUT_REAP_GRACE, stdout_pump).await;
                let _ = tokio::time::timeout(TIMEOUT_REAP_GRACE, stderr_pump).await;
                Ok(TIMEOUT_EXIT_CODE)
            }
        }
    }

    async fn finish_pump(handle: tokio::task::JoinHandle<()>) {
        if let Err(err) = handle.await {
            eprintln!("ls-windows-sandbox-exec: output pump failed: {err}");
        }
    }

    async fn pump<W>(mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>, mut sink: W)
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        while let Some(chunk) = rx.recv().await {
            if sink.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = sink.flush().await;
    }
}

#[cfg(target_os = "windows")]
pub use windows_backend::build_session_request;
#[cfg(target_os = "windows")]
use windows_backend::execute_plan;

#[cfg(not(target_os = "windows"))]
async fn execute_plan(_plan: &WindowsSandboxLaunchPlan) -> Result<i32, String> {
    Err("platform-unavailable: ls-windows-sandbox-exec only runs on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_env() -> Vec<(String, String)> {
        vec![
            ("PATH".to_string(), r"C:\Windows\system32".to_string()),
            ("PATHEXT".to_string(), ".COM;.EXE;.BAT".to_string()),
            ("SystemRoot".to_string(), r"C:\Windows".to_string()),
            ("WINDIR".to_string(), r"C:\Windows".to_string()),
            ("TEMP".to_string(), r"C:\Temp".to_string()),
            ("TMP".to_string(), r"C:\Temp".to_string()),
            (
                "OPENCODE_API_KEY".to_string(),
                "canary-opencode".to_string(),
            ),
            (
                "DEEPSEEK_API_KEY".to_string(),
                "canary-deepseek".to_string(),
            ),
            (
                "LS_RUNTIME_UPSTREAM_API_KEY".to_string(),
                "canary-leapsea-bridge".to_string(),
            ),
            (
                "RB_RUNTIME_UPSTREAM_API_KEY".to_string(),
                "canary-legacy-bridge".to_string(),
            ),
            ("RANDOM_CALLER_VAR".to_string(), "dropped".to_string()),
            ("APPDATA".to_string(), r"C:\Users\x\AppData".to_string()),
        ]
    }

    #[test]
    fn env_filter_keeps_only_the_fixed_allowlist() {
        let environment = filtered_environment_from(parent_env());
        assert_eq!(environment.len(), 4);
        for key in ["PATH", "PATHEXT", "SystemRoot", "WINDIR"] {
            assert!(
                environment.iter().any(|(existing, _)| existing == key),
                "allowlist key {key} must be preserved"
            );
        }
        for secret in [
            "OPENCODE_API_KEY",
            "DEEPSEEK_API_KEY",
            "LS_RUNTIME_UPSTREAM_API_KEY",
            "RB_RUNTIME_UPSTREAM_API_KEY",
            "RANDOM_CALLER_VAR",
            "APPDATA",
            "TEMP",
            "TMP",
        ] {
            assert!(
                !environment.iter().any(|(existing, _)| existing == secret),
                "{secret} must be dropped"
            );
        }
    }

    #[test]
    fn env_filter_matches_windows_keys_case_insensitively() {
        let environment = filtered_environment_from([
            ("Path", r"C:\tools"),
            ("pathext", ".EXE;.CMD"),
            ("SYSTEMROOT", r"C:\Windows"),
            ("windir", r"C:\Windows"),
        ]);
        assert_eq!(
            environment,
            vec![
                ("PATH".to_string(), r"C:\tools".to_string()),
                ("PATHEXT".to_string(), ".EXE;.CMD".to_string()),
                ("SystemRoot".to_string(), r"C:\Windows".to_string()),
                ("WINDIR".to_string(), r"C:\Windows".to_string()),
            ]
        );
    }

    #[test]
    fn env_filter_drops_non_utf8_entries() {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let invalid = std::ffi::OsString::from_wide(&[0xD800u16]);
            let environment =
                filtered_environment_from(vec![(invalid, std::ffi::OsString::from("v"))]);
            assert!(environment.is_empty());
        }
    }

    #[test]
    fn failure_reason_is_single_line() {
        assert_eq!(
            flatten_failure_reason("alpha\nbeta\rgamma"),
            "alpha beta gamma"
        );
    }

    #[test]
    fn failure_reason_is_bounded() {
        let long = "x".repeat(10_000);
        let flattened = flatten_failure_reason(&long);
        assert!(flattened.len() <= MAX_FAILURE_REASON_CHARS);
    }

    #[test]
    fn parse_cli_reports_syntax_errors_without_touching_the_filesystem() {
        assert!(parse_cli(&[]).is_err());
        assert!(parse_cli(&["--".to_string()]).is_err());
    }

    /// Task 2 adapter tests: the launch plan and session request pin every
    /// knob shut.
    #[cfg(windows)]
    mod adapter {
        use super::*;
        use codex_protocol::permissions::NetworkSandboxPolicy;

        fn canonical_temp_dir() -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().expect("tempdir");
            let canonical = dunce::canonicalize(dir.path()).expect("canonicalize tempdir");
            (dir, canonical)
        }

        fn options_for(root: &Path, home: &Path) -> WindowsSandboxExecOptions {
            WindowsSandboxExecOptions {
                workspace_root: root.to_path_buf(),
                codex_home: home.to_path_buf(),
                timeout_ms: None,
            }
        }

        fn sample_command() -> Vec<String> {
            vec!["cmd".to_string(), "/c".to_string(), "echo ok".to_string()]
        }

        #[test]
        fn launch_plan_contains_exactly_the_frozen_profile() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let plan = build_launch_plan(
                &options_for(&root, &codex_home),
                &sample_command(),
                parent_env(),
            )
            .unwrap();
            // Exactly one materialized workspace root.
            assert_eq!(plan.workspace_roots.len(), 1);
            assert_eq!(plan.workspace_roots[0].as_path(), root);
            // Fixed managed workspace-write permissions with restricted
            // network.
            assert_eq!(
                plan.permission_profile,
                PermissionProfile::workspace_write()
            );
            match &plan.permission_profile {
                PermissionProfile::Managed { network, .. } => assert!(
                    matches!(network, NetworkSandboxPolicy::Restricted),
                    "network policy must be restricted"
                ),
                other => panic!("expected a managed permission profile, got {other:?}"),
            }
            // The permissions must resolve for the Windows sandbox.
            let resolved =
                codex_windows_sandbox::ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                    &plan.permission_profile,
                    &plan.workspace_roots,
                );
            assert!(resolved.is_ok(), "frozen profile must be enforceable");
            // The command runs inside the workspace root.
            assert_eq!(plan.cwd, root);
            // Bounded environment without provider credentials.
            assert!(plan.env.iter().all(|(key, _)| {
                ["PATH", "PATHEXT", "SystemRoot", "WINDIR", "TEMP", "TMP"].contains(&key.as_str())
            }));
            assert_eq!(
                plan.env
                    .iter()
                    .find(|(key, _)| key == "TEMP")
                    .map(|(_, value)| value.as_str()),
                plan.command_temp_root.to_str()
            );
            assert_eq!(plan.timeout_ms, None);
        }

        #[test]
        fn session_request_has_no_widening_knobs() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let plan = build_launch_plan(
                &options_for(&root, &codex_home),
                &sample_command(),
                parent_env(),
            )
            .unwrap();
            let request = build_session_request(&plan);
            assert_eq!(request.workspace_roots.len(), 1);
            assert_eq!(request.workspace_roots[0].as_path(), root);
            assert!(request.read_roots_override.is_none());
            assert!(request.write_roots_override.is_none());
            assert!(request.deny_read_paths_override.is_empty());
            assert_eq!(request.deny_write_paths_override, plan.deny_write_paths);
            assert!(!request.proxy_enforced);
            assert!(request.network_proxy_restricting_sid.is_none());
            assert!(!request.use_private_desktop);
            assert!(!request.tty);
            assert!(!request.stdin_open);
            assert!(!request.preserve_descendants_on_root_exit);
            assert_eq!(
                request.windows_sandbox_level,
                WindowsSandboxLevel::RestrictedToken
            );
            // The runner owns the timeout (124 semantics), not the backend.
            assert_eq!(request.timeout_ms, None);
            // The sandboxed environment carries the allowlist, never secrets.
            assert!(!request.env_map.contains_key("OPENCODE_API_KEY"));
            assert!(!request.env_map.contains_key("DEEPSEEK_API_KEY"));
            assert!(!request.env_map.contains_key("LS_RUNTIME_UPSTREAM_API_KEY"));
            assert!(!request.env_map.contains_key("RB_RUNTIME_UPSTREAM_API_KEY"));
            assert!(request.env_map.contains_key("PATH"));
        }

        #[test]
        fn launch_plan_requires_a_command() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let error =
                build_launch_plan(&options_for(&root, &codex_home), &[], parent_env()).unwrap_err();
            assert!(error.contains("missing command"));
        }

        #[test]
        fn launch_plan_revalidates_canonical_roots() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let options = WindowsSandboxExecOptions {
                workspace_root: root.join("sub").join(".."),
                codex_home,
                timeout_ms: None,
            };
            let error = build_launch_plan(&options, &sample_command(), parent_env()).unwrap_err();
            assert!(error.contains("canonical"), "got: {error}");
        }
    }
}

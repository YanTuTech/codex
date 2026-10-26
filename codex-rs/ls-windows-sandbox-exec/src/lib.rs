//! `ls-windows-sandbox-exec` is the Windows runner shell that executes a
//! single command inside a Codex-managed Windows sandbox on behalf of
//! LeapSea's managed runtime.
//!
//! The runner delegates filesystem, token, process-tree, and network-policy
//! projection to the shared `codex-windows-sandbox` implementation; this crate
//! never hand-writes token, ACL, Job Object, or WFP policy. It accepts exactly
//! one canonical workspace root plus optional Host-authorized extra write
//! roots (never model input), and a Host-selected closed sandbox mode: the
//! default `workspace-write` profile or the strictly narrower `read-only`
//! profile (commands execute inside the sandbox with every write denied,
//! including the runner-managed TEMP/TMP root). Host authority additionally
//! selects either the product-scoped `Elevated` backend (dedicated
//! low-privilege identity + kernel WFP denial) or the explicitly weaker
//! `RestrictedToken` backend (current-user restricted token + environment
//! offline controls). No selection falls back to unsandboxed execution.
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
/// Upper bound on Host-authorized extra write roots per command. The Host
/// enforces the same cap; the runner re-checks so a runaway caller cannot
/// project an unbounded ACL surface onto one sandboxed command.
const MAX_EXTRA_WRITE_ROOTS: usize = 4;
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

/// Host-selected backend. The runner accepts only these two closed values;
/// roots, policy JSON, network allowlists, and arbitrary sandbox flags remain
/// unavailable to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsSandboxBackend {
    Elevated,
    RestrictedToken,
}

#[cfg(target_os = "windows")]
pub fn selected_windows_sandbox_level(backend: WindowsSandboxBackend) -> WindowsSandboxLevel {
    match backend {
        WindowsSandboxBackend::Elevated => WindowsSandboxLevel::Elevated,
        WindowsSandboxBackend::RestrictedToken => WindowsSandboxLevel::RestrictedToken,
    }
}

/// Host-selected sandbox mode. The runner accepts only these two closed
/// values: the default `workspace-write` profile (the one materialized
/// workspace root plus the runner-managed TEMP/TMP root stay writable) and the
/// strictly narrower `read-only` profile (the sandboxed command may read the
/// workspace but every write is denied, including TEMP/TMP; there is no
/// writable root at all). Arbitrary per-root policy, network, and environment
/// knobs remain unavailable to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindowsSandboxMode {
    #[default]
    WorkspaceWrite,
    ReadOnly,
}

/// Parsed runner inputs that do not depend on the command being executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSandboxExecOptions {
    /// Host-selected strong or weaker sandbox backend. Defaults to Elevated
    /// when omitted for backwards compatibility with already pinned callers.
    pub backend: WindowsSandboxBackend,
    /// Host-selected closed sandbox mode. Defaults to `workspace-write` for
    /// backwards compatibility with already pinned callers.
    pub mode: WindowsSandboxMode,
    /// The one writable workspace root. It must already be canonical
    /// (absolute, existing, a directory, and free of symlink/junction or
    /// `..` components) so the sandbox policy never contains aliased path
    /// components. It is also the working directory of the sandboxed command.
    /// Under `read-only` it stays readable but never becomes writable.
    pub workspace_root: PathBuf,
    /// Optional extra writable roots, each individually user-authorized by
    /// the Host (never model input). Same canonical-directory contract as
    /// [`Self::workspace_root`]; they must not overlap the workspace root,
    /// the sandbox state root, or each other. Under `read-only` the grammar
    /// rejects them outright: the no-writable-root property is never widened.
    pub extra_write_roots: Vec<PathBuf>,
    /// Optional Host-projected working directory for the sandboxed command,
    /// workspace-relative and forward-slash separated (`.` = root). Syntax
    /// only here; [`build_launch_plan`] resolves it under the canonical
    /// workspace root and refuses to launch the command body when the
    /// directory is missing, not a directory, or escapes the root
    /// (`cwd-inaccessible` / `cwd-invalid`). The command body can never run
    /// in a different directory than the Host authorized.
    pub cwd_relative: Option<String>,
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
    /// Backend chosen by the Host before the plan is built.
    pub backend: WindowsSandboxBackend,
    /// Sandbox mode chosen by the Host before the plan is built.
    pub sandbox_mode: WindowsSandboxMode,
    /// Exactly one materialized workspace root.
    pub workspace_roots: Vec<AbsolutePathBuf>,
    /// The closed Codex managed permission profile selected by
    /// [`WindowsSandboxMode`]: `workspace-write` or `read-only`, both with
    /// restricted network; enforcement comes from the selected backend.
    pub permission_profile: PermissionProfile,
    /// Validated sandbox state directory.
    pub codex_home: PathBuf,
    /// The sandboxed command argv.
    pub command: Vec<String>,
    /// Working directory of the sandboxed command: the canonical workspace
    /// root, or the Host-projected `--cwd-relative` directory resolved and
    /// validated inside it.
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
/// `--workspace-root <dir> --codex-home <dir> [--backend <elevated|restricted-token>] [--sandbox-mode <workspace-write|read-only>] [--cwd-relative <dir>] [--timeout-ms <n>] [--extra-write-root <dir>]... -- <command>...`
///
/// Syntax only; filesystem validation happens in
/// [`build_launch_plan`]. No other flag exists on purpose:
/// policy JSON, network mode, and environment overrides are
/// not caller-settable. The repeatable `--extra-write-root` is the only
/// root-widening surface and exists exclusively for Host-projected,
/// user-authorized write roots; it is rejected under `read-only`.
/// `--cwd-relative` is Host-projected too: the working directory of the
/// sandboxed command, resolved strictly inside the workspace root.
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
    let mut backend: Option<WindowsSandboxBackend> = None;
    let mut mode: Option<WindowsSandboxMode> = None;
    let mut extra_write_roots: Vec<String> = Vec::new();
    let mut cwd_relative: Option<String> = None;

    let mut index = 0;
    while index < flags.len() {
        let flag = flags[index].as_str();
        match flag {
            "--workspace-root" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                replace_once(&mut workspace_root, value, flag)?;
            }
            "--cwd-relative" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                validate_relative_cwd_syntax(&value)?;
                replace_once(&mut cwd_relative, value, flag)?;
            }
            "--extra-write-root" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                if extra_write_roots.contains(&value) {
                    return Err(format!(
                        "duplicate value for {flag}: `{value}` (each extra root may appear once)"
                    ));
                }
                if extra_write_roots.len() >= MAX_EXTRA_WRITE_ROOTS {
                    return Err(format!(
                        "too many {flag} values (at most {MAX_EXTRA_WRITE_ROOTS})"
                    ));
                }
                extra_write_roots.push(value);
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
            "--backend" => {
                let value = next_flag_value(flags, &mut index, flag)?;
                if backend.is_some() {
                    return Err(format!("duplicate flag {flag}"));
                }
                backend = Some(match value.as_str() {
                    "elevated" => WindowsSandboxBackend::Elevated,
                    "restricted-token" => WindowsSandboxBackend::RestrictedToken,
                    _ => return Err(format!("invalid value for {flag}: `{value}`")),
                });
            }
            "--sandbox-mode" => {
                let value = next_flag_value(flags, &mut index, flag)?;
                if mode.is_some() {
                    return Err(format!("duplicate flag {flag}"));
                }
                mode = Some(match value.as_str() {
                    "workspace-write" => WindowsSandboxMode::WorkspaceWrite,
                    "read-only" => WindowsSandboxMode::ReadOnly,
                    _ => return Err(format!("invalid value for {flag}: `{value}`")),
                });
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }

    let workspace_root =
        workspace_root.ok_or_else(|| "missing required flag --workspace-root <dir>".to_string())?;
    let codex_home =
        codex_home.ok_or_else(|| "missing required flag --codex-home <dir>".to_string())?;
    let mode = mode.unwrap_or_default();
    if mode == WindowsSandboxMode::ReadOnly && !extra_write_roots.is_empty() {
        return Err("--extra-write-root is incompatible with --sandbox-mode read-only".to_string());
    }
    Ok(WindowsSandboxExecOptions {
        backend: backend.unwrap_or(WindowsSandboxBackend::Elevated),
        mode,
        workspace_root: PathBuf::from(workspace_root),
        extra_write_roots: extra_write_roots.into_iter().map(PathBuf::from).collect(),
        cwd_relative,
        codex_home: PathBuf::from(codex_home),
        timeout_ms,
    })
}

/// `--cwd-relative` syntax gate: forward-slash separated workspace-relative
/// path (`.` = root), bounded, without drive letters, backslashes, empty,
/// `.`, or `..` components. Filesystem resolution happens in
/// [`build_launch_plan`] so the failure reasons stay distinguishable.
fn validate_relative_cwd_syntax(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 1024 {
        return Err(
            "invalid value for --cwd-relative: bounded non-empty path expected".to_string(),
        );
    }
    if value.starts_with('/') || value.starts_with('\\') || value.contains('\\') {
        return Err(
            "invalid value for --cwd-relative: forward-slash relative path expected".to_string(),
        );
    }
    if value.len() >= 2 && value.as_bytes()[1] == b':' {
        return Err(
            "invalid value for --cwd-relative: drive-qualified paths are rejected".to_string(),
        );
    }
    if value != "." {
        for part in value.split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return Err(format!(
                    "invalid value for --cwd-relative: plain segments expected, got `{value}`"
                ));
            }
        }
    }
    Ok(())
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
/// the only place the closed profile is chosen: one canonical workspace root,
/// the Host-selected Codex managed profile (`workspace-write` or
/// `read-only`), a runner-owned TEMP/TMP root, the fixed environment
/// allowlist, and no override knobs at all. Under `read-only` the managed
/// TEMP/TMP root still exists and is exported through the environment, but it
/// is never granted to the sandbox identity: every write, including scratch
/// writes, fails closed.
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
    // Host-projected working directory: resolved under the canonical
    // workspace root. Every failure here runs BEFORE the sandboxed command
    // body exists, so a broken cwd can never degrade into running the
    // command somewhere else.
    let cwd = match &options.cwd_relative {
        None => workspace_root.clone(),
        Some(relative) => {
            let joined = if relative == "." {
                workspace_root.clone()
            } else {
                workspace_root.join(relative.replace('/', "\\"))
            };
            let canonical = dunce::canonicalize(&joined).map_err(|_| {
                format!("cwd-inaccessible: --cwd-relative `{relative}` cannot be opened inside the workspace root")
            })?;
            if !canonical.starts_with(&workspace_root) {
                return Err(format!(
                    "cwd-invalid: --cwd-relative `{relative}` escapes the workspace root"
                ));
            }
            if !canonical.is_dir() {
                return Err(format!(
                    "cwd-inaccessible: --cwd-relative `{relative}` is not a directory"
                ));
            }
            canonical
        }
    };
    // Extra write roots: same canonical-directory contract, plus pairwise and
    // against-root overlap rejection so the ACL surface stays a disjoint set
    // of user-authorized directories.
    let mut extra_roots = Vec::with_capacity(options.extra_write_roots.len());
    for raw in &options.extra_write_roots {
        let extra = validate_canonical_directory(raw, "--extra-write-root")?;
        if paths_overlap(&extra, &workspace_root)
            || paths_overlap(&extra, &codex_home)
            || extra_roots
                .iter()
                .any(|previous: &PathBuf| paths_overlap(previous, &extra))
        {
            return Err(format!(
                "--extra-write-root must not overlap the workspace, the sandbox state root, or another extra root: `{}`",
                raw.display()
            ));
        }
        extra_roots.push(extra);
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
        || extra_roots
            .iter()
            .any(|extra| paths_overlap(extra, &command_temp_root))
    {
        return Err(
            "managed TEMP must not overlap the workspace or sandbox state root".to_string(),
        );
    }
    let absolute_root = AbsolutePathBuf::from_absolute_path(&workspace_root)
        .map_err(|err| format!("--workspace-root is not absolute: {err}"))?;
    let denied_codex_home = AbsolutePathBuf::from_absolute_path(&codex_home)
        .map_err(|err| format!("--codex-home is not absolute: {err}"))?;
    let mut deny_write_paths = vec![denied_codex_home];
    // Defense-in-depth carveouts on every user-authorized extra root: an
    // existing `.git`/`.agents` directory stays read-only exactly like the
    // workspace root's own copy. Only directories that already exist are
    // pinned; the runner never fabricates paths inside a user directory.
    for extra in &extra_roots {
        for protected in [".git", ".agents"] {
            let candidate = extra.join(protected);
            if candidate.is_dir() {
                deny_write_paths.push(
                    AbsolutePathBuf::from_absolute_path(&candidate)
                        .map_err(|err| format!("--extra-write-root is not absolute: {err}"))?,
                );
            }
        }
    }
    let permission_profile = match options.mode {
        WindowsSandboxMode::WorkspaceWrite => PermissionProfile::workspace_write(),
        WindowsSandboxMode::ReadOnly => PermissionProfile::read_only(),
    };
    let mut env = filtered_environment_from(parent_vars);
    let managed_temp = command_temp_root.to_string_lossy().into_owned();
    env.push(("TEMP".to_string(), managed_temp.clone()));
    env.push(("TMP".to_string(), managed_temp));
    let mut workspace_roots = Vec::with_capacity(extra_roots.len() + 1);
    workspace_roots.push(absolute_root);
    for extra in extra_roots {
        workspace_roots.push(
            AbsolutePathBuf::from_absolute_path(&extra)
                .map_err(|err| format!("--extra-write-root is not absolute: {err}"))?,
        );
    }
    Ok(WindowsSandboxLaunchPlan {
        backend: options.backend,
        sandbox_mode: options.mode,
        workspace_roots,
        permission_profile,
        codex_home,
        command: command.to_vec(),
        cwd,
        env,
        command_temp_root,
        deny_write_paths,
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
    /// widening knob pinned shut. The explicit empty read-root override is
    /// security-significant: `None` asks Codex workspace-write to grant the
    /// sandbox account read access across the real user's profile, while V1
    /// permits only the workspace, sandbox-owned roots, and the OS/toolchain
    /// closure already readable by the low-privilege Windows identity.
    ///
    /// Descendants are preserved at the backend level because the elevated
    /// backend does not support terminating them on root exit; the runner's
    /// own exit paths always call `session.terminate()`, which kills the
    /// whole non-breakaway Job Object (kill-on-close), so nothing survives a
    /// completed or timed-out tool call.
    pub fn build_session_request(
        plan: &WindowsSandboxLaunchPlan,
    ) -> WindowsSandboxSessionRequest<'_> {
        const NO_EXTRA_READ_ROOTS: &[PathBuf] = &[];
        const NO_WRITE_ROOTS: &[PathBuf] = &[];
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
            windows_sandbox_level: super::selected_windows_sandbox_level(plan.backend),
            proxy_enforced: false,
            network_proxy_restricting_sid: None,
            proxy_settings_mode: WindowsSandboxProxySettingsMode::default(),
            timeout_ms: None,
            read_roots_override: Some(NO_EXTRA_READ_ROOTS),
            read_roots_include_platform_defaults: false,
            // `read-only` pins an explicit empty write-root override so the
            // no-writable-root property does not depend on profile
            // derivation; `workspace-write` keeps `None` and lets the
            // profile materialize the workspace plus TEMP/TMP roots.
            write_roots_override: match plan.sandbox_mode {
                WindowsSandboxMode::ReadOnly => Some(NO_WRITE_ROOTS),
                WindowsSandboxMode::WorkspaceWrite => None,
            },
            deny_read_paths_override: NO_DENY_PATHS,
            deny_write_paths_override: &plan.deny_write_paths,
            tty: false,
            stdin_open: false,
            // V1 security profile: the sandboxed command runs on a private
            // desktop so it cannot interact with the user's interactive
            // desktop.
            use_private_desktop: true,
            // The elevated backend requires descendants to be preserved at
            // the session level; the runner terminates the full tree itself.
            preserve_descendants_on_root_exit: true,
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
        let base = [
            "--workspace-root",
            r"C:\workspace",
            "--codex-home",
            r"C:\codex-home",
        ];
        let args = base
            .into_iter()
            .chain(["--backend", "restricted-token", "--", "cmd"])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            parse_cli(&args).unwrap().backend,
            WindowsSandboxBackend::RestrictedToken
        );
        let invalid = base
            .into_iter()
            .chain(["--backend", "unknown", "--", "cmd"])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(parse_cli(&invalid).is_err());
    }

    #[test]
    fn parse_cli_accepts_repeatable_extra_write_roots_with_a_cap() {
        let base = [
            "--workspace-root",
            r"C:\workspace",
            "--codex-home",
            r"C:\codex-home",
        ];
        let args = base
            .clone()
            .into_iter()
            .chain([
                "--extra-write-root",
                r"C:\wbgds",
                "--extra-write-root",
                r"C:\cache",
                "--",
                "cmd",
            ])
            .map(str::to_string)
            .collect::<Vec<_>>();
        let options = parse_cli(&args).unwrap();
        assert_eq!(
            options.extra_write_roots,
            vec![PathBuf::from(r"C:\wbgds"), PathBuf::from(r"C:\cache")]
        );
        // The same root twice is rejected at parse time.
        let duplicate = base
            .clone()
            .into_iter()
            .chain([
                "--extra-write-root",
                r"C:\wbgds",
                "--extra-write-root",
                r"C:\wbgds",
                "--",
                "cmd",
            ])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(
            parse_cli(&duplicate)
                .unwrap_err()
                .contains("duplicate value for --extra-write-root")
        );
        // The Host cap is re-checked by the grammar.
        let too_many = base
            .into_iter()
            .chain([
                "--extra-write-root",
                "a",
                "--extra-write-root",
                "b",
                "--extra-write-root",
                "c",
                "--extra-write-root",
                "d",
                "--extra-write-root",
                "e",
                "--",
                "cmd",
            ])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(
            parse_cli(&too_many)
                .unwrap_err()
                .contains("too many --extra-write-root")
        );
    }

    #[test]
    fn parse_cli_rejects_extra_write_roots_under_read_only() {
        let args = [
            "--workspace-root",
            r"C:\workspace",
            "--codex-home",
            r"C:\codex-home",
            "--sandbox-mode",
            "read-only",
            "--extra-write-root",
            r"C:\wbgds",
            "--",
            "cmd",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let error = parse_cli(&args).unwrap_err();
        assert!(
            error.contains("--extra-write-root is incompatible"),
            "got: {error}"
        );
    }

    #[test]
    fn parse_cli_accepts_and_bounds_the_cwd_relative_flag() {
        let base = [
            "--workspace-root",
            r"C:\workspace",
            "--codex-home",
            r"C:\codex-home",
        ];
        let with_cwd = base
            .into_iter()
            .chain(["--cwd-relative", "mask/layout", "--", "cmd"])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            parse_cli(&with_cwd).unwrap().cwd_relative.as_deref(),
            Some("mask/layout")
        );
        // `.` is the explicit workspace root.
        let root_cwd = [
            "--workspace-root",
            r"C:\workspace",
            "--codex-home",
            r"C:\codex-home",
            "--cwd-relative",
            ".",
            "--",
            "cmd",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        assert_eq!(
            parse_cli(&root_cwd).unwrap().cwd_relative.as_deref(),
            Some(".")
        );
        // Escaping, absolute, drive-qualified, backslash, and empty values
        // all reject before the filesystem is touched.
        for hostile in ["..", "a/../b", "a/./b", "/abs", r"C:\elsewhere", r"a\b", ""] {
            let invalid = [
                "--workspace-root",
                r"C:\workspace",
                "--codex-home",
                r"C:\codex-home",
                "--cwd-relative",
                hostile,
                "--",
                "cmd",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
            let error = parse_cli(&invalid).unwrap_err();
            assert!(
                error.contains("invalid value for --cwd-relative"),
                "value {hostile:?} must be rejected; got: {error}"
            );
        }
        // Duplicates reject like every other single-value flag.
        let duplicate = [
            "--workspace-root",
            r"C:\workspace",
            "--codex-home",
            r"C:\codex-home",
            "--cwd-relative",
            "a",
            "--cwd-relative",
            "b",
            "--",
            "cmd",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        assert!(
            parse_cli(&duplicate)
                .unwrap_err()
                .contains("duplicate flag --cwd-relative")
        );
    }

    #[test]
    fn parse_cli_accepts_only_the_closed_sandbox_mode_values() {
        let base = [
            "--workspace-root",
            r"C:\workspace",
            "--codex-home",
            r"C:\codex-home",
        ];
        let readonly = base
            .into_iter()
            .chain(["--sandbox-mode", "read-only", "--", "cmd"])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            parse_cli(&readonly).unwrap().mode,
            WindowsSandboxMode::ReadOnly
        );
        let workspace_write = base
            .into_iter()
            .chain(["--sandbox-mode", "workspace-write", "--", "cmd"])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            parse_cli(&workspace_write).unwrap().mode,
            WindowsSandboxMode::WorkspaceWrite
        );
        // Omitted mode keeps the backwards-compatible default.
        let default = base
            .into_iter()
            .chain(["--", "cmd"])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            parse_cli(&default).unwrap().mode,
            WindowsSandboxMode::WorkspaceWrite
        );
        // Closed enum: every other value is rejected.
        for hostile in ["readonly", "read_only", "danger-full-access", "full"] {
            let invalid = base
                .into_iter()
                .chain(["--sandbox-mode", hostile, "--", "cmd"])
                .map(str::to_string)
                .collect::<Vec<_>>();
            let error = parse_cli(&invalid).unwrap_err();
            assert!(
                error.contains("invalid value for --sandbox-mode"),
                "value {hostile:?} must be rejected; got: {error}"
            );
        }
        // Duplicates are rejected like every other flag.
        let duplicate = base
            .into_iter()
            .chain([
                "--sandbox-mode",
                "read-only",
                "--sandbox-mode",
                "workspace-write",
                "--",
                "cmd",
            ])
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(
            parse_cli(&duplicate)
                .unwrap_err()
                .contains("duplicate flag --sandbox-mode")
        );
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
                backend: WindowsSandboxBackend::Elevated,
                mode: WindowsSandboxMode::WorkspaceWrite,
                workspace_root: root.to_path_buf(),
                extra_write_roots: Vec::new(),
                cwd_relative: None,
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
            assert_eq!(request.read_roots_override, Some([].as_slice()));
            assert!(request.write_roots_override.is_none());
            assert!(request.deny_read_paths_override.is_empty());
            assert_eq!(request.deny_write_paths_override, plan.deny_write_paths);
            assert!(!request.proxy_enforced);
            assert!(request.network_proxy_restricting_sid.is_none());
            assert!(request.use_private_desktop);
            assert!(!request.tty);
            assert!(!request.stdin_open);
            assert!(
                request.use_private_desktop,
                "the frozen profile must run on a private desktop"
            );
            // Required by the elevated backend; the runner owns tree
            // termination through session.terminate() on every exit path.
            assert!(request.preserve_descendants_on_root_exit);
            assert_eq!(
                request.windows_sandbox_level,
                WindowsSandboxLevel::Elevated,
                "the live facade path must select only the elevated backend"
            );
            // The runner owns the timeout (124 semantics), not the backend.
            assert_eq!(request.timeout_ms, None);
            // The sandboxed environment carries the allowlist, never secrets.
            assert!(!request.env_map.contains_key("OPENCODE_API_KEY"));
            assert!(!request.env_map.contains_key("DEEPSEEK_API_KEY"));
            assert!(!request.env_map.contains_key("LS_RUNTIME_UPSTREAM_API_KEY"));
            assert!(!request.env_map.contains_key("RB_RUNTIME_UPSTREAM_API_KEY"));
            assert!(request.env_map.contains_key("PATH"));

            let mut restricted_options = options_for(&root, &codex_home);
            restricted_options.backend = WindowsSandboxBackend::RestrictedToken;
            let restricted_plan =
                build_launch_plan(&restricted_options, &sample_command(), parent_env()).unwrap();
            let restricted_request = build_session_request(&restricted_plan);
            assert_eq!(
                restricted_request.windows_sandbox_level,
                WindowsSandboxLevel::RestrictedToken
            );
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
        fn launch_plan_resolves_cwd_relative_inside_the_workspace_root() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            std::fs::create_dir(root.join("mask")).expect("create mask dir");
            let mut options = options_for(&root, &codex_home);
            options.cwd_relative = Some("mask".to_string());
            let plan = build_launch_plan(&options, &sample_command(), parent_env()).unwrap();
            assert_eq!(plan.cwd, root.join("mask"));
            // `.` keeps the workspace root as the working directory.
            let mut root_options = options_for(&root, &codex_home);
            root_options.cwd_relative = Some(".".to_string());
            let root_plan =
                build_launch_plan(&root_options, &sample_command(), parent_env()).unwrap();
            assert_eq!(root_plan.cwd, root);
        }

        #[test]
        fn launch_plan_refuses_a_missing_or_escaping_cwd_before_any_spawn() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let mut options = options_for(&root, &codex_home);
            options.cwd_relative = Some("missing-subdir".to_string());
            let error = build_launch_plan(&options, &sample_command(), parent_env()).unwrap_err();
            assert!(
                error.starts_with("cwd-inaccessible"),
                "a missing cwd must refuse launch; got: {error}"
            );
            // A regular file in the cwd position is not a directory.
            std::fs::write(root.join("notes.txt"), b"x").expect("write file");
            options.cwd_relative = Some("notes.txt".to_string());
            let file_error =
                build_launch_plan(&options, &sample_command(), parent_env()).unwrap_err();
            assert!(
                file_error.starts_with("cwd-inaccessible"),
                "a file cwd must refuse launch; got: {file_error}"
            );
        }

        #[test]
        fn launch_plan_revalidates_canonical_roots() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let options = WindowsSandboxExecOptions {
                backend: WindowsSandboxBackend::Elevated,
                mode: WindowsSandboxMode::WorkspaceWrite,
                workspace_root: root.join("sub").join(".."),
                extra_write_roots: Vec::new(),
                cwd_relative: None,
                codex_home,
                timeout_ms: None,
            };
            let error = build_launch_plan(&options, &sample_command(), parent_env()).unwrap_err();
            assert!(error.contains("canonical"), "got: {error}");
        }

        #[test]
        fn read_only_launch_plan_pins_the_narrower_profile() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let mut options = options_for(&root, &codex_home);
            options.mode = WindowsSandboxMode::ReadOnly;
            let plan = build_launch_plan(&options, &sample_command(), parent_env()).unwrap();
            // The read-only profile: no writable root exists at all.
            assert_eq!(plan.permission_profile, PermissionProfile::read_only());
            match &plan.permission_profile {
                PermissionProfile::Managed { network, .. } => assert!(
                    matches!(network, NetworkSandboxPolicy::Restricted),
                    "read-only network policy must stay restricted"
                ),
                other => panic!("expected a managed permission profile, got {other:?}"),
            }
            // The permissions must still resolve for the Windows sandbox
            // (the read-only capability path, not write capabilities).
            let resolved =
                codex_windows_sandbox::ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                    &plan.permission_profile,
                    &plan.workspace_roots,
                );
            assert!(resolved.is_ok(), "read-only profile must be enforceable");
            // TEMP/TMP still point at the managed root, but the root is not
            // exported as writable: the environment is unchanged and only the
            // profile decides writability.
            assert_eq!(
                plan.env
                    .iter()
                    .find(|(key, _)| key == "TEMP")
                    .map(|(_, value)| value.as_str()),
                plan.command_temp_root.to_str()
            );
        }

        #[test]
        fn read_only_session_request_pins_an_empty_write_root_override() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let mut options = options_for(&root, &codex_home);
            options.mode = WindowsSandboxMode::ReadOnly;
            let plan = build_launch_plan(&options, &sample_command(), parent_env()).unwrap();
            let request = build_session_request(&plan);
            assert_eq!(
                request.write_roots_override,
                Some([].as_slice()),
                "read-only must pin an explicit empty write-root override"
            );
            assert_eq!(request.read_roots_override, Some([].as_slice()));
            assert_eq!(request.deny_write_paths_override, plan.deny_write_paths);
        }

        #[test]
        fn launch_plan_appends_canonical_extra_write_roots() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let (_extra_keep, extra) = canonical_temp_dir();
            let mut options = options_for(&root, &codex_home);
            options.extra_write_roots = vec![extra.clone()];
            let plan = build_launch_plan(&options, &sample_command(), parent_env()).unwrap();
            // Main root first, extras after; the profile stays frozen.
            assert_eq!(plan.workspace_roots.len(), 2);
            assert_eq!(plan.workspace_roots[0].as_path(), root);
            assert_eq!(plan.workspace_roots[1].as_path(), extra);
            assert_eq!(
                plan.permission_profile,
                PermissionProfile::workspace_write()
            );
            // Multi-root permissions must still resolve for the sandbox.
            let resolved =
                codex_windows_sandbox::ResolvedWindowsSandboxPermissions::try_from_permission_profile_for_workspace_roots(
                    &plan.permission_profile,
                    &plan.workspace_roots,
                );
            assert!(resolved.is_ok(), "extra-root profile must be enforceable");
            // The session request carries the widened root set verbatim.
            let request = build_session_request(&plan);
            assert_eq!(request.workspace_roots.len(), 2);
            // Only the codex-home deny when no `.git`/`.agents` exists.
            assert_eq!(plan.deny_write_paths.len(), 1);
        }

        #[test]
        fn launch_plan_pins_existing_git_and_agents_dirs_in_extra_roots() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let (_extra_keep, extra) = canonical_temp_dir();
            std::fs::create_dir_all(extra.join(".git")).expect("create .git");
            let mut options = options_for(&root, &codex_home);
            options.extra_write_roots = vec![extra.clone()];
            let plan = build_launch_plan(&options, &sample_command(), parent_env()).unwrap();
            let denied: Vec<_> = plan
                .deny_write_paths
                .iter()
                .map(|path| path.as_path().to_path_buf())
                .collect();
            assert!(
                denied.contains(&extra.join(".git")),
                "existing .git in an extra root must be write-denied: {denied:?}"
            );
            assert!(
                !denied.contains(&extra.join(".agents")),
                "non-existing .agents must not be fabricated"
            );
        }

        #[test]
        fn launch_plan_rejects_extra_roots_overlapping_any_other_root() {
            let (_workspace, root) = canonical_temp_dir();
            let (_home, codex_home) = canonical_temp_dir();
            let (_extra_keep, extra) = canonical_temp_dir();
            let mut options = options_for(&root, &codex_home);
            // Overlaps the workspace root.
            options.extra_write_roots = vec![root];
            let error = build_launch_plan(&options, &sample_command(), parent_env()).unwrap_err();
            assert!(
                error.contains("must not overlap"),
                "workspace overlap must be rejected: {error}"
            );
            // Overlaps codex-home.
            options.extra_write_roots = vec![codex_home];
            let error = build_launch_plan(&options, &sample_command(), parent_env()).unwrap_err();
            assert!(error.contains("must not overlap"));
            // Pairwise overlap: two distinct raw paths that canonicalize into
            // an ancestor/descendant relationship.
            let child = extra.join("child");
            std::fs::create_dir_all(&child).expect("create child");
            options.extra_write_roots = vec![extra, child];
            let error = build_launch_plan(&options, &sample_command(), parent_env()).unwrap_err();
            assert!(
                error.contains("must not overlap"),
                "nested extras must be rejected: {error}"
            );
        }
    }
}

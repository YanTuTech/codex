//! `ls-windows-sandbox-exec` command line entry point.
//!
//! Usage:
//! ```text
//! ls-windows-sandbox-exec --workspace-root <canonical-directory>
//!                         --codex-home <sandbox-state-directory>
//!                         [--backend <elevated|restricted-token>]
//!                         [--sandbox-mode <workspace-write|read-only>]
//!                         [--cwd-relative <workspace-relative-directory>]
//!                         [--timeout-ms <positive-integer>]
//!                         -- <command> [args...]
//! ```
//!
//! Runner-own failures (argument errors, unusable roots, missing sandbox
//! prerequisites, or spawn errors) print a single
//! `LS_WINDOWS_SANDBOX_UNAVAILABLE:<reason>` line to stderr and exit with
//! 250. The command is never executed without a sandbox, and a failed
//! sandbox launch never falls back to unsandboxed host execution.

use ls_windows_sandbox_exec::RUNNER_FAILURE_EXIT_CODE;
use ls_windows_sandbox_exec::RUNNER_FAILURE_MARKER;

fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let options = match ls_windows_sandbox_exec::parse_cli(&raw_args) {
        Ok(options) => options,
        Err(reason) => fail_unavailable(&format!("invalid-arguments: {reason}")),
    };
    if let Err(reason) = ls_windows_sandbox_exec::validate_canonical_directory(
        &options.workspace_root,
        "--workspace-root",
    ) {
        fail_unavailable(&reason);
    }
    if let Err(reason) =
        ls_windows_sandbox_exec::validate_canonical_directory(&options.codex_home, "--codex-home")
    {
        fail_unavailable(&reason);
    }
    let command = match ls_windows_sandbox_exec::command_from_args(&raw_args) {
        Ok(command) => command,
        Err(reason) => fail_unavailable(&format!("invalid-arguments: {reason}")),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => fail_unavailable(&format!("runtime-failed: {err}")),
    };
    let exit_code = runtime.block_on(ls_windows_sandbox_exec::run_sandboxed(
        &options,
        &command,
        std::env::vars_os(),
    ));
    match exit_code {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(reason) => fail_unavailable(&reason),
    }
}

/// Single failure funnel: one bounded stderr line, exit 250, never run the
/// command.
fn fail_unavailable(reason: &str) -> ! {
    let reason = ls_windows_sandbox_exec::flatten_failure_reason(reason);
    eprintln!("{RUNNER_FAILURE_MARKER}:{reason}");
    std::process::exit(RUNNER_FAILURE_EXIT_CODE);
}

//! Explicit uninstall phase state machine.
//!
//! Uninstall is a resumable journal: every phase (`acl-removed →
//! firewall-removed → wfp-removed → accounts-removed → verified-absent →
//! state-deleted`) records its completion in a `cleanup_pending.json`
//! journal inside the protected sandbox state before the next phase runs.
//! Failures are collected and never downgraded to success; the final state
//! files (installation identity, setup marker, WFP ownership record, user
//! secrets) are deleted ONLY after every family's absence has been proven
//! by an exact-name/GUID/SID query, so a failed or crashed uninstall always
//! leaves a precise, retryable manifest behind.

use std::io::Write;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use codex_windows_sandbox::installation::SandboxInstallationIdentity;

pub const CLEANUP_JOURNAL_FILE_NAME: &str = "cleanup_pending.json";
pub const CLEANUP_JOURNAL_VERSION: u32 = 1;

/// Completed phases, in execution order. The journal stores the last
/// completed phase; a fresh uninstall starts before `Pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UninstallPhase {
    Pending,
    AclRemoved,
    FirewallRemoved,
    WfpRemoved,
    AccountsRemoved,
    VerifiedAbsent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupJournal {
    pub version: u32,
    pub install_id: String,
    pub ownership_digest: Option<String>,
    pub completed_phase: UninstallPhase,
    pub updated_at: String,
}

/// The uninstall's external effects, injected for tests. Production wiring
/// calls the real Win32/COM/WFP implementations; the state machine itself is
/// pure orchestration with journal persistence.
pub trait UninstallEffects {
    /// Reads the recorded roots from the setup marker, when present.
    fn recorded_roots(&self) -> Vec<PathBuf>;
    /// Resolves the sandbox group SID for ACE removal, when resolvable.
    fn group_sid(&self) -> Option<Vec<u8>>;
    /// Removes the group's allow ACEs from the recorded roots; returns the
    /// roots whose removal failed (failures are collected, not fatal here).
    fn remove_group_aces(&mut self, roots: &[PathBuf], sid: &[u8]) -> Vec<String>;
    /// Removes the installation's firewall rules (best effort).
    fn remove_firewall_rules(&mut self, identity: &SandboxInstallationIdentity);
    /// Names of the installation's firewall rules still present.
    fn firewall_rules_present(&self, identity: &SandboxInstallationIdentity) -> Vec<String>;
    /// Removes the recorded WFP objects (best effort).
    fn remove_wfp_objects(&mut self, identity: &SandboxInstallationIdentity);
    /// Descriptions of the recorded WFP objects still present.
    fn wfp_objects_present(&self, identity: &SandboxInstallationIdentity) -> Vec<String>;
    /// Removes the derived accounts and group (best effort).
    fn remove_accounts(&mut self, identity: &SandboxInstallationIdentity);
    /// Names of the derived accounts/group still present.
    fn accounts_present(&self, identity: &SandboxInstallationIdentity) -> Vec<String>;
    /// Deletes one terminal state file; missing files are fine.
    fn delete_state_file(&mut self, name: &str);
    /// Reads the persisted installation identity, when present.
    fn persisted_installation_id(&self) -> Option<String>;
    /// Digest of the persisted WFP ownership record, when present; the
    /// journal binds it so a swapped record cannot silently hijack a retry.
    fn ownership_digest(&self) -> Option<String>;
}

pub trait UninstallJournalIo {
    fn read_journal(&self) -> Option<CleanupJournal>;
    fn write_journal(&mut self, journal: &CleanupJournal) -> std::io::Result<()>;
    fn delete_journal(&mut self) -> std::io::Result<()>;
}

/// One phase's failure report; all failures across phases are aggregated and
/// the uninstall returns `Err` if the list is non-empty.
#[derive(Debug)]
pub struct UninstallFailure {
    pub phase: &'static str,
    pub detail: String,
}

/// Writes `journal` atomically: serialize to a sibling temp file, fsync,
/// rename over the target.
pub fn write_journal_atomic(
    journal: &CleanupJournal,
    open_temp: impl FnOnce(&str) -> std::io::Result<(PathBuf, std::fs::File)>,
    rename: impl FnOnce(&PathBuf, &str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec_pretty(journal)
        .map_err(|err| std::io::Error::other(format!("serialize cleanup journal: {err}")))?;
    let nonce = format!("{}.tmp-{}", CLEANUP_JOURNAL_FILE_NAME, journal.updated_at);
    let (temp_path, mut file) = open_temp(&nonce)?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(&payload)?;
        file.sync_all()?;
        drop(file);
        rename(&temp_path, CLEANUP_JOURNAL_FILE_NAME)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

/// Runs the full uninstall state machine. Returns Ok(()) only when every
/// phase completed and every family's absence was proven; otherwise the
/// journal (and all state files) survive for an exact retry.
pub fn run_uninstall(
    identity: &SandboxInstallationIdentity,
    effects: &mut dyn UninstallEffects,
    journal_io: &mut dyn UninstallJournalIo,
    now: impl Fn() -> String,
    log: &mut dyn FnMut(&str),
) -> Result<(), Vec<UninstallFailure>> {
    let mut failures: Vec<UninstallFailure> = Vec::new();
    let install_id = identity.install_id_hex();

    // Load or initialize the journal; verify it belongs to this identity.
    let mut journal = journal_io.read_journal();
    if let Some(existing) = &journal {
        if existing.version != CLEANUP_JOURNAL_VERSION {
            return Err(vec![UninstallFailure {
                phase: "journal",
                detail: format!(
                    "cleanup journal version {} is not {}; refusing to resume",
                    existing.version, CLEANUP_JOURNAL_VERSION
                ),
            }]);
        }
        if existing.install_id != install_id {
            return Err(vec![UninstallFailure {
                phase: "journal",
                detail: format!(
                    "cleanup journal belongs to installation {}; refusing to run for {}",
                    existing.install_id, install_id
                ),
            }]);
        }
    }
    // Ownership-record consistency: once journalled, a different persisted
    // record digest fails closed (the journal names the exact WFP keys).
    if let Some(journalled) = journal
        .as_ref()
        .and_then(|entry| entry.ownership_digest.clone())
    {
        let current = effects.ownership_digest();
        if current.is_some() && current != Some(journalled) {
            return Err(vec![UninstallFailure {
                phase: "journal",
                detail: "the WFP ownership record changed since the uninstall started; refusing to continue".to_string(),
            }]);
        }
    }

    let completed = journal.as_ref().map(|entry| entry.completed_phase);
    // The journal binds the ownership-record digest from its first write (or
    // the resumed journal keeps its original binding); a later mismatch with
    // the persisted record fails closed before any phase runs.
    let initial_ownership_digest = match journal
        .as_ref()
        .and_then(|entry| entry.ownership_digest.clone())
    {
        Some(existing) => Some(existing),
        None => effects.ownership_digest(),
    };
    let mut advance = |phase: UninstallPhase| -> std::io::Result<()> {
        let next = CleanupJournal {
            version: CLEANUP_JOURNAL_VERSION,
            install_id: install_id.clone(),
            ownership_digest: initial_ownership_digest.clone(),
            completed_phase: phase,
            updated_at: now(),
        };
        journal_io.write_journal(&next)?;
        journal = Some(next);
        Ok(())
    };

    // Identity consistency: the persisted installation identity, when
    // present, must match the request.
    if let Some(persisted) = effects.persisted_installation_id()
        && persisted != install_id
    {
        return Err(vec![UninstallFailure {
            phase: "journal",
            detail: format!(
                "persisted installation identity {persisted} does not match the uninstall request {install_id}"
            ),
        }]);
    }

    // ---- Phase 1: ACL removal ------------------------------------------
    if completed
        .map(|done| done < UninstallPhase::AclRemoved)
        .unwrap_or(true)
    {
        let roots = effects.recorded_roots();
        if let Some(sid) = effects.group_sid() {
            if roots.is_empty() {
                log("acl phase: no recorded roots in the setup marker; skipping ACE sweep");
            } else {
                let acl_failures = effects.remove_group_aces(&roots, &sid);
                for root in &acl_failures {
                    failures.push(UninstallFailure {
                        phase: "acl-removed",
                        detail: format!("ACE removal failed for {root}"),
                    });
                }
            }
        } else {
            log("acl phase: sandbox group no longer resolvable; skipping ACE sweep");
        }
        if let Err(err) = advance(UninstallPhase::AclRemoved) {
            failures.push(UninstallFailure {
                phase: "acl-removed",
                detail: format!("journal write failed: {err}"),
            });
            return Err(failures);
        }
        log("acl phase complete");
    }

    // ---- Phase 2: firewall removal -------------------------------------
    if completed
        .map(|done| done < UninstallPhase::FirewallRemoved)
        .unwrap_or(true)
    {
        effects.remove_firewall_rules(identity);
        if let Err(err) = advance(UninstallPhase::FirewallRemoved) {
            failures.push(UninstallFailure {
                phase: "firewall-removed",
                detail: format!("journal write failed: {err}"),
            });
            return Err(failures);
        }
        log("firewall phase complete");
    }

    // ---- Phase 3: WFP removal ------------------------------------------
    if completed
        .map(|done| done < UninstallPhase::WfpRemoved)
        .unwrap_or(true)
    {
        effects.remove_wfp_objects(identity);
        if let Err(err) = advance(UninstallPhase::WfpRemoved) {
            failures.push(UninstallFailure {
                phase: "wfp-removed",
                detail: format!("journal write failed: {err}"),
            });
            return Err(failures);
        }
        log("wfp phase complete");
    }

    // ---- Phase 4: account removal --------------------------------------
    if completed
        .map(|done| done < UninstallPhase::AccountsRemoved)
        .unwrap_or(true)
    {
        effects.remove_accounts(identity);
        if let Err(err) = advance(UninstallPhase::AccountsRemoved) {
            failures.push(UninstallFailure {
                phase: "accounts-removed",
                detail: format!("journal write failed: {err}"),
            });
            return Err(failures);
        }
        log("accounts phase complete");
    }

    // ---- Phase 5: verified absence -------------------------------------
    if completed
        .map(|done| done < UninstallPhase::VerifiedAbsent)
        .unwrap_or(true)
    {
        let firewall = effects.firewall_rules_present(identity);
        let wfp = effects.wfp_objects_present(identity);
        let accounts = effects.accounts_present(identity);
        if firewall.is_empty() && wfp.is_empty() && accounts.is_empty() {
            if let Err(err) = advance(UninstallPhase::VerifiedAbsent) {
                failures.push(UninstallFailure {
                    phase: "verified-absent",
                    detail: format!("journal write failed: {err}"),
                });
                return Err(failures);
            }
            log("verified-absent: every family proven gone");
        } else {
            if !firewall.is_empty() {
                failures.push(UninstallFailure {
                    phase: "verified-absent",
                    detail: format!("firewall rules still present: {}", firewall.join(", ")),
                });
            }
            if !wfp.is_empty() {
                failures.push(UninstallFailure {
                    phase: "verified-absent",
                    detail: format!("WFP objects still present: {}", wfp.join(", ")),
                });
            }
            if !accounts.is_empty() {
                failures.push(UninstallFailure {
                    phase: "verified-absent",
                    detail: format!("accounts still present: {}", accounts.join(", ")),
                });
            }
            // Absence not proven: keep the journal and the state files for a
            // precise retry; do NOT fall through to state deletion.
            return Err(failures);
        }
    }

    // Collected failures (e.g. ACL removal) block the terminal deletion:
    // the setup marker's root list is the retry manifest for a failed ACE
    // sweep, so state survives until a retry completes cleanly.
    if !failures.is_empty() {
        return Err(failures);
    }

    // ---- Phase 6: terminal state deletion ------------------------------
    // Only reached with verified absence and zero collected failures. The
    // WFP ownership record is deleted here as well: absence is proven, so
    // the manifest's purpose is fulfilled.
    for name in [
        "setup_marker.json",
        "installation.json",
        "sandbox_users.json",
        "setup_error.json",
        "wfp_ownership.json",
    ] {
        effects.delete_state_file(name);
    }
    if let Err(err) = journal_io.delete_journal() {
        return Err(vec![UninstallFailure {
            phase: "state-deleted",
            detail: format!("cleanup journal delete failed: {err}"),
        }]);
    }
    log("state-deleted: uninstall fully complete");
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

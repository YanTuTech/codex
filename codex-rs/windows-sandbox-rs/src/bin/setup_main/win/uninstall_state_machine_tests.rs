//! Failure-mode tests for the uninstall phase state machine. Every case uses
//! a fake effects harness: no UAC, no real accounts, WFP, firewall, or ACL
//! changes. The invariants under test:
//!
//! 1. A failed family removal returns non-zero AND keeps
//!    installation/marker/ownership state for an exact retry.
//! 2. Terminal state files are deleted only after every family's absence is
//!    proven.
//! 3. A retry with the same installation identity succeeds idempotently.

use super::uninstall_state_machine::{
    CleanupJournal, UninstallEffects, UninstallJournalIo, UninstallPhase, run_uninstall,
};
use codex_windows_sandbox::installation::SandboxInstallationIdentity;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

#[derive(Default)]
struct FakeEffects {
    roots: Vec<PathBuf>,
    sid: Option<Vec<u8>>,
    acl_failures: Vec<String>,
    firewall_removed: bool,
    firewall_attempts: usize,
    firewall_still_present: Vec<String>,
    wfp_removed: bool,
    wfp_attempts: usize,
    wfp_still_present: Vec<String>,
    accounts_removed: bool,
    account_attempts: usize,
    recover_on_delete: bool,
    accounts_still_present: Vec<String>,
    deleted_files: Vec<String>,
    persisted_installation_id: Option<String>,
    ownership_digest: Option<String>,
}

impl UninstallEffects for FakeEffects {
    fn recorded_roots(&self) -> Vec<PathBuf> {
        self.roots.clone()
    }
    fn group_sid(&self) -> Option<Vec<u8>> {
        self.sid.clone()
    }
    fn remove_group_aces(&mut self, _roots: &[PathBuf], _sid: &[u8]) -> Vec<String> {
        std::mem::take(&mut self.acl_failures)
    }
    fn remove_firewall_rules(&mut self, _identity: &SandboxInstallationIdentity) {
        self.firewall_removed = true;
        self.firewall_attempts += 1;
        if self.recover_on_delete {
            self.firewall_still_present.clear();
        }
    }
    fn firewall_rules_present(&self, _identity: &SandboxInstallationIdentity) -> Vec<String> {
        self.firewall_still_present.clone()
    }
    fn remove_wfp_objects(&mut self, _identity: &SandboxInstallationIdentity) {
        self.wfp_removed = true;
        self.wfp_attempts += 1;
        if self.recover_on_delete {
            self.wfp_still_present.clear();
        }
    }
    fn wfp_objects_present(&self, _identity: &SandboxInstallationIdentity) -> Vec<String> {
        self.wfp_still_present.clone()
    }
    fn remove_accounts(&mut self, _identity: &SandboxInstallationIdentity) {
        self.accounts_removed = true;
        self.account_attempts += 1;
        if self.recover_on_delete {
            self.accounts_still_present.clear();
        }
    }
    fn accounts_present(&self, _identity: &SandboxInstallationIdentity) -> Vec<String> {
        self.accounts_still_present.clone()
    }
    fn delete_state_file(&mut self, name: &str) {
        self.deleted_files.push(name.to_string());
    }
    fn persisted_installation_id(&self) -> Option<String> {
        self.persisted_installation_id.clone()
    }
    fn ownership_digest(&self) -> Option<String> {
        self.ownership_digest.clone()
    }
}

#[derive(Default)]
struct MemoryJournal {
    inner: RefCell<Option<CleanupJournal>>,
}

impl UninstallJournalIo for MemoryJournal {
    fn read_journal(&self) -> Option<CleanupJournal> {
        self.inner.borrow().clone()
    }
    fn write_journal(&mut self, journal: &CleanupJournal) -> std::io::Result<()> {
        *self.inner.borrow_mut() = Some(journal.clone());
        Ok(())
    }
    fn delete_journal(&mut self) -> std::io::Result<()> {
        *self.inner.borrow_mut() = None;
        Ok(())
    }
}

struct Harness {
    effects: FakeEffects,
    journal: Rc<MemoryJournal>,
    identity: SandboxInstallationIdentity,
}

impl Harness {
    fn new() -> Harness {
        Harness {
            effects: FakeEffects {
                sid: Some(vec![1, 2, 3]),
                persisted_installation_id: None,
                ..FakeEffects::default()
            },
            journal: Rc::default(),
            identity: SandboxInstallationIdentity::generate(),
        }
    }

    fn run(&mut self) -> Result<(), Vec<super::uninstall_state_machine::UninstallFailure>> {
        let effects = &mut self.effects;
        let journal = MemoryJournal::default();
        // Share state with the harness journal so tests can inspect it.
        *journal.inner.borrow_mut() = self.journal.inner.borrow().clone();
        let mut journal_adapter = JournalAdapter {
            live: Rc::clone(&self.journal),
            local: self.journal.inner.borrow().clone(),
        };
        let outcome = run_uninstall(
            &self.identity,
            effects,
            &mut journal_adapter,
            || "2026-09-07T00:00:00.000Z".to_string(),
            &mut |_message| {},
        );
        *self.journal.inner.borrow_mut() = journal_adapter.local.clone();
        outcome
    }

    fn journal_phase(&self) -> Option<UninstallPhase> {
        self.journal
            .inner
            .borrow()
            .as_ref()
            .map(|j| j.completed_phase)
    }
}

struct JournalAdapter {
    live: Rc<MemoryJournal>,
    local: Option<CleanupJournal>,
}

impl UninstallJournalIo for JournalAdapter {
    fn read_journal(&self) -> Option<CleanupJournal> {
        self.local.clone()
    }
    fn write_journal(&mut self, journal: &CleanupJournal) -> std::io::Result<()> {
        self.local = Some(journal.clone());
        *self.live.inner.borrow_mut() = Some(journal.clone());
        Ok(())
    }
    fn delete_journal(&mut self) -> std::io::Result<()> {
        self.local = None;
        *self.live.inner.borrow_mut() = None;
        Ok(())
    }
}

#[test]
fn wfp_removal_failure_keeps_state_and_is_retryable() {
    let mut harness = Harness::new();
    // Simulate: the WFP engine accepted the delete calls but one object
    // survives (e.g. a locked filter), so presence still reports it.
    harness.effects.wfp_still_present = vec!["filter:codex_wfp_dns_53_v4".to_string()];
    let result = harness.run();
    let failures = result.expect_err("unproven absence must fail");
    assert!(
        failures
            .iter()
            .any(|f| f.phase == "wfp-removed" && f.detail.contains("WFP objects still present")),
        "failures: {failures:?}"
    );
    // Non-zero exit is represented by the Err; the state files survive.
    assert!(
        harness.effects.deleted_files.is_empty(),
        "no terminal state file may be deleted before proven absence"
    );
    assert!(
        matches!(
            harness.journal_phase(),
            Some(UninstallPhase::FirewallRemoved)
        ),
        "journal records the last completed phase, got {:?}",
        harness.journal_phase()
    );
    // Retry with the SAME installation identity now succeeds once the
    // object is gone (e.g. after reboot released the lock).
    harness.effects.wfp_still_present.clear();
    harness
        .run()
        .expect("retry with the same identity must succeed");
    assert!(
        harness.journal_phase().is_none(),
        "journal removed at completion"
    );
}

#[test]
fn firewall_removal_failure_keeps_state() {
    let mut harness = Harness::new();
    harness.effects.firewall_still_present = vec!["ls_sbx_x_block_outbound".to_string()];
    let failures = harness.run().expect_err("firewall presence must fail");
    assert!(
        failures
            .iter()
            .any(|f| f.detail.contains("ls_sbx_x_block_outbound")),
        "failures: {failures:?}"
    );
    assert!(harness.effects.deleted_files.is_empty());
    assert!(
        matches!(harness.journal_phase(), Some(UninstallPhase::AclRemoved)),
        "failed removal must not advance the checkpoint"
    );
}

#[test]
fn acl_failure_preserves_later_resources_for_exact_retry() {
    let mut harness = Harness::new();
    harness.effects.roots = vec![PathBuf::from(r"C:\ws\locked-root")];
    harness.effects.acl_failures = vec![r"C:\ws\locked-root".to_string()];
    let failures = harness.run().expect_err("collected ACL failure must fail");
    assert!(
        failures
            .iter()
            .any(|f| f.phase == "acl-removed" && f.detail.contains("locked-root")),
        "failures: {failures:?}"
    );
    // Keep the trustee and confinement resources until ACL recovery.
    assert!(!harness.effects.firewall_removed);
    assert!(!harness.effects.wfp_removed);
    assert!(!harness.effects.accounts_removed);
    assert!(harness.effects.deleted_files.is_empty());
}

#[test]
fn account_removal_failure_keeps_installation_identity() {
    let mut harness = Harness::new();
    harness.effects.accounts_still_present = vec!["LsSbxOff-0123456789".to_string()];
    let failures = harness.run().expect_err("account presence must fail");
    assert!(
        failures
            .iter()
            .any(|f| f.detail.contains("LsSbxOff-0123456789")),
        "failures: {failures:?}"
    );
    assert!(harness.effects.deleted_files.is_empty());
    // installation.json deletion is the identity removal: it must NOT have
    // happened.
    assert!(
        !harness
            .effects
            .deleted_files
            .iter()
            .any(|name| name == "installation.json"),
        "the installation identity must survive for the exact retry"
    );
}

#[test]
fn terminal_state_deleted_only_after_proven_absence() {
    let mut harness = Harness::new();
    harness.run().expect("all-absent uninstall must succeed");
    let mut expected = vec![
        "setup_marker.json",
        "installation.json",
        "sandbox_users.json",
        "setup_error.json",
        "wfp_ownership.json",
    ];
    expected.sort();
    let mut deleted = harness.effects.deleted_files.clone();
    deleted.sort();
    assert_eq!(deleted, expected, "exactly the terminal state files");
    assert!(harness.journal_phase().is_none(), "journal deleted last");
}

#[test]
fn second_uninstall_of_the_same_identity_is_idempotent() {
    let mut harness = Harness::new();
    harness.run().expect("first uninstall");
    // A second run starts with no journal (it was deleted) and every family
    // already absent: it must succeed without touching anything unexpected.
    let before = harness.effects.deleted_files.len();
    harness.run().expect("second uninstall must be idempotent");
    // The sweep deletes missing files harmlessly (same five names).
    assert_eq!(harness.effects.deleted_files.len(), before + 5);
}

#[test]
fn journal_from_another_installation_is_rejected() {
    let mut harness = Harness::new();
    *harness.journal.inner.borrow_mut() = Some(CleanupJournal {
        version: 1,
        install_id: SandboxInstallationIdentity::generate().install_id_hex(),
        ownership_digest: None,
        completed_phase: UninstallPhase::Pending,
        updated_at: "2026-09-07T00:00:00.000Z".to_string(),
    });
    let failures = harness.run().expect_err("foreign journal must be rejected");
    assert!(
        failures
            .iter()
            .any(|f| f.phase == "journal" && f.detail.contains("belongs to installation")),
        "failures: {failures:?}"
    );
    assert!(harness.effects.deleted_files.is_empty());
}

#[test]
fn persisted_identity_mismatch_is_rejected_fail_closed() {
    let mut harness = Harness::new();
    harness.effects.persisted_installation_id =
        Some(SandboxInstallationIdentity::generate().install_id_hex());
    let failures = harness
        .run()
        .expect_err("identity mismatch must be rejected");
    assert!(
        failures
            .iter()
            .any(|f| f.phase == "journal" && f.detail.contains("does not match")),
        "failures: {failures:?}"
    );
    assert!(harness.effects.deleted_files.is_empty());
}

#[test]
fn a_swapped_ownership_record_fails_closed_on_resume() {
    let mut harness = Harness::new();
    // First run fails on a surviving WFP object; the journal binds the
    // current ownership digest at that point.
    harness.effects.ownership_digest = Some("aaa".to_string());
    harness.effects.wfp_still_present = vec!["filter:codex_wfp_dns_53_v4".to_string()];
    harness.run().expect_err("first run fails on WFP presence");
    // The record is then swapped (different digest): the retry must refuse.
    harness.effects.ownership_digest = Some("bbb".to_string());
    harness.effects.wfp_still_present.clear();
    let failures = harness.run().expect_err("swapped record must be rejected");
    assert!(
        failures
            .iter()
            .any(|f| f.phase == "journal" && f.detail.contains("ownership record changed")),
        "failures: {failures:?}"
    );
    assert!(harness.effects.deleted_files.is_empty());
}

#[test]
fn cleanup_journal_persists_rfc3339_and_replaces_atomically() {
    let temp = tempfile::tempdir().expect("journal directory");
    let mut io = super::FileCleanupJournalIo {
        sandbox_dir: temp.path().to_path_buf(),
    };
    let mut journal = CleanupJournal {
        version: super::uninstall_state_machine::CLEANUP_JOURNAL_VERSION,
        install_id: SandboxInstallationIdentity::generate().install_id_hex(),
        ownership_digest: Some("a".repeat(64)),
        completed_phase: UninstallPhase::Pending,
        updated_at: "2026-09-08T01:55:39.8145343+08:00".to_string(),
    };
    io.write_journal(&journal)
        .expect("RFC3339 timestamp is payload, not a filename");
    assert_eq!(io.read_journal(), Some(journal.clone()));
    journal.completed_phase = UninstallPhase::AclRemoved;
    io.write_journal(&journal)
        .expect("replace the existing journal");
    assert_eq!(io.read_journal(), Some(journal));
    assert_eq!(
        std::fs::read_dir(temp.path())
            .expect("list journal directory")
            .count(),
        1
    );
}

#[test]
fn acl_failure_does_not_advance_or_destroy_retry_identity() {
    let mut harness = Harness::new();
    harness.effects.roots = vec![PathBuf::from(r"C:\ws\locked-root")];
    harness.effects.acl_failures = vec!["locked-root".to_string()];
    harness
        .run()
        .expect_err("ACL failure must preserve the trustee for retry");
    assert!(!harness.effects.accounts_removed);
    assert_eq!(harness.journal_phase(), Some(UninstallPhase::Pending));
    harness.effects.acl_failures = vec!["locked-root".to_string()];
    harness
        .run()
        .expect_err("retry must attempt ACL removal again");
    assert!(!harness.effects.accounts_removed);
    harness.run().expect("retry after ACL recovery succeeds");
    assert!(harness.effects.accounts_removed);
    assert!(harness.journal_phase().is_none());
}

#[test]
fn native_account_absence_query_does_not_crash() {
    // This random identity is never provisioned. The real local Net APIs
    // must report absence without creating or deleting any account/group.
    let identity = SandboxInstallationIdentity::generate();
    assert!(super::sandbox_users::accounts_present(&identity).is_empty());
}

#[test]
fn resource_removal_is_retried_after_a_failed_attempt() {
    for family in ["firewall", "wfp", "accounts"] {
        let mut harness = Harness::new();
        match family {
            "firewall" => harness
                .effects
                .firewall_still_present
                .push("rule".to_string()),
            "wfp" => harness.effects.wfp_still_present.push("filter".to_string()),
            "accounts" => harness
                .effects
                .accounts_still_present
                .push("account".to_string()),
            _ => unreachable!(),
        }
        harness
            .run()
            .expect_err("failed removal must keep recovery state");
        // Exercise compatibility with an older checkpoint that advanced
        // despite a surviving resource. Only a fresh deletion clears it.
        harness
            .journal
            .inner
            .borrow_mut()
            .as_mut()
            .expect("journal")
            .completed_phase = UninstallPhase::AccountsRemoved;
        harness.effects.recover_on_delete = true;
        harness.run().expect("retry after the transient failure");
        let attempts = match family {
            "firewall" => harness.effects.firewall_attempts,
            "wfp" => harness.effects.wfp_attempts,
            "accounts" => harness.effects.account_attempts,
            _ => unreachable!(),
        };
        assert_eq!(attempts, 2, "retry must invoke {family} deletion again");
    }
}

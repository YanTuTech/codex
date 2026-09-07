mod filter_specs;

use crate::to_wide;
use anyhow::Result;
use std::ffi::OsStr;
use std::mem::zeroed;
use std::ptr::null;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::FWP_E_ALREADY_EXISTS;
use windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_NOT_FOUND;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_BLOCK;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTRL_MATCH_FILTER;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_EMPTY;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_EQUAL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_SECURITY_DESCRIPTOR_TYPE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT16;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_USER_ID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_PROTOCOL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_CONDITION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineOpen0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterGetByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFreeMemory0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderGetByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerGetByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionAbort0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionBegin0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionCommit0;
use windows_sys::Win32::Security::Authorization::BuildExplicitAccessWithNameW;
use windows_sys::Win32::Security::Authorization::BuildSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::GetSecurityDescriptorOwner;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

use filter_specs::ConditionSpec;
use filter_specs::FILTER_SPECS;
use filter_specs::FilterSpec;

use crate::installation::SandboxInstallationIdentity;
use crate::wfp_ownership::WfpOwnershipRecord;
use crate::wfp_ownership::load_or_allocate_wfp_ownership;

/// The static filter-spec names, exposed for ownership-record allocation.
pub fn filter_spec_names() -> Vec<&'static str> {
    FILTER_SPECS.iter().map(|spec| spec.name).collect()
}

/// Installs the persistent, installation-scoped WFP objects for `account`.
///
/// Provider, sublayer, and filter GUIDs come from (and are persisted in) the
/// installation's ownership record, so two installations never share a WFP
/// namespace and uninstall can remove exactly what was installed. This is
/// intended to run from the already-elevated setup helper. Callers should
/// treat any returned error as non-fatal to the rest of setup.
pub fn install_wfp_filters_for_installation(
    codex_home: &std::path::Path,
    identity: &SandboxInstallationIdentity,
    account: &str,
) -> Result<usize> {
    let record = load_or_allocate_wfp_ownership(codex_home, identity, &filter_spec_names())?;
    install_wfp_filters_with_record(&record, account)
}

fn install_wfp_filters_with_record(record: &WfpOwnershipRecord, account: &str) -> Result<usize> {
    let engine = Engine::open(record)?;
    let mut transaction = engine.begin_transaction()?;
    ensure_provider(engine.handle, record)?;
    ensure_sublayer(engine.handle, record)?;

    let user_condition = UserMatchCondition::for_account(account)?;
    let mut installed_filter_count = 0;
    for spec in FILTER_SPECS {
        let filter_key = GUID::from_u128(record.filter_key_u128(spec.name)?);
        delete_filter_if_present(engine.handle, &filter_key)?;
        add_filter(engine.handle, spec, &filter_key, record, &user_condition)?;
        installed_filter_count += 1;
    }

    transaction.commit()?;
    Ok(installed_filter_count)
}

/// Reports which of this installation's recorded WFP objects still exist,
/// by exact GUID query. Absence is claimed only when every recorded object
/// queries as FWP_E_NOT_FOUND; a missing ownership record means nothing is
/// recorded to check (empty result), and an engine error reports every
/// object as present so absence can never be claimed without a query.
pub fn wfp_objects_present(
    codex_home: &std::path::Path,
    identity: &SandboxInstallationIdentity,
) -> Vec<String> {
    let Some(record) =
        crate::wfp_ownership::load_wfp_ownership(codex_home, identity).unwrap_or(None)
    else {
        return Vec::new();
    };
    let mut present = Vec::new();
    let engine = match Engine::open(&record) {
        Ok(engine) => engine,
        Err(_) => {
            // Fail closed: without an engine handle, claim everything.
            present.push("engine:query-failed".to_string());
            return present;
        }
    };
    for spec in FILTER_SPECS {
        if let Ok(key) = record.filter_key_u128(spec.name) {
            let guid = GUID::from_u128(key);
            let result = unsafe { FwpmFilterGetByKey0(engine.handle, &guid, std::ptr::null_mut()) };
            if result != FWP_E_NOT_FOUND as u32 && result != FWP_E_FILTER_NOT_FOUND as u32 {
                present.push(format!("filter:{}", spec.name));
            }
        }
    }
    if let Ok(key) = record.sublayer_key_u128() {
        let guid = GUID::from_u128(key);
        let result = unsafe { FwpmSubLayerGetByKey0(engine.handle, &guid, std::ptr::null_mut()) };
        if result != FWP_E_NOT_FOUND as u32 {
            present.push("sublayer".to_string());
        }
    }
    if let Ok(key) = record.provider_key_u128() {
        let guid = GUID::from_u128(key);
        let result = unsafe { FwpmProviderGetByKey0(engine.handle, &guid, std::ptr::null_mut()) };
        if result != FWP_E_NOT_FOUND as u32 {
            present.push("provider".to_string());
        }
    }
    present
}

/// Field-wise GUID equality: windows-sys GUID derives no PartialEq.
fn guid_eq(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

/// Standard GUID text form. The elevated helper (receipt production) and
/// Main's native live read (`readWfpFilterFacts`) MUST format keys the same
/// way so receipt facts and live objects compare byte-for-byte.
pub(crate) fn guid_to_text(guid: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

/// Reads a NUL-terminated wide string behind a PWSTR into a Rust String.
///
/// # Safety
/// `textual` must point to a NUL-terminated wide string owned by the caller.
unsafe fn pwstr_to_string(textual: *const u16) -> String {
    let mut length = 0usize;
    unsafe {
        while *textual.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(textual, length))
    }
}

/// Live read-back of every WFP filter this installation owns, plus its
/// provider and sublayer, for receipt production. Every recorded key must
/// exist, every filter must sit in its spec's layer as a BLOCK filter, and
/// every user condition must constrain exactly `expected_user_sid` — any
/// deviation is an error so the helper cannot write a receipt over an
/// incomplete WFP closure.
pub fn read_live_filter_facts(
    codex_home: &std::path::Path,
    identity: &SandboxInstallationIdentity,
    expected_user_sid: &str,
) -> Result<std::collections::BTreeMap<String, crate::setup_receipt::WfpFilterFactV1>> {
    let Some(record) = crate::wfp_ownership::load_wfp_ownership(codex_home, identity)? else {
        anyhow::bail!("no WFP ownership record for this installation");
    };
    let engine = Engine::open(&record)?;
    // Provider and sublayer must be live before any filter can be.
    let sublayer_guid = GUID::from_u128(record.sublayer_key_u128()?);
    let sublayer_result =
        unsafe { FwpmSubLayerGetByKey0(engine.handle, &sublayer_guid, std::ptr::null_mut()) };
    if sublayer_result == FWP_E_NOT_FOUND as u32 {
        anyhow::bail!("live WFP sublayer is absent from the engine");
    }
    if sublayer_result != 0 {
        anyhow::bail!("live WFP sublayer query failed with {sublayer_result:#x}");
    }
    let provider_guid = GUID::from_u128(record.provider_key_u128()?);
    let provider_result =
        unsafe { FwpmProviderGetByKey0(engine.handle, &provider_guid, std::ptr::null_mut()) };
    if provider_result == FWP_E_NOT_FOUND as u32 {
        anyhow::bail!("live WFP provider is absent from the engine");
    }
    if provider_result != 0 {
        anyhow::bail!("live WFP provider query failed with {provider_result:#x}");
    }

    let mut facts = std::collections::BTreeMap::new();
    for spec in FILTER_SPECS {
        let filter_key = GUID::from_u128(record.filter_key_u128(spec.name)?);
        let mut filter: *mut FWPM_FILTER0 = null_mut();
        let result = unsafe { FwpmFilterGetByKey0(engine.handle, &filter_key, &mut filter) };
        if result != 0 {
            anyhow::bail!(
                "live WFP filter {} query failed with {result:#x}",
                spec.name
            );
        }
        // The closure scopes every bail to the read-back, so the engine's
        // returned object is ALWAYS released before an error propagates.
        let read_back = || -> Result<crate::setup_receipt::WfpFilterFactV1> {
            unsafe {
                let filter_ref = &*filter;
                if !guid_eq(&filter_ref.layerKey, &spec.layer_key) {
                    anyhow::bail!("live WFP filter {} sits in an unexpected layer", spec.name);
                }
                if filter_ref.action.r#type != FWP_ACTION_BLOCK {
                    anyhow::bail!("live WFP filter {} is not a BLOCK filter", spec.name);
                }
                let conditions = std::slice::from_raw_parts(
                    filter_ref.filterCondition,
                    filter_ref.numFilterConditions as usize,
                );
                let user = conditions
                    .iter()
                    .find(|condition| guid_eq(&condition.fieldKey, &FWPM_CONDITION_ALE_USER_ID))
                    .ok_or_else(|| {
                        anyhow::Error::msg(format!(
                            "live WFP filter {} carries no user condition",
                            spec.name
                        ))
                    })?;
                if user.conditionValue.r#type != FWP_SECURITY_DESCRIPTOR_TYPE {
                    anyhow::bail!(
                        "live WFP filter {} user condition has an unexpected value type",
                        spec.name
                    );
                }
                let blob = &*user.conditionValue.Anonymous.sd;
                if blob.size == 0 || blob.data.is_null() {
                    anyhow::bail!(
                        "live WFP filter {} user condition carries no security descriptor",
                        spec.name
                    );
                }
                let mut owner: *mut core::ffi::c_void = null_mut();
                let mut owner_defaulted: i32 = 0;
                if GetSecurityDescriptorOwner(
                    blob.data as PSECURITY_DESCRIPTOR,
                    &mut owner,
                    &mut owner_defaulted,
                ) == 0
                    || owner.is_null()
                {
                    anyhow::bail!(
                        "live WFP filter {} user condition has no descriptor owner",
                        spec.name
                    );
                }
                let mut textual: *mut u16 = null_mut();
                if ConvertSidToStringSidW(owner, &mut textual) == 0 || textual.is_null() {
                    anyhow::bail!(
                        "live WFP filter {} user SID could not be rendered",
                        spec.name
                    );
                }
                let sid = pwstr_to_string(textual);
                LocalFree(textual as HLOCAL);
                if sid != expected_user_sid {
                    anyhow::bail!(
                        "live WFP filter {} constrains a different user than {}",
                        spec.name,
                        expected_user_sid
                    );
                }
                Ok(crate::setup_receipt::WfpFilterFactV1 {
                    layer_key: guid_to_text(&filter_ref.layerKey),
                    action: "BLOCK".to_string(),
                    condition_user_sid: sid,
                })
            }
        };
        let fact = read_back();
        unsafe { FwpmFreeMemory0(&mut filter as *mut _ as *mut _) };
        facts.insert(spec.name.to_string(), fact?);
    }
    Ok(facts)
}

/// Removes exactly the WFP objects recorded in this installation's ownership
/// record. Objects owned by other installations (including Codex-global
/// provider/sublayer keys) are never addressed. Deletes the ownership record
/// afterwards; a missing record means there is nothing owned to remove.
pub fn remove_wfp_objects_for_installation(
    codex_home: &std::path::Path,
    identity: &SandboxInstallationIdentity,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let Some(record) = crate::wfp_ownership::load_wfp_ownership(codex_home, identity)? else {
        log("no WFP ownership record; nothing to remove");
        return Ok(());
    };
    let engine = Engine::open(&record)?;
    {
        let mut transaction = engine.begin_transaction()?;
        for spec in FILTER_SPECS {
            if let Ok(key) = record.filter_key_u128(spec.name) {
                delete_filter_if_present(engine.handle, &GUID::from_u128(key))?;
            }
        }
        let sublayer_key = GUID::from_u128(record.sublayer_key_u128()?);
        let sublayer_result = unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &sublayer_key) };
        if sublayer_result != 0
            && sublayer_result != FWP_E_NOT_FOUND as u32
            && sublayer_result != FWP_E_FILTER_NOT_FOUND as u32
        {
            // Abort the transaction: committing after a failed delete would
            // erase the only cleanup manifest while WFP objects remain.
            return Err(anyhow::Error::msg(format!(
                "FwpmSubLayerDeleteByKey0 failed with {sublayer_result}; ownership record retained"
            )));
        }
        let provider_key = GUID::from_u128(record.provider_key_u128()?);
        let provider_result = unsafe { FwpmProviderDeleteByKey0(engine.handle, &provider_key) };
        if provider_result != 0 && provider_result != FWP_E_NOT_FOUND as u32 {
            return Err(anyhow::Error::msg(format!(
                "FwpmProviderDeleteByKey0 failed with {provider_result}; ownership record retained"
            )));
        }
        transaction.commit()?;
    }
    drop(engine);
    crate::wfp_ownership::delete_wfp_ownership(codex_home)?;
    log("WFP ownership record deleted");
    Ok(())
}

/// Owns an open WFP engine handle and closes it on drop.
struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open(record: &WfpOwnershipRecord) -> Result<Self> {
        let session_name = format!(
            "LeapSea Windows Sandbox WFP {}",
            &record.provider_key[..8.min(record.provider_key.len())]
        );
        let session_name = to_wide(OsStr::new(&session_name));
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.displayData = FWPM_DISPLAY_DATA0 {
            name: session_name.as_ptr() as *mut _,
            description: null_mut(),
        };
        session.txnWaitTimeoutInMSec = INFINITE;

        let mut handle = HANDLE::default();
        let result = unsafe {
            FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_DEFAULT as u32,
                null(),
                &session,
                &mut handle,
            )
        };
        ensure_success(result, "FwpmEngineOpen0")?;
        Ok(Self { handle })
    }

    fn begin_transaction(&self) -> Result<Transaction<'_>> {
        let result = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        ensure_success(result, "FwpmTransactionBegin0")?;
        Ok(Transaction {
            engine: self,
            committed: false,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.handle);
        }
    }
}

/// Aborts an open WFP transaction unless it was explicitly committed.
struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl Transaction<'_> {
    fn commit(&mut self) -> Result<()> {
        let result = unsafe { FwpmTransactionCommit0(self.engine.handle) };
        ensure_success(result, "FwpmTransactionCommit0")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                FwpmTransactionAbort0(self.engine.handle);
            }
        }
    }
}

/// Builds the ALE_USER_ID condition blob that scopes filters to one account.
struct UserMatchCondition {
    security_descriptor: PSECURITY_DESCRIPTOR,
    blob: FWP_BYTE_BLOB,
}

impl UserMatchCondition {
    fn for_account(account: &str) -> Result<Self> {
        let account_w = to_wide(OsStr::new(account));
        let mut access: EXPLICIT_ACCESS_W = unsafe { zeroed() };
        unsafe {
            BuildExplicitAccessWithNameW(
                &mut access,
                account_w.as_ptr(),
                FWP_ACTRL_MATCH_FILTER,
                GRANT_ACCESS,
                0,
            );
        }

        let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let mut security_descriptor_len = 0;
        let result = unsafe {
            BuildSecurityDescriptorW(
                null(),
                null(),
                1,
                &access,
                0,
                null(),
                null_mut(),
                &mut security_descriptor_len,
                &mut security_descriptor,
            )
        };
        ensure_success(result, "BuildSecurityDescriptorW")?;

        Ok(Self {
            security_descriptor,
            blob: FWP_BYTE_BLOB {
                size: security_descriptor_len,
                data: security_descriptor as *mut u8,
            },
        })
    }
}

impl Drop for UserMatchCondition {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe {
                LocalFree(self.security_descriptor as HLOCAL);
            }
        }
    }
}

/// Ensures the persistent, installation-scoped WFP provider exists.
fn ensure_provider(engine: HANDLE, record: &WfpOwnershipRecord) -> Result<()> {
    let provider_name = format!(
        "LeapSea Windows Sandbox WFP (install {})",
        &record.install_id[..8.min(record.install_id.len())]
    );
    let provider_description = format!(
        "Persistent WFP provider for LeapSea Windows sandbox filters (installation {})",
        record.install_id
    );
    let provider_name = to_wide(OsStr::new(&provider_name));
    let provider_description = to_wide(OsStr::new(&provider_description));
    let provider = FWPM_PROVIDER0 {
        providerKey: GUID::from_u128(record.provider_key_u128()?),
        displayData: FWPM_DISPLAY_DATA0 {
            name: provider_name.as_ptr() as *mut _,
            description: provider_description.as_ptr() as *mut _,
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: null_mut(),
    };

    let result = unsafe { FwpmProviderAdd0(engine, &provider, null_mut()) };
    ensure_success_or(result, "FwpmProviderAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Ensures the persistent, installation-scoped sublayer exists under this
/// installation's provider.
fn ensure_sublayer(engine: HANDLE, record: &WfpOwnershipRecord) -> Result<()> {
    let sublayer_name = format!(
        "LeapSea Windows Sandbox Sublayer (install {})",
        &record.install_id[..8.min(record.install_id.len())]
    );
    let sublayer_description = format!(
        "Persistent WFP sublayer for LeapSea Windows sandbox filters (installation {})",
        record.install_id
    );
    let sublayer_name = to_wide(OsStr::new(&sublayer_name));
    let sublayer_description = to_wide(OsStr::new(&sublayer_description));
    let provider_key = GUID::from_u128(record.provider_key_u128()?);
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: GUID::from_u128(record.sublayer_key_u128()?),
        displayData: FWPM_DISPLAY_DATA0 {
            name: sublayer_name.as_ptr() as *mut _,
            description: sublayer_description.as_ptr() as *mut _,
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        weight: 0x8000,
    };

    let result = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    ensure_success_or(result, "FwpmSubLayerAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Adds one blocking WFP filter from the static filter spec list, keyed by
/// the installation-owned filter key from the ownership record.
fn add_filter(
    engine: HANDLE,
    spec: &FilterSpec,
    filter_key: &GUID,
    record: &WfpOwnershipRecord,
    user_condition: &UserMatchCondition,
) -> Result<()> {
    let filter_name = format!("ls_wfp_{}_{}", &record.install_id[..8], spec.name);
    let filter_name = to_wide(OsStr::new(&filter_name));
    let filter_description = to_wide(OsStr::new(spec.description));
    let mut filter_conditions = build_conditions(spec.conditions, user_condition);
    let provider_key = GUID::from_u128(record.provider_key_u128()?);
    let filter = FWPM_FILTER0 {
        filterKey: *filter_key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: filter_name.as_ptr() as *mut _,
            description: filter_description.as_ptr() as *mut _,
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        layerKey: spec.layer_key,
        subLayerKey: GUID::from_u128(record.sublayer_key_u128()?),
        weight: empty_value(),
        numFilterConditions: filter_conditions.len() as u32,
        filterCondition: filter_conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: zero_guid(),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: null_mut(),
        filterId: 0,
        effectiveWeight: empty_value(),
    };

    let mut filter_id = 0_u64;
    let result = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id) };
    ensure_success(result, &format!("FwpmFilterAdd0({})", spec.name))
}

/// Converts our compact condition specs into WFP filter conditions.
fn build_conditions(
    specs: &[ConditionSpec],
    user_condition: &UserMatchCondition,
) -> Vec<FWPM_FILTER_CONDITION0> {
    specs
        .iter()
        .map(|spec| match spec {
            ConditionSpec::User => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_USER_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        sd: &user_condition.blob as *const _ as *mut _,
                    },
                },
            },
            ConditionSpec::Protocol(protocol) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *protocol },
                },
            },
            ConditionSpec::RemotePort(port) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            },
        })
        .collect()
}

/// Deletes an old copy of a filter before re-adding it.
fn delete_filter_if_present(engine: HANDLE, key: &GUID) -> Result<()> {
    let result = unsafe { FwpmFilterDeleteByKey0(engine, key) };
    ensure_success_or(
        result,
        "FwpmFilterDeleteByKey0",
        &[FWP_E_FILTER_NOT_FOUND as u32, FWP_E_NOT_FOUND as u32],
    )
}

fn ensure_success(result: u32, operation: &str) -> Result<()> {
    ensure_success_or(result, operation, &[])
}

fn ensure_success_or(result: u32, operation: &str, allowed: &[u32]) -> Result<()> {
    if result == 0 || allowed.contains(&result) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{operation} failed: {}",
            format_error_code(result)
        ))
    }
}

fn format_error_code(result: u32) -> String {
    format!("0x{result:08X}")
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: null_mut(),
    }
}

fn empty_value() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: unsafe { zeroed() },
    }
}

fn zero_guid() -> GUID {
    GUID::from_u128(0)
}

#[cfg(test)]
mod tests {
    use super::FILTER_SPECS;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeSet;

    #[test]
    fn allocated_filter_keys_are_unique_per_installation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = crate::installation::SandboxInstallationIdentity::generate();
        let names: Vec<&str> = FILTER_SPECS.iter().map(|spec| spec.name).collect();
        let record =
            crate::wfp_ownership::load_or_allocate_wfp_ownership(dir.path(), &identity, &names)
                .expect("allocate ownership");
        let keys = record
            .filter_keys
            .values()
            .map(std::string::String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), FILTER_SPECS.len());
        // A second installation allocates a completely disjoint key set in its
        // own state directory; a shared directory must fail closed instead
        // (covered by the ownership tests).
        let other_dir = tempfile::tempdir().expect("tempdir");
        let other = crate::installation::SandboxInstallationIdentity::generate();
        let other_record =
            crate::wfp_ownership::load_or_allocate_wfp_ownership(other_dir.path(), &other, &names)
                .expect("allocate other ownership");
        let disjoint = other_record
            .filter_keys
            .values()
            .all(|hex| !record.filter_keys.values().any(|existing| existing == hex));
        assert!(disjoint, "two installations must not share filter keys");
    }

    #[test]
    fn filter_names_are_unique() {
        let names = FILTER_SPECS
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), FILTER_SPECS.len());
    }
}

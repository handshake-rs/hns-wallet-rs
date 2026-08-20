use super::*;

use hns_wallet_store::{MAX_STATE_BYTES, PendingApproval};

/// The only Shakedex actions that may ask the ordinary HNS key role to sign a
/// funding suffix. The script-FINALIZE purpose is deliberately distinct from
/// the two FINALIZE-lock purposes so a persisted reservation cannot silently
/// exchange current-lock authority for current-TRANSFER authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HnsShakedexFundingPurpose {
    BuyerFulfillment,
    SellerRecovery,
    SellerScriptFinalize,
}

/// Opaque account namespace used to derive reservation record identifiers.
/// It can only be obtained from an open HNS runtime, so an external workflow
/// cannot silently substitute another wallet or account configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsShakedexFundingScope {
    config: HnsRuntimeConfig,
}

impl HnsShakedexFundingScope {
    pub const fn wallet_id(&self) -> WalletId {
        self.config.wallet_id
    }

    pub const fn account_id(&self) -> AccountId {
        self.config.account_id
    }
}

/// Complete persisted reservation identity for one script-controlled source
/// and its ordered ordinary-wallet funding suffix. The private fields prevent
/// callers from mutating only one part after construction, while serde permits
/// the enclosing Shakedex aggregate to retain the exact evidence across a
/// restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HnsShakedexFundingReservation {
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    purpose: HnsShakedexFundingPurpose,
    name_hash: [u8; 32],
    source_outpoint: HnsOutpoint,
    funding_inputs: Vec<TrackedHnsCoin>,
    expires_at_unix: u64,
}

/// Exact wallet-account mutation required when a funded Shakedex transaction
/// uses the account's current internal change address. The fields remain
/// private so another crate cannot substitute a different account row or
/// derivation after coin selection. The enclosing Shakedex workflow persists
/// this save in the same immediate transaction as its input reservations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsShakedexChangeReservation {
    derivation: DerivationReference,
    account_save: EntityBatchSave<HnsAccountRecord>,
}

impl HnsShakedexChangeReservation {
    pub const fn derivation(&self) -> DerivationReference {
        self.derivation
    }

    pub const fn expected_account_revision(&self) -> u64 {
        self.account_save.expected_revision
    }

    pub const fn account_save(&self) -> &EntityBatchSave<HnsAccountRecord> {
        &self.account_save
    }
}

/// Product-owned result of selecting and binding the ordinary HNS funding
/// suffix for one current Shakedex action. The generic prepared artifact is
/// retained with the exact scope, reservations, fee, and optional change
/// mutation that were computed from it; callers cannot independently replace
/// one component.
pub struct HnsPreparedShakedexFunding<T> {
    prepared: T,
    scope: HnsShakedexFundingScope,
    funding_reservation: HnsShakedexFundingReservation,
    change_reservation: Option<HnsShakedexChangeReservation>,
    fee_rate: BaseUnits,
    fee: BaseUnits,
    maximum_fee: BaseUnits,
    expires_at_unix: u64,
}

impl<T> HnsPreparedShakedexFunding<T> {
    pub const fn prepared(&self) -> &T {
        &self.prepared
    }

    pub const fn scope(&self) -> &HnsShakedexFundingScope {
        &self.scope
    }

    pub const fn funding_reservation(&self) -> &HnsShakedexFundingReservation {
        &self.funding_reservation
    }

    pub const fn change_reservation(&self) -> Option<&HnsShakedexChangeReservation> {
        self.change_reservation.as_ref()
    }

    pub const fn fee_rate(&self) -> BaseUnits {
        self.fee_rate
    }

    pub const fn fee(&self) -> BaseUnits {
        self.fee
    }

    pub const fn maximum_fee(&self) -> BaseUnits {
        self.maximum_fee
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        T,
        HnsShakedexFundingScope,
        HnsShakedexFundingReservation,
        Option<HnsShakedexChangeReservation>,
        BaseUnits,
        BaseUnits,
        u64,
    ) {
        (
            self.prepared,
            self.scope,
            self.funding_reservation,
            self.change_reservation,
            self.fee,
            self.maximum_fee,
            self.expires_at_unix,
        )
    }
}

impl HnsShakedexFundingReservation {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &HnsShakedexFundingScope,
        workflow_id: WorkflowId,
        purpose: HnsShakedexFundingPurpose,
        name_hash: [u8; 32],
        source_outpoint: HnsOutpoint,
        funding_inputs: Vec<TrackedHnsCoin>,
        expires_at_unix: u64,
    ) -> Result<Self, HnsWalletError> {
        let reservation = Self {
            wallet_id: scope.config.wallet_id,
            account_id: scope.config.account_id,
            workflow_id,
            purpose,
            name_hash,
            source_outpoint,
            funding_inputs,
            expires_at_unix,
        };
        validate_reservation_identity(scope, &reservation, None)?;
        Ok(reservation)
    }

    pub const fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub const fn purpose(&self) -> HnsShakedexFundingPurpose {
        self.purpose
    }

    pub const fn name_hash(&self) -> [u8; 32] {
        self.name_hash
    }

    pub const fn source_outpoint(&self) -> HnsOutpoint {
        self.source_outpoint
    }

    pub fn funding_inputs(&self) -> &[TrackedHnsCoin] {
        &self.funding_inputs
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HnsShakedexFundingReservationState {
    Prepared,
    Active,
    Released,
}

/// Opaque entity mutations that an enclosing Shakedex workflow passes to one
/// of the wallet store's existing workflow/entity CAS operations. Merely
/// constructing this value never writes the database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsShakedexFundingReservationBatch {
    saves: Vec<EntityBatchSave<HnsInputReservation>>,
    deletes: Vec<EntityBatchDelete>,
}

impl HnsShakedexFundingReservationBatch {
    pub fn saves(&self) -> &[EntityBatchSave<HnsInputReservation>] {
        &self.saves
    }

    pub fn deletes(&self) -> &[EntityBatchDelete] {
        &self.deletes
    }

    pub fn is_empty(&self) -> bool {
        self.saves.is_empty() && self.deletes.is_empty()
    }
}

/// Exact private-approval row expected by suffix authorization. The request
/// bytes are deliberately opaque here: the Shakedex aggregate owns their
/// market-terms schema, while this boundary requires byte-for-byte equality
/// with the authenticated live store row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsShakedexFundingApprovalExpectation {
    approval_id: ApprovalId,
    origin: String,
    request_bytes: Vec<u8>,
    expires_at_unix: u64,
}

impl HnsShakedexFundingApprovalExpectation {
    pub fn new(
        approval_id: ApprovalId,
        origin: String,
        request_bytes: Vec<u8>,
        expires_at_unix: u64,
    ) -> Result<Self, HnsWalletError> {
        if approval_id.as_bytes().iter().all(|byte| *byte == 0)
            || origin.is_empty()
            || origin.len() > 512
            || !origin.is_ascii()
            || request_bytes.is_empty()
            || request_bytes.len() > MAX_STATE_BYTES
            || expires_at_unix == 0
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        Ok(Self {
            approval_id,
            origin,
            request_bytes,
            expires_at_unix,
        })
    }

    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

/// Signed exact transaction bytes plus the still-live authenticated approval
/// row. The caller must pass that row to the store's atomic consume-and-save
/// CAS; this method never consumes approval separately from the aggregate.
pub struct HnsShakedexFundingAuthorization {
    signed_transaction: Vec<u8>,
    pending_approval: PendingApproval,
}

impl HnsShakedexFundingAuthorization {
    pub fn signed_transaction(&self) -> &[u8] {
        &self.signed_transaction
    }

    pub const fn pending_approval(&self) -> &PendingApproval {
        &self.pending_approval
    }

    pub fn into_parts(self) -> (Vec<u8>, PendingApproval) {
        (self.signed_transaction, self.pending_approval)
    }
}

impl fmt::Debug for HnsShakedexFundingAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsShakedexFundingAuthorization")
            .field("signed_transaction", &"[REDACTED]")
            .field("pending_approval", &self.pending_approval)
            .finish()
    }
}

/// Opaque same-snapshot transaction and input-spend evidence fetched for one
/// exact persisted Shakedex transaction. Construction remains runtime-owned,
/// so a product caller cannot promote self-authored status objects.
pub struct HnsShakedexTransactionObservation {
    transaction: TransactionHash,
    transaction_evidence: TransactionEvidence,
    spend_evidence: OutpointSpendEvidence,
    observed_at_unix: u64,
}

impl HnsShakedexTransactionObservation {
    pub const fn transaction(&self) -> TransactionHash {
        self.transaction
    }

    pub const fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    pub fn into_parts(self) -> (TransactionEvidence, OutpointSpendEvidence) {
        (self.transaction_evidence, self.spend_evidence)
    }
}

impl fmt::Debug for HnsShakedexTransactionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsShakedexTransactionObservation")
            .field("transaction", &self.transaction)
            .field("transaction_evidence", &self.transaction_evidence)
            .field("spend_evidence", &self.spend_evidence)
            .field("observed_at_unix", &self.observed_at_unix)
            .finish()
    }
}

/// Construct the exact source/funding reservation inserts for the enclosing
/// Shakedex workflow's initial CAS. Existing workflow or outpoint reservations
/// fail closed; retry recovery should validate the already-persisted set.
pub fn create_hns_shakedex_funding_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    reservation: &HnsShakedexFundingReservation,
    now_unix: u64,
) -> Result<HnsShakedexFundingReservationBatch, HnsWalletError> {
    validate_reservation_identity(scope, reservation, Some(now_unix))?;
    let expected = expected_reservation_kinds(reservation)?;
    let existing = account_input_reservations(store, &scope.config)?;
    let source_id = global_shakedex_source_reservation_id(reservation.source_outpoint);
    if existing.iter().any(|stored| {
        stored.value.workflow_id == reservation.workflow_id
            || expected.contains_key(&stored.value.outpoint)
    }) || store
        .load_entity::<HnsInputReservation>(EntityKind::InputReservation, &source_id)?
        .is_some()
    {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let saves = expected
        .into_iter()
        .map(|(outpoint, kind)| EntityBatchSave {
            id: shakedex_reservation_record_id(&scope.config, outpoint, kind),
            expected_revision: 0,
            value: HnsInputReservation {
                wallet_id: reservation.wallet_id,
                account_id: reservation.account_id,
                outpoint,
                workflow_id: reservation.workflow_id,
                expires_at_unix: Some(reservation.expires_at_unix),
                kind,
            },
            updated_at_unix: now_unix,
        })
        .collect();
    Ok(HnsShakedexFundingReservationBatch {
        saves,
        deletes: Vec::new(),
    })
}

/// Authenticate the complete persisted reservation set and reject missing,
/// extra, mixed-state, retyped, or cross-account rows.
pub fn validate_hns_shakedex_funding_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    reservation: &HnsShakedexFundingReservation,
    state: HnsShakedexFundingReservationState,
) -> Result<(), HnsWalletError> {
    validate_reservation_identity(scope, reservation, None)?;
    let expected = expected_reservation_kinds(reservation)?;
    let matching = stored_shakedex_reservations(store, scope, reservation)?;
    if state == HnsShakedexFundingReservationState::Released {
        return if matching.is_empty() {
            Ok(())
        } else {
            Err(HnsWalletError::InvalidWorkflow)
        };
    }
    if matching.len() != expected.len() {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let expected_expiry = match state {
        HnsShakedexFundingReservationState::Prepared => Some(reservation.expires_at_unix),
        HnsShakedexFundingReservationState::Active => None,
        HnsShakedexFundingReservationState::Released => unreachable!("handled above"),
    };
    for stored in matching {
        let Some(expected_kind) = expected.get(&stored.value.outpoint).copied() else {
            return Err(HnsWalletError::InvalidWorkflow);
        };
        let expected_id =
            shakedex_reservation_record_id(&scope.config, stored.value.outpoint, expected_kind);
        if stored.id != expected_id
            || stored.value.wallet_id != reservation.wallet_id
            || stored.value.account_id != reservation.account_id
            || stored.value.expires_at_unix != expected_expiry
            || stored.value.kind != expected_kind
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
    }
    Ok(())
}

/// Construct the exact prepared-to-active reservation updates for the same
/// transaction that consumes approval and persists signed bytes.
pub fn activate_hns_shakedex_funding_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    reservation: &HnsShakedexFundingReservation,
    now_unix: u64,
) -> Result<HnsShakedexFundingReservationBatch, HnsWalletError> {
    validate_reservation_identity(scope, reservation, Some(now_unix))?;
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        reservation,
        HnsShakedexFundingReservationState::Prepared,
    )?;
    let saves = stored_shakedex_reservations(store, scope, reservation)?
        .into_iter()
        .map(|stored| {
            let mut value = stored.value;
            value.expires_at_unix = None;
            EntityBatchSave {
                id: stored.id,
                expected_revision: stored.revision,
                value,
                updated_at_unix: now_unix,
            }
        })
        .collect();
    Ok(HnsShakedexFundingReservationBatch {
        saves,
        deletes: Vec::new(),
    })
}

/// Construct an exact no-op rewrite of every active protected row. Passing
/// this batch to the workflow's pre-submit CAS makes reservation presence,
/// type, and revisions part of the same durable fence as the signed bytes.
pub fn retain_active_hns_shakedex_funding_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    reservation: &HnsShakedexFundingReservation,
    now_unix: u64,
) -> Result<HnsShakedexFundingReservationBatch, HnsWalletError> {
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        reservation,
        HnsShakedexFundingReservationState::Active,
    )?;
    let saves = stored_shakedex_reservations(store, scope, reservation)?
        .into_iter()
        .map(|stored| EntityBatchSave {
            id: stored.id,
            expected_revision: stored.revision,
            value: stored.value,
            updated_at_unix: now_unix,
        })
        .collect();
    Ok(HnsShakedexFundingReservationBatch {
        saves,
        deletes: Vec::new(),
    })
}

/// Construct exact terminal reservation deletes. Generic HNS cleanup ignores
/// these protected rows, so only the enclosing Shakedex workflow may request
/// this explicit CAS after authenticating its expected state.
pub fn delete_hns_shakedex_funding_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    reservation: &HnsShakedexFundingReservation,
    state: HnsShakedexFundingReservationState,
) -> Result<HnsShakedexFundingReservationBatch, HnsWalletError> {
    validate_hns_shakedex_funding_reservations(store, scope, reservation, state)?;
    let deletes = stored_shakedex_reservations(store, scope, reservation)?
        .into_iter()
        .map(|stored| EntityBatchDelete {
            id: stored.id,
            expected_revision: stored.revision,
        })
        .collect();
    Ok(HnsShakedexFundingReservationBatch {
        saves: Vec::new(),
        deletes,
    })
}

impl<B: HnsBackend, C: HnsClock> HnsWalletRuntime<B, C> {
    /// Trusted runtime time for Shakedex persistence and approval decisions.
    pub fn shakedex_now_unix(&self) -> Result<u64, HnsWalletError> {
        self.clock.now_unix()
    }

    pub fn shakedex_funding_scope(&self) -> Result<HnsShakedexFundingScope, HnsWalletError> {
        Ok(HnsShakedexFundingScope {
            config: self.cache_read()?.account.config.clone(),
        })
    }

    /// Derive the selected account's exact current dedicated name recipient.
    /// This address is taken from the authenticated restore branch at
    /// `next_name_index`; a website or market peer never supplies it.
    pub fn shakedex_name_receive_address(&self) -> Result<Address, HnsWalletError> {
        let (account, account_revision) = {
            let cache = self.cache_read()?;
            ensure_shakedex_funding_ready(&cache)?;
            (cache.account.clone(), cache.account_revision)
        };
        let derivation = DerivationReference {
            role: KeyRole::HnsName,
            account: account_number(&account),
            change: 0,
            index: account.next_name_index,
        };
        let address = {
            let store = self.store_lock()?;
            let id = derived_address_record_id(&account.config, derivation)?;
            let stored = store
                .derived_address::<DerivedHnsAddress>(&id)?
                .ok_or(HnsWalletError::InvalidEvidence)?;
            let public = derive_hns_public_key(&store, account.config.wallet_id, derivation)?;
            let program = public_key_hash(&public)?.to_vec();
            let display = encode_v0_address(account.config.network, &program)?;
            if stored.id != id
                || stored.value.account_id != account.config.account_id
                || stored.value.derivation != derivation
                || stored.value.program != program
                || stored.value.address != display
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            Address::new(0, program).map_err(|_| HnsWalletError::InvalidAddress)?
        };
        let cache = self.cache_read()?;
        if cache.account_revision != account_revision || cache.account != account {
            return Err(HnsWalletError::StaleAddressReservation);
        }
        Ok(address)
    }

    /// Derive the exact ordinary receive address used for seller payment.
    /// Economic terms therefore pay the selected local wallet and cannot be
    /// redirected by a provider request.
    pub fn shakedex_payment_receive_address(&self) -> Result<Address, HnsWalletError> {
        let (account, account_revision) = {
            let cache = self.cache_read()?;
            ensure_shakedex_funding_ready(&cache)?;
            (cache.account.clone(), cache.account_revision)
        };
        let derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 0,
            index: account.next_receive_index,
        };
        let address = {
            let store = self.store_lock()?;
            let id = derived_address_record_id(&account.config, derivation)?;
            let stored = store
                .derived_address::<DerivedHnsAddress>(&id)?
                .ok_or(HnsWalletError::InvalidEvidence)?;
            let public = derive_hns_public_key(&store, account.config.wallet_id, derivation)?;
            let program = public_key_hash(&public)?.to_vec();
            let display = encode_v0_address(account.config.network, &program)?;
            if stored.id != id
                || stored.value.account_id != account.config.account_id
                || stored.value.derivation != derivation
                || stored.value.program != program
                || stored.value.address != display
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            Address::new(0, program).map_err(|_| HnsWalletError::InvalidAddress)?
        };
        let cache = self.cache_read()?;
        if cache.account_revision != account_revision || cache.account != account {
            return Err(HnsWalletError::StaleAddressReservation);
        }
        Ok(address)
    }

    /// Select, fee, and bind the complete ordinary-wallet suffix for a buyer
    /// fulfillment or seller recovery. The builder is an internal protocol
    /// adapter: it receives only wallet-selected canonical inputs and optional
    /// change, and must return the canonical prepared bytes it constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_current_shakedex_lock_funding<T, F>(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        workflow_id: WorkflowId,
        purpose: HnsShakedexFundingPurpose,
        ordinary_value: BaseUnits,
        maximum_fee: BaseUnits,
        max_funding_inputs: usize,
        not_after_unix: Option<u64>,
        mut build: F,
    ) -> Result<HnsPreparedShakedexFunding<T>, HnsWalletError>
    where
        F: FnMut(Vec<Input>, Vec<Coin>, Vec<Output>, u64) -> Result<(Vec<u8>, T), HnsWalletError>,
    {
        require_lock_funding_purpose(purpose)?;
        match purpose {
            HnsShakedexFundingPurpose::BuyerFulfillment if ordinary_value.is_zero() => {
                return Err(HnsWalletError::InvalidAmount);
            }
            HnsShakedexFundingPurpose::SellerRecovery if !ordinary_value.is_zero() => {
                return Err(HnsWalletError::InvalidAmount);
            }
            HnsShakedexFundingPurpose::BuyerFulfillment
            | HnsShakedexFundingPurpose::SellerRecovery => {}
            HnsShakedexFundingPurpose::SellerScriptFinalize => {
                return Err(HnsWalletError::InvalidWorkflow);
            }
        }
        let (account, account_revision, cached_coins, change_derivation, change_address, now_unix) =
            self.prepare_shakedex_funding_selection()?;
        let fee_rate = self.backend.estimate_fee_rate(DEFAULT_FEE_TARGET_BLOCKS)?;
        let source_coin = current_lock.locking_coin();
        let selection = select_shakedex_funding(
            source_coin,
            cached_coins,
            change_address,
            ordinary_value,
            fee_rate,
            maximum_fee,
            account.config.dust_threshold,
            account.config.minimum_confirmations,
            max_funding_inputs,
            &mut build,
        )?;
        let maximum_expiry = now_unix
            .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
            .ok_or(HnsWalletError::Arithmetic)?;
        let expires_at_unix =
            not_after_unix.map_or(maximum_expiry, |not_after| not_after.min(maximum_expiry));
        if expires_at_unix <= now_unix {
            return Err(HnsWalletError::PreparedArtifactExpired);
        }
        let funding_coins = selection
            .selected
            .iter()
            .map(TrackedHnsCoin::to_canonical_coin)
            .collect::<Result<Vec<_>, _>>()?;
        let (scope, funding_reservation) = self.bind_shakedex_funding_reservation(
            current_lock,
            workflow_id,
            purpose,
            &funding_coins,
            expires_at_unix,
        )?;
        let change_reservation = selection.uses_change.then(|| {
            Self::change_account_save(
                &account,
                account_revision,
                change_derivation.index,
                now_unix,
            )
            .map(|account_save| HnsShakedexChangeReservation {
                derivation: change_derivation,
                account_save,
            })
        });
        let change_reservation = change_reservation.transpose()?;
        Ok(HnsPreparedShakedexFunding {
            prepared: selection.prepared,
            scope,
            funding_reservation,
            change_reservation,
            fee_rate,
            fee: selection.fee,
            maximum_fee,
            expires_at_unix,
        })
    }

    /// Select, fee, and bind the ordinary-wallet suffix for the distinct
    /// script-controlled FINALIZE path. Current-TRANSFER authority cannot be
    /// exchanged for a current-lock purpose through this API.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_current_shakedex_finalize_funding<T, F>(
        &self,
        current_transfer: &VerifiedCurrentShakedexTransfer,
        workflow_id: WorkflowId,
        maximum_fee: BaseUnits,
        max_funding_inputs: usize,
        mut build: F,
    ) -> Result<HnsPreparedShakedexFunding<T>, HnsWalletError>
    where
        F: FnMut(Vec<Input>, Vec<Coin>, Vec<Output>, u64) -> Result<(Vec<u8>, T), HnsWalletError>,
    {
        let (account, account_revision, cached_coins, change_derivation, change_address, now_unix) =
            self.prepare_shakedex_funding_selection()?;
        let fee_rate = self.backend.estimate_fee_rate(DEFAULT_FEE_TARGET_BLOCKS)?;
        let selection = select_shakedex_funding(
            current_transfer.transfer_coin(),
            cached_coins,
            change_address,
            BaseUnits::ZERO,
            fee_rate,
            maximum_fee,
            account.config.dust_threshold,
            account.config.minimum_confirmations,
            max_funding_inputs,
            &mut build,
        )?;
        let expires_at_unix = now_unix
            .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
            .ok_or(HnsWalletError::Arithmetic)?;
        let funding_coins = selection
            .selected
            .iter()
            .map(TrackedHnsCoin::to_canonical_coin)
            .collect::<Result<Vec<_>, _>>()?;
        let (scope, funding_reservation) = self.bind_shakedex_finalize_funding_reservation(
            current_transfer,
            workflow_id,
            &funding_coins,
            expires_at_unix,
        )?;
        let change_reservation = selection.uses_change.then(|| {
            Self::change_account_save(
                &account,
                account_revision,
                change_derivation.index,
                now_unix,
            )
            .map(|account_save| HnsShakedexChangeReservation {
                derivation: change_derivation,
                account_save,
            })
        });
        let change_reservation = change_reservation.transpose()?;
        Ok(HnsPreparedShakedexFunding {
            prepared: selection.prepared,
            scope,
            funding_reservation,
            change_reservation,
            fee_rate,
            fee: selection.fee,
            maximum_fee,
            expires_at_unix,
        })
    }

    /// Install the account revision committed atomically by the enclosing
    /// Shakedex workflow. A stale or substituted reservation poisons no state;
    /// it returns a fenced address-reservation error instead.
    pub fn install_committed_shakedex_change(
        &self,
        change: &HnsShakedexChangeReservation,
        committed_account_revision: u64,
    ) -> Result<(), HnsWalletError> {
        self.install_committed_account(
            change.account_save.expected_revision,
            committed_account_revision,
            change.account_save.value.clone(),
        )
    }

    fn prepare_shakedex_funding_selection(
        &self,
    ) -> Result<
        (
            HnsAccountRecord,
            u64,
            Vec<TrackedHnsCoin>,
            DerivationReference,
            Address,
            u64,
        ),
        HnsWalletError,
    > {
        let now_unix = self.clock.now_unix()?;
        let (account, account_revision, cached_coins) = {
            let cache = self.cache_read()?;
            ensure_shakedex_funding_ready(&cache)?;
            (
                cache.account.clone(),
                cache.account_revision,
                cache.coins.clone(),
            )
        };
        let change_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 1,
            index: account.next_change_index,
        };
        let (available, change_address) = {
            let mut store = self.store_lock()?;
            let available =
                available_unreserved_coins(&mut store, &account.config, cached_coins, now_unix)?;
            let public =
                derive_hns_public_key(&store, account.config.wallet_id, change_derivation)?;
            let address = Address::new(0, public_key_hash(&public)?.to_vec())
                .map_err(|_| HnsWalletError::InvalidAddress)?;
            (available, address)
        };
        let cache = self.cache_read()?;
        if cache.account_revision != account_revision || cache.account != account {
            return Err(HnsWalletError::StaleAddressReservation);
        }
        Ok((
            account,
            account_revision,
            available,
            change_derivation,
            change_address,
            now_unix,
        ))
    }

    /// Bind canonical funding-coin evidence from a verified Shakedex plan to
    /// the exact current account cache. Callers never manufacture derivation
    /// metadata: every supplied coin must match exactly one currently tracked,
    /// ordinary, sufficiently confirmed HNS coin in the same order.
    pub fn bind_shakedex_funding_reservation(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        workflow_id: WorkflowId,
        purpose: HnsShakedexFundingPurpose,
        funding_input_coins: &[Coin],
        expires_at_unix: u64,
    ) -> Result<(HnsShakedexFundingScope, HnsShakedexFundingReservation), HnsWalletError> {
        require_lock_funding_purpose(purpose)?;
        let now_unix = self.clock.now_unix()?;
        let (account, account_revision, binding, mempool, cached_coins) = {
            let cache = self.cache_read()?;
            ensure_shakedex_funding_ready(&cache)?;
            (
                cache.account.clone(),
                cache.account_revision,
                cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache
                    .mempool_binding
                    .ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache.coins.clone(),
            )
        };
        if current_lock.binding() != binding || current_lock.mempool_binding() != mempool {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let descriptor = current_lock.descriptor();
        let reacquired =
            self.verify_current_shakedex_lock(&descriptor.name, descriptor.seller_public_key)?;
        if !same_current_shakedex_lock(current_lock, &reacquired)
            || reacquired.binding() != binding
            || reacquired.mempool_binding() != mempool
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let funding_inputs = bind_current_tracked_funding_coins(
            &account,
            &cached_coins,
            funding_input_coins,
            current_lock.locking_coin(),
        )?;
        let scope = HnsShakedexFundingScope {
            config: account.config.clone(),
        };
        let name_hash = hash_name(&descriptor.name)
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .into_bytes();
        let source_outpoint = HnsOutpoint {
            transaction: TransactionHash::new(
                current_lock
                    .locking_coin()
                    .outpoint
                    .transaction_hash
                    .into_bytes(),
            ),
            output_index: current_lock.locking_coin().outpoint.index,
        };
        let reservation = HnsShakedexFundingReservation::new(
            &scope,
            workflow_id,
            purpose,
            name_hash,
            source_outpoint,
            funding_inputs,
            expires_at_unix,
        )?;
        validate_reservation_identity(&scope, &reservation, Some(now_unix))?;
        let cache = self.cache_read()?;
        if cache.account_revision != account_revision
            || cache.account != account
            || cache.binding != Some(binding)
            || cache.mempool_binding != Some(mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok((scope, reservation))
    }

    /// Rebind deserialized reservation evidence to the exact current account
    /// cache and current lock before an enclosing workflow may persist it.
    pub fn validate_current_shakedex_funding_reservation(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        reservation: &HnsShakedexFundingReservation,
    ) -> Result<HnsShakedexFundingScope, HnsWalletError> {
        let supplied_coins = reservation
            .funding_inputs
            .iter()
            .map(TrackedHnsCoin::to_canonical_coin)
            .collect::<Result<Vec<_>, _>>()?;
        let (scope, current) = self.bind_shakedex_funding_reservation(
            current_lock,
            reservation.workflow_id,
            reservation.purpose,
            &supplied_coins,
            reservation.expires_at_unix,
        )?;
        if reservation.wallet_id != current.wallet_id
            || reservation.account_id != current.account_id
            || reservation.workflow_id != current.workflow_id
            || reservation.purpose != current.purpose
            || reservation.name_hash != current.name_hash
            || reservation.source_outpoint != current.source_outpoint
            || reservation.expires_at_unix != current.expires_at_unix
            || reservation.funding_inputs.len() != current.funding_inputs.len()
            || reservation
                .funding_inputs
                .iter()
                .zip(&current.funding_inputs)
                .any(|(expected, candidate)| {
                    !same_reserved_funding_coin(
                        expected,
                        candidate,
                        scope.config.minimum_confirmations,
                    )
                })
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        Ok(scope)
    }

    /// Bind the ordinary funding suffix for a script-controlled FINALIZE to a
    /// freshly reacquired, exact current TRANSFER. This API cannot accept a
    /// `VerifiedCurrentShakedexLock`, and it fixes the reservation purpose
    /// rather than trusting a caller-supplied enum value.
    pub fn bind_shakedex_finalize_funding_reservation(
        &self,
        current_transfer: &VerifiedCurrentShakedexTransfer,
        workflow_id: WorkflowId,
        funding_input_coins: &[Coin],
        expires_at_unix: u64,
    ) -> Result<(HnsShakedexFundingScope, HnsShakedexFundingReservation), HnsWalletError> {
        let now_unix = self.clock.now_unix()?;
        let (account, account_revision, binding, mempool, cached_coins) = {
            let cache = self.cache_read()?;
            ensure_shakedex_funding_ready(&cache)?;
            (
                cache.account.clone(),
                cache.account_revision,
                cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache
                    .mempool_binding
                    .ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache.coins.clone(),
            )
        };
        if current_transfer.binding() != binding || current_transfer.mempool_binding() != mempool {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let expected_transfer = TransactionHash::new(
            current_transfer
                .transfer_coin()
                .outpoint
                .transaction_hash
                .into_bytes(),
        );
        let reacquired = self
            .verify_current_shakedex_transfer(current_transfer.descriptor(), expected_transfer)?;
        if !same_current_shakedex_transfer(current_transfer, &reacquired)
            || reacquired.binding() != binding
            || reacquired.mempool_binding() != mempool
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let funding_inputs = bind_current_tracked_funding_coins(
            &account,
            &cached_coins,
            funding_input_coins,
            current_transfer.transfer_coin(),
        )?;
        let scope = HnsShakedexFundingScope {
            config: account.config.clone(),
        };
        let name_hash = hash_name(&current_transfer.descriptor().name)
            .map_err(|_| HnsWalletError::InvalidEvidence)?
            .into_bytes();
        let source_outpoint = HnsOutpoint {
            transaction: expected_transfer,
            output_index: current_transfer.transfer_coin().outpoint.index,
        };
        let reservation = HnsShakedexFundingReservation::new(
            &scope,
            workflow_id,
            HnsShakedexFundingPurpose::SellerScriptFinalize,
            name_hash,
            source_outpoint,
            funding_inputs,
            expires_at_unix,
        )?;
        validate_reservation_identity(&scope, &reservation, Some(now_unix))?;
        let cache = self.cache_read()?;
        if cache.account_revision != account_revision
            || cache.account != account
            || cache.binding != Some(binding)
            || cache.mempool_binding != Some(mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok((scope, reservation))
    }

    /// Rebind deserialized script-FINALIZE reservation evidence to the exact
    /// current account and current TRANSFER before it can be persisted.
    pub fn validate_current_shakedex_finalize_funding_reservation(
        &self,
        current_transfer: &VerifiedCurrentShakedexTransfer,
        reservation: &HnsShakedexFundingReservation,
    ) -> Result<HnsShakedexFundingScope, HnsWalletError> {
        require_finalize_funding_purpose(reservation.purpose)?;
        let supplied_coins = reservation
            .funding_inputs
            .iter()
            .map(TrackedHnsCoin::to_canonical_coin)
            .collect::<Result<Vec<_>, _>>()?;
        let (scope, current) = self.bind_shakedex_finalize_funding_reservation(
            current_transfer,
            reservation.workflow_id,
            &supplied_coins,
            reservation.expires_at_unix,
        )?;
        if reservation.wallet_id != current.wallet_id
            || reservation.account_id != current.account_id
            || reservation.workflow_id != current.workflow_id
            || reservation.purpose != current.purpose
            || reservation.name_hash != current.name_hash
            || reservation.source_outpoint != current.source_outpoint
            || reservation.expires_at_unix != current.expires_at_unix
            || reservation.funding_inputs.len() != current.funding_inputs.len()
            || reservation
                .funding_inputs
                .iter()
                .zip(&current.funding_inputs)
                .any(|(expected, candidate)| {
                    !same_reserved_funding_coin(
                        expected,
                        candidate,
                        scope.config.minimum_confirmations,
                    )
                })
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        Ok(scope)
    }

    /// Sign only ordinary P2PKH inputs `1..` of one exact, canonical Shakedex
    /// transaction. Input zero, including its seller/script witness, is
    /// preserved byte-for-byte. The returned approval remains unconsumed so
    /// the caller can atomically commit it with the aggregate workflow.
    pub fn authorize_shakedex_funding_suffix(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        reservation: &HnsShakedexFundingReservation,
        prepared_transaction: &[u8],
        expected_approval: &HnsShakedexFundingApprovalExpectation,
    ) -> Result<HnsShakedexFundingAuthorization, HnsWalletError> {
        require_lock_funding_purpose(reservation.purpose)?;
        let now_unix = self.clock.now_unix()?;
        let (account, account_revision, binding, mempool, cached_coins) = {
            let cache = self.cache_read()?;
            ensure_shakedex_funding_ready(&cache)?;
            (
                cache.account.clone(),
                cache.account_revision,
                cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache
                    .mempool_binding
                    .ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache.coins.clone(),
            )
        };
        let scope = HnsShakedexFundingScope {
            config: account.config.clone(),
        };
        validate_reservation_identity(&scope, reservation, Some(now_unix))?;
        if expected_approval.expires_at_unix <= now_unix
            || expected_approval.expires_at_unix > reservation.expires_at_unix
        {
            return Err(HnsWalletError::ApprovalRequired);
        }
        validate_current_funding_coins(&account, &cached_coins, reservation)?;
        if current_lock.binding() != binding || current_lock.mempool_binding() != mempool {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }

        let descriptor = current_lock.descriptor();
        let reacquired =
            self.verify_current_shakedex_lock(&descriptor.name, descriptor.seller_public_key)?;
        if !same_current_shakedex_lock(current_lock, &reacquired)
            || reacquired.binding() != binding
            || reacquired.mempool_binding() != mempool
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        validate_lock_reservation_binding(&reacquired, reservation)?;
        let prepared = validate_prepared_shakedex_funding_transaction(
            &reacquired,
            reservation,
            prepared_transaction,
        )?;

        let (pending_approval, signed_transaction) = {
            let store = self.store_lock()?;
            validate_hns_shakedex_funding_reservations(
                &store,
                &scope,
                reservation,
                HnsShakedexFundingReservationState::Prepared,
            )?;
            let pending_approval = store
                .get_pending_approval(expected_approval.approval_id, now_unix)?
                .ok_or(HnsWalletError::ApprovalRequired)?;
            if pending_approval.origin.as_str() != expected_approval.origin.as_str()
                || pending_approval.expires_at_unix != expected_approval.expires_at_unix
                || pending_approval.request_json.as_slice()
                    != expected_approval.request_bytes.as_slice()
            {
                return Err(HnsWalletError::ApprovalRequired);
            }
            let roles = vec![KeyRole::HnsCoin; reservation.funding_inputs.len()];
            let signed = sign_ordered_p2pkh_inputs_from(
                &store,
                &account,
                prepared.clone(),
                1,
                &reservation.funding_inputs,
                &roles,
            )?;
            validate_signed_shakedex_funding_suffix(
                &prepared,
                &signed,
                &reservation.funding_inputs,
            )?;
            (pending_approval, signed)
        };

        let cache = self.cache_read()?;
        if cache.account_revision != account_revision
            || cache.account != account
            || cache.binding != Some(binding)
            || cache.mempool_binding != Some(mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok(HnsShakedexFundingAuthorization {
            signed_transaction,
            pending_approval,
        })
    }

    /// Sign only ordinary P2PKH inputs `1..` of an exact script-FINALIZE.
    /// Current TRANSFER authority, FINALIZE covenant/renewal structure, source
    /// reservation purpose, and the untouched script witness at input zero are
    /// all reauthenticated before any wallet key is used.
    pub fn authorize_shakedex_finalize_funding_suffix(
        &self,
        current_transfer: &VerifiedCurrentShakedexTransfer,
        reservation: &HnsShakedexFundingReservation,
        prepared_transaction: &[u8],
        expected_approval: &HnsShakedexFundingApprovalExpectation,
    ) -> Result<HnsShakedexFundingAuthorization, HnsWalletError> {
        require_finalize_funding_purpose(reservation.purpose)?;
        let now_unix = self.clock.now_unix()?;
        let (account, account_revision, binding, mempool, cached_coins) = {
            let cache = self.cache_read()?;
            ensure_shakedex_funding_ready(&cache)?;
            (
                cache.account.clone(),
                cache.account_revision,
                cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache
                    .mempool_binding
                    .ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache.coins.clone(),
            )
        };
        let scope = HnsShakedexFundingScope {
            config: account.config.clone(),
        };
        validate_reservation_identity(&scope, reservation, Some(now_unix))?;
        if expected_approval.expires_at_unix <= now_unix
            || expected_approval.expires_at_unix > reservation.expires_at_unix
        {
            return Err(HnsWalletError::ApprovalRequired);
        }
        validate_current_funding_coins(&account, &cached_coins, reservation)?;
        if current_transfer.binding() != binding || current_transfer.mempool_binding() != mempool {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }

        let expected_transfer = TransactionHash::new(
            current_transfer
                .transfer_coin()
                .outpoint
                .transaction_hash
                .into_bytes(),
        );
        let reacquired = self
            .verify_current_shakedex_transfer(current_transfer.descriptor(), expected_transfer)?;
        if !same_current_shakedex_transfer(current_transfer, &reacquired)
            || reacquired.binding() != binding
            || reacquired.mempool_binding() != mempool
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        validate_transfer_reservation_binding(&reacquired, reservation)?;
        let prepared = validate_prepared_shakedex_finalize_funding_transaction(
            &reacquired,
            reservation,
            prepared_transaction,
        )?;

        let (pending_approval, signed_transaction) = {
            let store = self.store_lock()?;
            validate_hns_shakedex_funding_reservations(
                &store,
                &scope,
                reservation,
                HnsShakedexFundingReservationState::Prepared,
            )?;
            let pending_approval = store
                .get_pending_approval(expected_approval.approval_id, now_unix)?
                .ok_or(HnsWalletError::ApprovalRequired)?;
            if pending_approval.origin.as_str() != expected_approval.origin.as_str()
                || pending_approval.expires_at_unix != expected_approval.expires_at_unix
                || pending_approval.request_json.as_slice()
                    != expected_approval.request_bytes.as_slice()
            {
                return Err(HnsWalletError::ApprovalRequired);
            }
            let roles = vec![KeyRole::HnsCoin; reservation.funding_inputs.len()];
            let signed = sign_ordered_p2pkh_inputs_from(
                &store,
                &account,
                prepared.clone(),
                1,
                &reservation.funding_inputs,
                &roles,
            )?;
            validate_signed_shakedex_funding_suffix(
                &prepared,
                &signed,
                &reservation.funding_inputs,
            )?;
            (pending_approval, signed)
        };

        let cache = self.cache_read()?;
        if cache.account_revision != account_revision
            || cache.account != account
            || cache.binding != Some(binding)
            || cache.mempool_binding != Some(mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok(HnsShakedexFundingAuthorization {
            signed_transaction,
            pending_approval,
        })
    }

    /// Fetch current status and every exact input spender for one persisted
    /// signed Shakedex transaction from a single runtime-owned chain snapshot.
    pub fn observe_shakedex_transaction(
        &self,
        reservation: &HnsShakedexFundingReservation,
        signed_transaction: &[u8],
    ) -> Result<HnsShakedexTransactionObservation, HnsWalletError> {
        let observed_at_unix = self.clock.now_unix()?;
        let (account, account_revision, binding, mempool) = {
            let cache = self.cache_read()?;
            ensure_shakedex_observation_ready(&cache)?;
            (
                cache.account.clone(),
                cache.account_revision,
                cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?,
                cache
                    .mempool_binding
                    .ok_or(HnsWalletError::StaleNodeSnapshot)?,
            )
        };
        let scope = HnsShakedexFundingScope {
            config: account.config.clone(),
        };
        validate_reservation_identity(&scope, reservation, None)?;
        let (transaction, outpoints) =
            validate_observed_shakedex_transaction(reservation, signed_transaction)?;
        let transaction_hash = wallet_transaction_hash(&transaction)?;
        let transaction_evidence =
            self.backend
                .get_transaction_evidence(transaction_hash, binding, Some(mempool))?;
        if transaction_evidence.binding != binding
            || transaction_evidence.mempool != mempool
            || transaction_evidence
                .raw
                .as_deref()
                .is_some_and(|raw| raw != signed_transaction)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let spend_evidence = self
            .backend
            .get_outpoint_spend_evidence(&outpoints, binding)?;
        if spend_evidence.binding != binding {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        let cache = self.cache_read()?;
        if cache.account_revision != account_revision
            || cache.account != account
            || cache.binding != Some(binding)
            || cache.mempool_binding != Some(mempool)
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        Ok(HnsShakedexTransactionObservation {
            transaction: transaction_hash,
            transaction_evidence,
            spend_evidence,
            observed_at_unix,
        })
    }
}

/// Validate exact final node fee evidence for a Shakedex lock transaction
/// without granting signing, approval, submission, or release qualification.
/// Product paths must still pass their independent runtime and broadcast gates.
pub fn validate_hns_shakedex_final_fee_quote_evidence(
    current_lock: &VerifiedCurrentShakedexLock,
    reservation: &HnsShakedexFundingReservation,
    signed_transaction: &[u8],
    quote: &HnsTransactionFeeQuote,
    expected_fee: BaseUnits,
    maximum_fee: BaseUnits,
) -> Result<(), HnsWalletError> {
    require_lock_funding_purpose(reservation.purpose)?;
    validate_lock_reservation_binding(current_lock, reservation)?;
    let mut coins = Vec::with_capacity(reservation.funding_inputs.len() + 1);
    coins.push(current_lock.locking_coin().clone());
    coins.extend(canonical_input_coins(&reservation.funding_inputs)?);
    validate_final_fee_quote_evidence(
        signed_transaction,
        &coins,
        quote,
        current_lock.binding(),
        current_lock.mempool_binding(),
        expected_fee,
        maximum_fee,
    )
}

/// Validate exact final node fee evidence for a script-controlled FINALIZE.
/// Unlike the lock-spend validator, this accepts only current TRANSFER
/// authority and the purpose dedicated to that source covenant.
pub fn validate_hns_shakedex_finalize_final_fee_quote_evidence(
    current_transfer: &VerifiedCurrentShakedexTransfer,
    reservation: &HnsShakedexFundingReservation,
    signed_transaction: &[u8],
    quote: &HnsTransactionFeeQuote,
    expected_fee: BaseUnits,
    maximum_fee: BaseUnits,
) -> Result<(), HnsWalletError> {
    require_finalize_funding_purpose(reservation.purpose)?;
    validate_transfer_reservation_binding(current_transfer, reservation)?;
    let mut coins = Vec::with_capacity(reservation.funding_inputs.len() + 1);
    coins.push(current_transfer.transfer_coin().clone());
    coins.extend(canonical_input_coins(&reservation.funding_inputs)?);
    validate_final_fee_quote_evidence(
        signed_transaction,
        &coins,
        quote,
        current_transfer.binding(),
        current_transfer.mempool_binding(),
        expected_fee,
        maximum_fee,
    )
}

/// Reauthenticate a persisted Shakedex fee quote from its exact ordered coin
/// evidence after restart. The quote's own snapshot identifiers are retained
/// only as authenticated historical evidence; this function does not claim
/// that either snapshot remains current and cannot authorize submission.
pub fn validate_persisted_hns_shakedex_fee_quote_evidence(
    source_coin: &Coin,
    funding_input_coins: &[Coin],
    signed_transaction: &[u8],
    quote: &HnsTransactionFeeQuote,
    expected_fee: BaseUnits,
    maximum_fee: BaseUnits,
) -> Result<(), HnsWalletError> {
    if funding_input_coins.is_empty()
        || funding_input_coins
            .len()
            .checked_add(1)
            .is_none_or(|count| count > MAX_TRANSACTION_INPUTS)
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut outpoints = HashSet::from([source_coin.outpoint]);
    if source_coin.outpoint.is_null()
        || funding_input_coins
            .iter()
            .any(|coin| coin.outpoint.is_null() || !outpoints.insert(coin.outpoint))
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut coins = Vec::with_capacity(funding_input_coins.len() + 1);
    coins.push(source_coin.clone());
    coins.extend_from_slice(funding_input_coins);
    validate_final_fee_quote_evidence(
        signed_transaction,
        &coins,
        quote,
        quote.binding,
        quote.mempool,
        expected_fee,
        maximum_fee,
    )
}

struct ShakedexFundingSelection<T> {
    prepared: T,
    selected: Vec<TrackedHnsCoin>,
    fee: BaseUnits,
    uses_change: bool,
}

#[allow(clippy::too_many_arguments)]
fn select_shakedex_funding<T, F>(
    source_coin: &Coin,
    mut candidates: Vec<TrackedHnsCoin>,
    change_address: Address,
    ordinary_value: BaseUnits,
    fee_rate: BaseUnits,
    maximum_fee: BaseUnits,
    dust_threshold: BaseUnits,
    minimum_confirmations: u32,
    max_funding_inputs: usize,
    build: &mut F,
) -> Result<ShakedexFundingSelection<T>, HnsWalletError>
where
    F: FnMut(Vec<Input>, Vec<Coin>, Vec<Output>, u64) -> Result<(Vec<u8>, T), HnsWalletError>,
{
    if source_coin.outpoint.is_null()
        || source_coin.coinbase
        || fee_rate.is_zero()
        || maximum_fee.is_zero()
        || dust_threshold.is_zero()
        || minimum_confirmations == 0
        || max_funding_inputs == 0
        || max_funding_inputs >= MAX_TRANSACTION_INPUTS
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    u64::try_from(ordinary_value.get()).map_err(|_| HnsWalletError::InvalidAmount)?;
    let source_outpoint = HnsOutpoint {
        transaction: TransactionHash::new(source_coin.outpoint.transaction_hash.into_bytes()),
        output_index: source_coin.outpoint.index,
    };
    candidates.retain(|candidate| {
        is_ordinary_hns_spend_candidate(candidate)
            && candidate.coin.confirmation_count >= minimum_confirmations
            && candidate.coin.outpoint != source_outpoint
    });
    candidates.sort_by(|left, right| {
        left.coin
            .value
            .cmp(&right.coin.value)
            .then_with(|| left.coin.outpoint.cmp(&right.coin.outpoint))
    });

    let mut selected = Vec::new();
    let mut total = 0_u128;
    for candidate in candidates.into_iter().take(max_funding_inputs) {
        total = total
            .checked_add(candidate.coin.value.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        selected.push(candidate);
        if total <= ordinary_value.get() {
            continue;
        }

        let fee_without_change = total - ordinary_value.get();
        if fee_without_change > 1 {
            let provisional_fee =
                u64::try_from(fee_without_change - 1).map_err(|_| HnsWalletError::InvalidAmount)?;
            let provisional_output = shakedex_change_output(change_address.clone(), 1)?;
            let (_, transaction, input_coins) = build_shakedex_funding_candidate(
                source_coin,
                &selected,
                vec![provisional_output],
                provisional_fee,
                build,
            )?;
            let minimum_fee =
                shakedex_policy_minimum_fee(transaction, &input_coins, selected.len(), fee_rate)?;
            let required_with_fee = ordinary_value
                .get()
                .checked_add(minimum_fee.get())
                .ok_or(HnsWalletError::Arithmetic)?;
            if total >= required_with_fee {
                let change_value = total - required_with_fee;
                if change_value >= dust_threshold.get() {
                    if minimum_fee > maximum_fee {
                        return Err(HnsWalletError::FeeLimit);
                    }
                    let change_value =
                        u64::try_from(change_value).map_err(|_| HnsWalletError::InvalidAmount)?;
                    let exact_fee = u64::try_from(minimum_fee.get())
                        .map_err(|_| HnsWalletError::InvalidAmount)?;
                    let change_output =
                        shakedex_change_output(change_address.clone(), change_value)?;
                    let (prepared, transaction, input_coins) = build_shakedex_funding_candidate(
                        source_coin,
                        &selected,
                        vec![change_output],
                        exact_fee,
                        build,
                    )?;
                    let final_minimum = shakedex_policy_minimum_fee(
                        transaction,
                        &input_coins,
                        selected.len(),
                        fee_rate,
                    )?;
                    if minimum_fee < final_minimum {
                        return Err(HnsWalletError::InvalidFeeQuote);
                    }
                    return Ok(ShakedexFundingSelection {
                        prepared,
                        selected,
                        fee: minimum_fee,
                        uses_change: true,
                    });
                }
            }
        }

        let actual_fee = BaseUnits::new(fee_without_change);
        let actual_fee_u64 =
            u64::try_from(fee_without_change).map_err(|_| HnsWalletError::InvalidAmount)?;
        let (prepared, transaction, input_coins) = build_shakedex_funding_candidate(
            source_coin,
            &selected,
            Vec::new(),
            actual_fee_u64,
            build,
        )?;
        let minimum_fee =
            shakedex_policy_minimum_fee(transaction, &input_coins, selected.len(), fee_rate)?;
        if actual_fee >= minimum_fee && actual_fee <= maximum_fee {
            return Ok(ShakedexFundingSelection {
                prepared,
                selected,
                fee: actual_fee,
                uses_change: false,
            });
        }
    }
    Err(HnsWalletError::InsufficientFunds)
}

fn shakedex_change_output(address: Address, value: u64) -> Result<Output, HnsWalletError> {
    if value == 0 || address.version != 0 || address.hash.len() != 20 {
        return Err(HnsWalletError::InvalidAddress);
    }
    address
        .validate()
        .map_err(|_| HnsWalletError::InvalidAddress)?;
    Ok(Output {
        value: Dollarydoos::new(value),
        address,
        covenant: Covenant::default(),
    })
}

fn build_shakedex_funding_candidate<T, F>(
    source_coin: &Coin,
    selected: &[TrackedHnsCoin],
    funding_outputs: Vec<Output>,
    expected_fee: u64,
    build: &mut F,
) -> Result<(T, Transaction, Vec<Coin>), HnsWalletError>
where
    F: FnMut(Vec<Input>, Vec<Coin>, Vec<Output>, u64) -> Result<(Vec<u8>, T), HnsWalletError>,
{
    if selected.is_empty() || expected_fee == 0 {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let funding_coins = selected
        .iter()
        .map(TrackedHnsCoin::to_canonical_coin)
        .collect::<Result<Vec<_>, _>>()?;
    let funding_inputs = funding_coins
        .iter()
        .map(|coin| Input {
            previous_output: coin.outpoint,
            sequence: u32::MAX,
            witness: Witness::default(),
        })
        .collect::<Vec<_>>();
    let (encoded, prepared) = build(
        funding_inputs,
        funding_coins.clone(),
        funding_outputs,
        expected_fee,
    )?;
    let transaction =
        Transaction::decode(&encoded).map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != encoded
        || transaction.is_coinbase()
        || transaction.inputs.len() != funding_coins.len() + 1
        || transaction.inputs[0].previous_output != source_coin.outpoint
        || transaction.inputs[0].witness.items.is_empty()
        || transaction.inputs[1..]
            .iter()
            .zip(&funding_coins)
            .any(|(input, coin)| {
                input.previous_output != coin.outpoint
                    || input.sequence != u32::MAX
                    || !input.witness.items.is_empty()
            })
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let mut input_coins = Vec::with_capacity(funding_coins.len() + 1);
    input_coins.push(source_coin.clone());
    input_coins.extend(funding_coins);
    if actual_transaction_fee(&transaction, &input_coins)?
        != BaseUnits::new(u128::from(expected_fee))
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    Ok((prepared, transaction, input_coins))
}

fn shakedex_policy_minimum_fee(
    mut transaction: Transaction,
    input_coins: &[Coin],
    funding_input_count: usize,
    fee_rate: BaseUnits,
) -> Result<BaseUnits, HnsWalletError> {
    if funding_input_count == 0 || transaction.inputs.len() != funding_input_count + 1 {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    for input in &mut transaction.inputs[1..] {
        if !input.witness.items.is_empty() {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        input.witness = Witness {
            items: vec![vec![0; 65], vec![0; 33]],
        };
    }
    canonical_policy_minimum_fee(&transaction, input_coins, fee_rate)
}

pub(super) fn ensure_shakedex_funding_ready(cache: &HnsRuntimeCache) -> Result<(), HnsWalletError> {
    if !HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED
        || !HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
        || !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
        || !cache.account.config.value_operations_enabled
    {
        return Err(HnsWalletError::RuntimeIntegrationUnavailable);
    }
    if cache.sync.phase != SyncPhase::Ready
        || cache.sync.validated_height != cache.sync.scanned_height
        || cache.sync.target_height != Some(cache.sync.validated_height)
        || cache.binding.is_none()
        || cache.mempool_binding.is_none()
    {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    Ok(())
}

fn ensure_shakedex_observation_ready(cache: &HnsRuntimeCache) -> Result<(), HnsWalletError> {
    if cache.sync.phase != SyncPhase::Ready
        || cache.sync.validated_height != cache.sync.scanned_height
        || cache.sync.target_height != Some(cache.sync.validated_height)
        || cache.binding.is_none()
        || cache.mempool_binding.is_none()
    {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    Ok(())
}

fn require_lock_funding_purpose(purpose: HnsShakedexFundingPurpose) -> Result<(), HnsWalletError> {
    if matches!(
        purpose,
        HnsShakedexFundingPurpose::BuyerFulfillment | HnsShakedexFundingPurpose::SellerRecovery
    ) {
        Ok(())
    } else {
        Err(HnsWalletError::InvalidWorkflow)
    }
}

fn require_finalize_funding_purpose(
    purpose: HnsShakedexFundingPurpose,
) -> Result<(), HnsWalletError> {
    if purpose == HnsShakedexFundingPurpose::SellerScriptFinalize {
        Ok(())
    } else {
        Err(HnsWalletError::InvalidWorkflow)
    }
}

fn validate_reservation_identity(
    scope: &HnsShakedexFundingScope,
    reservation: &HnsShakedexFundingReservation,
    now_unix: Option<u64>,
) -> Result<(), HnsWalletError> {
    if reservation.wallet_id != scope.config.wallet_id
        || reservation.account_id != scope.config.account_id
        || reservation
            .workflow_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || reservation.name_hash.iter().all(|byte| *byte == 0)
        || reservation
            .source_outpoint
            .transaction
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || reservation.funding_inputs.is_empty()
        || reservation.funding_inputs.len() >= MAX_TRANSACTION_INPUTS
        || reservation.expires_at_unix == 0
        || now_unix.is_some_and(|now| reservation.expires_at_unix <= now)
        || now_unix.is_some_and(|now| {
            reservation.expires_at_unix > now.saturating_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
        })
    {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let mut outpoints = BTreeSet::from([reservation.source_outpoint]);
    for input in &reservation.funding_inputs {
        if !is_ordinary_hns_spend_candidate(input)
            || input.derivation.account != account_number_from_config(&scope.config)
            || input.coin.confirmation_count < scope.config.minimum_confirmations
            || !outpoints.insert(input.coin.outpoint)
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let canonical = input.to_canonical_coin()?;
        if canonical.coinbase || canonical.covenant.kind != CovenantKind::None {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(())
}

fn account_number_from_config(config: &HnsRuntimeConfig) -> u32 {
    config.account_derivation_index
}

fn expected_reservation_kinds(
    reservation: &HnsShakedexFundingReservation,
) -> Result<BTreeMap<HnsOutpoint, HnsInputReservationKind>, HnsWalletError> {
    let mut expected = BTreeMap::new();
    expected.insert(
        reservation.source_outpoint,
        HnsInputReservationKind::ShakedexSource {
            name_hash: reservation.name_hash,
            purpose: reservation.purpose,
        },
    );
    for input in &reservation.funding_inputs {
        if expected
            .insert(
                input.coin.outpoint,
                HnsInputReservationKind::ShakedexFunding {
                    name_hash: reservation.name_hash,
                    purpose: reservation.purpose,
                },
            )
            .is_some()
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
    }
    Ok(expected)
}

fn global_shakedex_source_reservation_id(outpoint: HnsOutpoint) -> Vec<u8> {
    let mut id = b"hns-wallet-rs/shakedex-source-reservation/v1".to_vec();
    id.extend_from_slice(outpoint.transaction.as_bytes());
    id.extend_from_slice(&outpoint.output_index.to_be_bytes());
    id
}

fn shakedex_reservation_record_id(
    config: &HnsRuntimeConfig,
    outpoint: HnsOutpoint,
    kind: HnsInputReservationKind,
) -> Vec<u8> {
    if matches!(kind, HnsInputReservationKind::ShakedexSource { .. }) {
        global_shakedex_source_reservation_id(outpoint)
    } else {
        namespaced_outpoint_id(config, outpoint).to_vec()
    }
}

fn stored_shakedex_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    reservation: &HnsShakedexFundingReservation,
) -> Result<Vec<StoredEntity<HnsInputReservation>>, HnsWalletError> {
    let mut matching: Vec<_> = account_input_reservations(store, &scope.config)?
        .into_iter()
        .filter(|stored| stored.value.workflow_id == reservation.workflow_id)
        .collect();
    let source_id = global_shakedex_source_reservation_id(reservation.source_outpoint);
    if let Some(source) = store
        .load_entity::<HnsInputReservation>(EntityKind::InputReservation, &source_id)?
        .filter(|stored| stored.value.workflow_id == reservation.workflow_id)
    {
        matching.push(source);
    }
    Ok(matching)
}

fn validate_current_funding_coins(
    account: &HnsAccountRecord,
    cached_coins: &[TrackedHnsCoin],
    reservation: &HnsShakedexFundingReservation,
) -> Result<(), HnsWalletError> {
    if reservation.wallet_id != account.config.wallet_id
        || reservation.account_id != account.config.account_id
    {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    for expected in &reservation.funding_inputs {
        let matching = cached_coins.iter().filter(|candidate| {
            same_reserved_funding_coin(expected, candidate, account.config.minimum_confirmations)
        });
        if matching.count() != 1 {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(())
}

fn same_reserved_funding_coin(
    expected: &TrackedHnsCoin,
    current: &TrackedHnsCoin,
    minimum_confirmations: u32,
) -> bool {
    current.coin.confirmation_count >= minimum_confirmations
        && current.coin.outpoint == expected.coin.outpoint
        && current.coin.value == expected.coin.value
        && current.coin.confirmed_height == expected.coin.confirmed_height
        && current.coin.coinbase == expected.coin.coinbase
        && current.coin.covenant == expected.coin.covenant
        && current.coin.name_locked == expected.coin.name_locked
        && current.derivation == expected.derivation
        && current.address_program == expected.address_program
}

fn bind_current_tracked_funding_coins(
    account: &HnsAccountRecord,
    cached_coins: &[TrackedHnsCoin],
    supplied_coins: &[Coin],
    source_coin: &Coin,
) -> Result<Vec<TrackedHnsCoin>, HnsWalletError> {
    if supplied_coins.is_empty() || supplied_coins.len() >= MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut outpoints = HashSet::from([source_coin.outpoint]);
    let mut tracked = Vec::with_capacity(supplied_coins.len());
    for supplied in supplied_coins {
        if supplied.outpoint.is_null()
            || supplied.coinbase
            || supplied.covenant.kind != CovenantKind::None
            || !outpoints.insert(supplied.outpoint)
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let mut matching = cached_coins.iter().filter_map(|candidate| {
            if !is_ordinary_hns_spend_candidate(candidate)
                || candidate.derivation.account != account_number(account)
                || candidate.coin.confirmation_count < account.config.minimum_confirmations
            {
                return None;
            }
            candidate
                .to_canonical_coin()
                .ok()
                .filter(|canonical| canonical == supplied)
                .map(|_| candidate)
        });
        let candidate = matching.next().ok_or(HnsWalletError::InvalidEvidence)?;
        if matching.next().is_some() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        tracked.push(candidate.clone());
    }
    Ok(tracked)
}

fn same_current_shakedex_lock(
    left: &VerifiedCurrentShakedexLock,
    right: &VerifiedCurrentShakedexLock,
) -> bool {
    left.binding() == right.binding()
        && left.mempool_binding() == right.mempool_binding()
        && left.descriptor() == right.descriptor()
        && left.locking_coin() == right.locking_coin()
        && left.current_name_state() == right.current_name_state()
}

fn same_current_shakedex_transfer(
    left: &VerifiedCurrentShakedexTransfer,
    right: &VerifiedCurrentShakedexTransfer,
) -> bool {
    left.binding() == right.binding()
        && left.mempool_binding() == right.mempool_binding()
        && left.descriptor() == right.descriptor()
        && left.transfer_transaction() == right.transfer_transaction()
        && left.transfer_coin() == right.transfer_coin()
        && left.owner_inclusion() == right.owner_inclusion()
        && left.current_name_state() == right.current_name_state()
        && left.renewal_block_height() == right.renewal_block_height()
        && left.renewal_block_hash() == right.renewal_block_hash()
}

fn validate_lock_reservation_binding(
    current_lock: &VerifiedCurrentShakedexLock,
    reservation: &HnsShakedexFundingReservation,
) -> Result<(), HnsWalletError> {
    let descriptor = current_lock.descriptor();
    let name_hash = hash_name(&descriptor.name).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let locking = current_lock.locking_coin();
    let outpoint = HnsOutpoint {
        transaction: TransactionHash::new(locking.outpoint.transaction_hash.into_bytes()),
        output_index: locking.outpoint.index,
    };
    if reservation.name_hash != *name_hash.as_bytes() || reservation.source_outpoint != outpoint {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn validate_transfer_reservation_binding(
    current_transfer: &VerifiedCurrentShakedexTransfer,
    reservation: &HnsShakedexFundingReservation,
) -> Result<(), HnsWalletError> {
    require_finalize_funding_purpose(reservation.purpose)?;
    let descriptor = current_transfer.descriptor();
    let name_hash = hash_name(&descriptor.name).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let transfer = current_transfer.transfer_coin();
    let outpoint = HnsOutpoint {
        transaction: TransactionHash::new(transfer.outpoint.transaction_hash.into_bytes()),
        output_index: transfer.outpoint.index,
    };
    if reservation.name_hash != *name_hash.as_bytes() || reservation.source_outpoint != outpoint {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn validate_prepared_shakedex_funding_transaction(
    current_lock: &VerifiedCurrentShakedexLock,
    reservation: &HnsShakedexFundingReservation,
    prepared_transaction: &[u8],
) -> Result<Transaction, HnsWalletError> {
    validate_prepared_shakedex_funding_transaction_for_source(
        current_lock.locking_coin(),
        reservation,
        prepared_transaction,
    )
}

fn validate_prepared_shakedex_funding_transaction_for_source(
    source_coin: &Coin,
    reservation: &HnsShakedexFundingReservation,
    prepared_transaction: &[u8],
) -> Result<Transaction, HnsWalletError> {
    let transaction = Transaction::decode(prepared_transaction)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != prepared_transaction
        || transaction.is_coinbase()
        || transaction.inputs.len() != reservation.funding_inputs.len() + 1
        || transaction.inputs[0].previous_output != source_coin.outpoint
        || transaction.inputs[0].witness.items.is_empty()
        || transaction.inputs[1..]
            .iter()
            .any(|input| !input.witness.items.is_empty())
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    for (input, coin) in transaction.inputs[1..]
        .iter()
        .zip(&reservation.funding_inputs)
    {
        if input.previous_output != coin.to_canonical_coin()?.outpoint {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
    }
    Ok(transaction)
}

fn validate_prepared_shakedex_finalize_funding_transaction(
    current_transfer: &VerifiedCurrentShakedexTransfer,
    reservation: &HnsShakedexFundingReservation,
    prepared_transaction: &[u8],
) -> Result<Transaction, HnsWalletError> {
    validate_transfer_reservation_binding(current_transfer, reservation)?;
    let transaction = validate_prepared_shakedex_funding_transaction_for_source(
        current_transfer.transfer_coin(),
        reservation,
        prepared_transaction,
    )?;
    hns_transaction::verify_finalize_at_index_zero(
        &transaction,
        current_transfer.transfer_coin(),
        current_transfer.current_name_state(),
        BlockHash::new(current_transfer.renewal_block_hash()),
    )
    .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let transfer = TransferCovenant::try_from(&current_transfer.transfer_coin().covenant)
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if transaction.inputs[0].witness
        != current_transfer
            .descriptor()
            .finalize_witness()
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        || transaction.outputs.first().is_none_or(|output| {
            output.address.version != transfer.recipient_version
                || output.address.hash != transfer.recipient_hash
        })
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    Ok(transaction)
}

fn validate_observed_shakedex_transaction(
    reservation: &HnsShakedexFundingReservation,
    signed_transaction: &[u8],
) -> Result<(Transaction, Vec<HnsOutpoint>), HnsWalletError> {
    let transaction = Transaction::decode(signed_transaction)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != signed_transaction
        || transaction.is_coinbase()
        || transaction.inputs.len() != reservation.funding_inputs.len() + 1
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let mut expected = Vec::with_capacity(transaction.inputs.len());
    expected.push(reservation.source_outpoint);
    expected.extend(
        reservation
            .funding_inputs
            .iter()
            .map(|coin| coin.coin.outpoint),
    );
    for (input, outpoint) in transaction.inputs.iter().zip(&expected) {
        if input.previous_output.transaction_hash.as_bytes() != outpoint.transaction.as_bytes()
            || input.previous_output.index != outpoint.output_index
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
    }
    Ok((transaction, expected))
}

fn validate_signed_shakedex_funding_suffix(
    prepared: &Transaction,
    signed_bytes: &[u8],
    funding_inputs: &[TrackedHnsCoin],
) -> Result<(), HnsWalletError> {
    let signed =
        Transaction::decode(signed_bytes).map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if signed
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != signed_bytes
        || signed.version != prepared.version
        || signed.outputs != prepared.outputs
        || signed.locktime != prepared.locktime
        || signed.inputs.len() != prepared.inputs.len()
        || signed.inputs.first() != prepared.inputs.first()
        || signed.inputs[1..]
            .iter()
            .zip(&prepared.inputs[1..])
            .any(|(left, right)| {
                left.previous_output != right.previous_output || left.sequence != right.sequence
            })
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    for (offset, tracked) in funding_inputs.iter().enumerate() {
        let index = offset + 1;
        let canonical = tracked.to_canonical_coin()?;
        hns_script::verify_witness_program(
            &signed,
            index,
            &canonical,
            hns_script::ScriptFlags::STANDARD,
            &hns_script::K256SignatureVerifier,
        )
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_store() -> (TestDirectory, WalletStore) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hns-shakedex-global-reservation-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("test directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("private test directory");
        let store = WalletStore::create(directory.join("wallet.sqlite3"), "test-passphrase")
            .expect("encrypted store");
        (TestDirectory(directory), store)
    }

    fn scope(wallet: u8, account: u8, derivation: u32) -> HnsShakedexFundingScope {
        HnsShakedexFundingScope {
            config: HnsRuntimeConfig {
                wallet_id: WalletId::new([wallet; 16]),
                account_id: AccountId::new([account; 16]),
                account_derivation_index: derivation,
                network: HnsNetwork::Regtest,
                birthday_height: 1,
                restore_lookahead: DEFAULT_RESTORE_LOOKAHEAD,
                minimum_confirmations: 1,
                dust_threshold: BaseUnits::new(DEFAULT_DUST_THRESHOLD),
                value_operations_enabled: false,
                settlement_enabled: false,
            },
        }
    }

    fn funding_input(scope: &HnsShakedexFundingScope, tag: u8) -> TrackedHnsCoin {
        TrackedHnsCoin {
            coin: WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([tag; 32]),
                    output_index: u32::from(tag),
                },
                value: BaseUnits::new(50_000),
                confirmation_count: 4,
                confirmed_height: Some(100),
                coinbase: false,
                covenant: Covenant::default().encode().expect("covenant"),
                name_locked: false,
            },
            derivation: DerivationReference {
                role: KeyRole::HnsCoin,
                account: scope.config.account_derivation_index,
                change: 0,
                index: u32::from(tag),
            },
            address_program: vec![tag; 20],
        }
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn hns_shakedex_global_source_reservation_cas() {
        // Bind this source-reservation regression to the release gate remaining
        // closed; the assertion is intentionally compile-time visible.
        assert!(HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED);
        let (_directory, mut store) = test_store();
        let first_scope = scope(1, 2, 3);
        let second_scope = scope(4, 5, 6);
        let prepared_funding = funding_input(&first_scope, 0x20);
        let mut advanced_funding = prepared_funding.clone();
        advanced_funding.coin.confirmation_count += 12;
        assert!(same_reserved_funding_coin(
            &prepared_funding,
            &advanced_funding,
            first_scope.config.minimum_confirmations,
        ));
        advanced_funding.coin.value = BaseUnits::new(50_001);
        assert!(!same_reserved_funding_coin(
            &prepared_funding,
            &advanced_funding,
            first_scope.config.minimum_confirmations,
        ));
        let source = HnsOutpoint {
            transaction: TransactionHash::new([0x77; 32]),
            output_index: 9,
        };
        let first = HnsShakedexFundingReservation::new(
            &first_scope,
            WorkflowId::new([0x11; 16]),
            HnsShakedexFundingPurpose::BuyerFulfillment,
            [0x44; 32],
            source,
            vec![funding_input(&first_scope, 0x21)],
            1_000 + PREPARED_ARTIFACT_LIFETIME_SECONDS,
        )
        .expect("first reservation");
        let second = HnsShakedexFundingReservation::new(
            &second_scope,
            WorkflowId::new([0x12; 16]),
            HnsShakedexFundingPurpose::BuyerFulfillment,
            [0x44; 32],
            source,
            vec![funding_input(&second_scope, 0x22)],
            1_000 + PREPARED_ARTIFACT_LIFETIME_SECONDS,
        )
        .expect("second reservation");

        let prepared =
            create_hns_shakedex_funding_reservations(&store, &first_scope, &first, 1_000)
                .expect("prepare first");
        store
            .apply_entity_batch::<HnsInputReservation>(
                EntityKind::InputReservation,
                prepared.saves(),
                prepared.deletes(),
            )
            .expect("persist first");
        validate_hns_shakedex_funding_reservations(
            &store,
            &first_scope,
            &first,
            HnsShakedexFundingReservationState::Prepared,
        )
        .expect("prepared rows");
        assert!(
            create_hns_shakedex_funding_reservations(&store, &second_scope, &second, 1_001,)
                .is_err(),
            "the source outpoint is globally exclusive across accounts"
        );

        let active =
            activate_hns_shakedex_funding_reservations(&store, &first_scope, &first, 1_002)
                .expect("activate first");
        store
            .apply_entity_batch::<HnsInputReservation>(
                EntityKind::InputReservation,
                active.saves(),
                active.deletes(),
            )
            .expect("persist active rows");
        validate_hns_shakedex_funding_reservations(
            &store,
            &first_scope,
            &first,
            HnsShakedexFundingReservationState::Active,
        )
        .expect("active rows");

        let released = delete_hns_shakedex_funding_reservations(
            &store,
            &first_scope,
            &first,
            HnsShakedexFundingReservationState::Active,
        )
        .expect("release first");
        store
            .apply_entity_batch::<HnsInputReservation>(
                EntityKind::InputReservation,
                released.saves(),
                released.deletes(),
            )
            .expect("persist release");
        validate_hns_shakedex_funding_reservations(
            &store,
            &first_scope,
            &first,
            HnsShakedexFundingReservationState::Released,
        )
        .expect("released rows absent");
        create_hns_shakedex_funding_reservations(&store, &second_scope, &second, 1_003)
            .expect("source reusable only after explicit release");
    }

    #[test]
    fn production_next_shakedex_finalize_purpose_never_crosses_lock_authority() {
        for purpose in [
            HnsShakedexFundingPurpose::BuyerFulfillment,
            HnsShakedexFundingPurpose::SellerRecovery,
        ] {
            assert!(require_lock_funding_purpose(purpose).is_ok());
            assert!(require_finalize_funding_purpose(purpose).is_err());
        }
        assert!(
            require_lock_funding_purpose(HnsShakedexFundingPurpose::SellerScriptFinalize).is_err()
        );
        assert!(
            require_finalize_funding_purpose(HnsShakedexFundingPurpose::SellerScriptFinalize)
                .is_ok()
        );
    }
}

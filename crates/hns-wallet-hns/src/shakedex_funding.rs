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

fn ensure_shakedex_funding_ready(cache: &HnsRuntimeCache) -> Result<(), HnsWalletError> {
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
        assert!(!HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED);
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

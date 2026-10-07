//! Immutable session policy metadata and the store boundary enforcing it.

use super::{SessionConfig, Split, VoucherSigner};
use crate::mpp::{
    error::{Error, Result},
    store::{ChannelLifecycle, ChannelState, ChannelStore, StoreError},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{future::Future, pin::Pin};

const BINDING_KEY: &str = "mppSessionBinding";

/// Public configuration captured when a scoped channel is opened.
///
/// Signing keys and RPC connections are runtime capabilities, never persisted.
/// Restore this snapshot before constructing a recovery or settlement server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfigSnapshot {
    operator: String,
    recipient: String,
    splits: Vec<Split>,
    amount: u64,
    suggested_deposit: Option<u64>,
    minimum_deposit: Option<u64>,
    currency: String,
    decimals: u8,
    network: String,
    channel_program: Option<solana_pubkey::Pubkey>,
    token_program: Option<solana_pubkey::Pubkey>,
    min_voucher_delta: u64,
    voucher_signer: VoucherSigner,
    idle_timeout_options_seconds: Option<Vec<u32>>,
    idle_timeout_seconds: u32,
    grace_period_seconds: u32,
    fee_payer: Option<solana_pubkey::Pubkey>,
}

impl SessionConfigSnapshot {
    /// Capture public configuration without creating or authorizing a channel.
    /// Only the server's validated open flow may persist a channel binding.
    pub fn capture(config: &SessionConfig) -> Self {
        Self {
            operator: config.operator.clone(),
            recipient: config.recipient.clone(),
            splits: config.splits.clone(),
            amount: config.amount,
            suggested_deposit: config.suggested_deposit,
            minimum_deposit: config.minimum_deposit,
            // Invalid configuration remains invalid and cannot pass open
            // validation. Valid aliases are pinned to their concrete mint.
            currency: super::expected_payment_channel_mint(config)
                .map(|mint| mint.to_string())
                .unwrap_or_else(|_| config.currency.clone()),
            decimals: config.decimals,
            network: config.network.clone(),
            channel_program: Some(
                config
                    .channel_program
                    .unwrap_or_else(crate::mpp::program::payment_channels::default_program_id),
            ),
            token_program: config.token_program.or_else(|| {
                super::parse_pubkey_field(
                    crate::mpp::protocol::solana::default_token_program_for_currency(
                        &config.currency,
                        Some(config.network.as_str()),
                    ),
                    "token program",
                )
                .ok()
            }),
            min_voucher_delta: config.min_voucher_delta,
            voucher_signer: config.voucher_signer,
            idle_timeout_options_seconds: config.idle_timeout_options_seconds.clone(),
            idle_timeout_seconds: config.idle_timeout_seconds,
            grace_period_seconds: config.grace_period_seconds,
            fee_payer: config
                .fee_payer_signer
                .as_ref()
                .map(|signer| signer.pubkey()),
        }
    }

    /// Read the versioned snapshot. Legacy, unscoped channels return `None`.
    pub fn from_channel(state: &ChannelState) -> Result<Option<Self>> {
        Ok(read_binding(state)?.map(|binding| binding.snapshot))
    }

    /// Whether recovery needs the original transaction sponsor capability.
    pub fn requires_fee_payer(&self) -> bool {
        self.fee_payer.is_some()
    }

    /// Restore public policy while retaining the host's RPC and signing keys.
    /// The host must supply the original operator/sponsor signing capability.
    pub fn apply_to(&self, config: &mut SessionConfig) -> Result<()> {
        if self.fee_payer
            != config
                .fee_payer_signer
                .as_ref()
                .map(|signer| signer.pubkey())
        {
            return Err(Error::Other(
                "session snapshot fee-payer capability mismatch".into(),
            ));
        }
        config.operator = self.operator.clone();
        config.recipient = self.recipient.clone();
        config.splits = self.splits.clone();
        config.amount = self.amount;
        config.suggested_deposit = self.suggested_deposit;
        config.minimum_deposit = self.minimum_deposit;
        config.currency = self.currency.clone();
        config.decimals = self.decimals;
        config.network = self.network.clone();
        config.channel_program = self.channel_program;
        config.token_program = self.token_program;
        config.min_voucher_delta = self.min_voucher_delta;
        config.voucher_signer = self.voucher_signer;
        config.idle_timeout_options_seconds = self.idle_timeout_options_seconds.clone();
        config.idle_timeout_seconds = self.idle_timeout_seconds;
        config.grace_period_seconds = self.grace_period_seconds;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    version: u32,
    policy: Value,
    snapshot: SessionConfigSnapshot,
}

impl Binding {
    pub(super) fn new(policy: Value, config: &SessionConfig) -> Self {
        Self {
            version: 1,
            policy,
            snapshot: SessionConfigSnapshot::capture(config),
        }
    }

    pub(super) fn insert(&self, state: &mut ChannelState) -> Result<()> {
        state.schema_version = crate::mpp::store::CHANNEL_STATE_SCHEMA_VERSION;
        state.extra.insert(
            BINDING_KEY.into(),
            serde_json::to_value(self)
                .map_err(|error| Error::Other(format!("serialize session binding: {error}")))?,
        );
        Ok(())
    }
}

fn read_binding(state: &ChannelState) -> Result<Option<Binding>> {
    let Some(value) = state.extra.get(BINDING_KEY) else {
        return Ok(None);
    };
    let binding: Binding = serde_json::from_value(value.clone())
        .map_err(|_| Error::Other("invalid session policy binding".into()))?;
    if binding.version != 1 {
        return Err(Error::Other(
            "unsupported session policy binding version".into(),
        ));
    }
    Ok(Some(binding))
}

/// Read opaque host policy identity from versioned, trusted store metadata.
pub fn channel_binding(state: &ChannelState) -> Result<Option<Value>> {
    Ok(read_binding(state)?.map(|binding| binding.policy))
}

pub(super) fn require_binding(
    state: &ChannelState,
    expected: &Option<Binding>,
    allow_pending: bool,
) -> Result<()> {
    if super::session_open_is_terminal(state) {
        return Err(Error::Other(super::OPEN_TERMINAL_ERROR.into()));
    }
    if read_binding(state)? != *expected {
        return Err(Error::Other(
            "channel session policy binding mismatch".into(),
        ));
    }
    if !allow_pending
        && state
            .pending_setup
            .as_ref()
            .is_some_and(|setup| setup.opens_channel)
    {
        return Err(Error::Other("channel open is pending confirmation".into()));
    }
    Ok(())
}

type StoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, StoreError>> + Send + 'a>>;
type Updater =
    Box<dyn FnOnce(Option<ChannelState>) -> std::result::Result<ChannelState, StoreError> + Send>;

/// All request-time reads and atomic mutations pass through one policy guard.
/// Open/recovery alone use `inner`, because pending records cannot authorize.
pub(super) struct BoundStore<S> {
    pub(super) inner: S,
    pub(super) binding: Option<Binding>,
}

impl<S> BoundStore<S> {
    fn check(
        state: &ChannelState,
        binding: &Option<Binding>,
    ) -> std::result::Result<(), StoreError> {
        require_binding(state, binding, false)
            .map_err(|error| StoreError::Internal(error.to_string()))
    }
}

impl<S: ChannelStore> ChannelStore for BoundStore<S> {
    fn get_channel(&self, id: &str) -> StoreFuture<'_, Option<ChannelState>> {
        let id = id.to_owned();
        Box::pin(async move {
            let state = self.inner.get_channel(&id).await?;
            if let Some(state) = &state {
                Self::check(state, &self.binding)?;
            }
            Ok(state)
        })
    }

    fn update_channel(&self, id: &str, updater: Updater) -> StoreFuture<'_, ChannelState> {
        let binding = self.binding.clone();
        self.inner.update_channel(
            id,
            Box::new(move |state| {
                if let Some(state) = &state {
                    Self::check(state, &binding)?;
                }
                let updated = updater(state)?;
                Self::check(&updated, &binding)?;
                Ok(updated)
            }),
        )
    }

    fn read_channel(
        &self,
        id: &str,
        reader: Box<
            dyn FnOnce(Option<&ChannelState>) -> std::result::Result<(), StoreError> + Send,
        >,
    ) -> StoreFuture<'_, ()> {
        let binding = self.binding.clone();
        self.inner.read_channel(
            id,
            Box::new(move |state| {
                if let Some(state) = state {
                    Self::check(state, &binding)?;
                }
                reader(state)
            }),
        )
    }

    fn mutate_channel(
        &self,
        id: &str,
        seed: Option<ChannelState>,
        mutator: Box<dyn FnOnce(&mut ChannelState) -> std::result::Result<(), StoreError> + Send>,
    ) -> StoreFuture<'_, ()> {
        let id = id.to_owned();
        Box::pin(async move {
            self.update_channel(
                &id,
                Box::new(move |state| {
                    let mut state = state
                        .or(seed)
                        .ok_or_else(|| StoreError::Internal("Channel not found".into()))?;
                    mutator(&mut state)?;
                    Ok(state)
                }),
            )
            .await?;
            Ok(())
        })
    }

    fn put_channel(&self, id: &str, state: ChannelState) -> StoreFuture<'_, ()> {
        let id = id.to_owned();
        Box::pin(async move {
            self.update_channel(
                &id,
                Box::new(move |existing| {
                    if existing.is_some() {
                        return Err(StoreError::Internal("Channel already exists".into()));
                    }
                    Ok(state)
                }),
            )
            .await?;
            Ok(())
        })
    }

    fn list_channels(&self) -> StoreFuture<'_, Vec<ChannelState>> {
        Box::pin(async move {
            Ok(self
                .inner
                .list_channels()
                .await?
                .into_iter()
                .filter(|state| Self::check(state, &self.binding).is_ok())
                .collect())
        })
    }

    fn advance_cumulative(&self, id: &str, expected: u64, new: u64) -> StoreFuture<'_, bool> {
        let id = id.to_owned();
        Box::pin(async move {
            let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let output = changed.clone();
            self.update_channel(
                &id,
                Box::new(move |state| {
                    let mut state =
                        state.ok_or_else(|| StoreError::Internal("Channel not found".into()))?;
                    if state.cumulative == expected {
                        state.cumulative = new;
                        output.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    Ok(state)
                }),
            )
            .await?;
            Ok(changed.load(std::sync::atomic::Ordering::Relaxed))
        })
    }

    fn update_deposit(&self, id: &str, deposit: u64) -> StoreFuture<'_, ()> {
        self.mutate_channel(
            id,
            None,
            Box::new(move |state| {
                state.deposit = deposit;
                Ok(())
            }),
        )
    }

    fn mark_sealed(&self, id: &str) -> StoreFuture<'_, ()> {
        self.mutate_channel(
            id,
            None,
            Box::new(|state| {
                state.sealed = true;
                Ok(())
            }),
        )
    }

    fn touch_channel_lifecycle(
        &self,
        id: &str,
        lifecycle: ChannelLifecycle,
    ) -> StoreFuture<'_, ChannelState> {
        self.update_channel(
            id,
            Box::new(move |state| {
                let mut state =
                    state.ok_or_else(|| StoreError::Internal("Channel not found".into()))?;
                if !state.sealed
                    && state.close_requested_at.is_none()
                    && state.final_cumulative.is_none()
                    && state
                        .lifecycle
                        .as_ref()
                        .is_none_or(|current| current.close_after < lifecycle.close_after)
                {
                    state.lifecycle = Some(lifecycle);
                }
                Ok(state)
            }),
        )
    }

    // Workers use the raw store after reconciling the immutable snapshot.
    fn delete_channel(&self, _: &str) -> StoreFuture<'_, ()> {
        Box::pin(async {
            Err(StoreError::Internal(
                "request server cannot delete channels".into(),
            ))
        })
    }

    fn mark_finalized(&self, _: &str) -> StoreFuture<'_, ()> {
        Box::pin(async {
            Err(StoreError::Internal(
                "request server cannot finalize channels".into(),
            ))
        })
    }
}

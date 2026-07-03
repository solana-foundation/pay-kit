//! Chain-data source for client-side transaction builders.
//!
//! The charge/payment builders need two pieces of chain data the server's
//! challenge may or may not carry: a recent blockhash and (for SPL charges)
//! the mint's owning token program. Natively they can fall back to an RPC
//! fetch; on wasm32-unknown-unknown there is no RPC client, so the `_offline`
//! builder variants require the challenge to be self-contained and surface a
//! descriptive error otherwise.

use std::marker::PhantomData;

/// Where a client-side builder gets chain data the challenge omits.
#[derive(Clone, Copy)]
pub(crate) enum ChainSource<'a> {
    /// Fall back to this RPC client for anything the challenge omits.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    Rpc(&'a solana_rpc_client::rpc_client::RpcClient),
    /// No fallback: the challenge must be self-contained. The `PhantomData`
    /// keeps the lifetime parameter alive on wasm, where `Rpc` is compiled out.
    Offline(PhantomData<&'a ()>),
}

impl ChainSource<'_> {
    /// The no-fallback source used by the `_offline` builder variants.
    pub(crate) const OFFLINE: Self = Self::Offline(PhantomData);
}

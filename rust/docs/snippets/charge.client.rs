//! Client-side charge: read the 402 challenge, sign a credential, retry.
//!
//! Mirrors the Client section of `rust/README.md`. See
//! `../../../docs/snippets-convention.md` for the snippet:start/end convention.

use solana_pay_kit::mpp::client::{build_credential_header, parse_challenge};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;

async fn pay(
    www_authenticate: &str,
    signer: &MemorySigner,
    rpc: &RpcClient,
) -> Result<(), Box<dyn std::error::Error>> {
    // snippet:start
    // 1. Parse the MPP charge challenge from the 402 `WWW-Authenticate` header.
    let challenge = parse_challenge(www_authenticate)?;

    // 2. Sign a payment credential and replay the request with it.
    let authorization = build_credential_header(signer, rpc, &challenge).await?;
    let res = reqwest::Client::new()
        .get("${URL}")
        .header("Authorization", authorization)
        .send()
        .await?;
    println!("{}", res.text().await?);
    // snippet:end
    Ok(())
}

//! MPP deployment selection is explicit; account bytes never select an ABI.

use crate::core::payment_channels_v2::{ChannelHooks, Deployment};
use crate::mpp::error::{Error, Result};
use solana_pubkey::Pubkey;

/// Validate MPP deployment identity before approval, signing, or advertisement.
///
/// The integrated V2 deployment is supported only on devnet and localnet.
/// V1 network handling is unchanged.
pub fn resolve_for_network(
    program: Pubkey,
    version: Option<u8>,
    hooks: Option<&ChannelHooks>,
    network: &str,
) -> Result<Deployment> {
    let deployment = resolve(program, version, hooks)?;
    if deployment.version == 2 {
        use crate::mpp::protocol::solana::{validate_network, NETWORK_MAINNET};
        validate_network(network)?;
        if network == NETWORK_MAINNET {
            return Err(Error::InvalidConfig(
                "V2 channel deployment supports only devnet and localnet".into(),
            ));
        }
    }
    Ok(deployment)
}

pub(crate) fn resolve(
    program: Pubkey,
    version: Option<u8>,
    hooks: Option<&ChannelHooks>,
) -> Result<Deployment> {
    let deployment = Deployment::resolve(program, version)?;
    if deployment.version == 1 && hooks.is_some() {
        return Err(Error::InvalidConfig(
            "channelHooks requires the V2 channel deployment".into(),
        ));
    }
    if let Some(hooks) = hooks {
        hooks.validate()?;
    }
    Ok(deployment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn v2_network_support_is_explicit_without_changing_v1() {
        let v2 = Pubkey::from_str("CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ").unwrap();
        let v1 = crate::core::payment_channels::default_program_id();
        for network in ["devnet", "localnet"] {
            assert!(resolve_for_network(v2, Some(2), None, network).is_ok());
        }
        for network in ["mainnet", "", "testnet", "mainnet-beta", "Devnet"] {
            assert!(resolve_for_network(v2, Some(2), None, network).is_err());
            assert!(resolve_for_network(v1, None, None, network).is_ok());
        }
    }

    #[test]
    fn default_and_explicit_v1_are_equivalent() {
        let program = crate::core::payment_channels::default_program_id();
        assert_eq!(resolve(program, None, None).unwrap().version, 1);
        assert_eq!(resolve(program, Some(1), None).unwrap().version, 1);
        assert!(resolve(program, Some(2), None).is_err());
        assert!(resolve(program, Some(3), None).is_err());
        assert!(resolve(program, None, Some(&ChannelHooks::default())).is_err());
    }

    #[test]
    fn v2_requires_explicit_matching_abi() {
        let program = Pubkey::from_str("CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ").unwrap();
        assert!(resolve(program, None, None).is_err());
        assert!(resolve(program, Some(1), None).is_err());
        assert_eq!(resolve(program, Some(2), None).unwrap().version, 2);
        assert!(resolve(Pubkey::new_unique(), Some(2), None).is_err());
    }
}

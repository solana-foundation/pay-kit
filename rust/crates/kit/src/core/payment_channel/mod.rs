//! Versioned payment-channel ABIs and instruction builders.

pub mod v1;
pub mod v2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_module_paths_remain_compatible() {
        assert_eq!(
            crate::core::payment_channels::default_program_id(),
            v1::default_program_id()
        );
        let hooks: crate::core::payment_channels_v2::ChannelHooks = v2::ChannelHooks::default();
        assert!(hooks.is_empty());
    }
}

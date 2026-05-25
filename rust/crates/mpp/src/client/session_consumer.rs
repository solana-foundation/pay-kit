//! Kafka-style client helpers for metered session deliveries.
//!
//! `SessionConsumer` wraps [`ActiveSession`](super::session::ActiveSession) so
//! applications can process delivered messages and call `ack`/`commit` instead
//! of manually signing and posting vouchers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::protocol::intents::session::{
    CommitPayload, CommitReceipt, MeteredEnvelope, MeteringDirective,
};

use super::session::ActiveSession;

/// Transport used by [`SessionConsumer`] to send commit payloads.
///
/// HTTP clients, queues, and in-process tests can all implement this trait.
/// The directive is passed alongside the payload so transports can use
/// `commit_url`, `proof`, or other routing hints without those fields being
/// repeated in the signed commit body.
pub trait CommitTransport: Send + Sync {
    fn commit<'a>(
        &'a self,
        directive: &'a MeteringDirective,
        payload: CommitPayload,
    ) -> Pin<Box<dyn Future<Output = Result<CommitReceipt>> + Send + 'a>>;
}

impl<T: CommitTransport + ?Sized> CommitTransport for Arc<T> {
    fn commit<'a>(
        &'a self,
        directive: &'a MeteringDirective,
        payload: CommitPayload,
    ) -> Pin<Box<dyn Future<Output = Result<CommitReceipt>> + Send + 'a>> {
        self.as_ref().commit(directive, payload)
    }
}

/// Client-side consumer for session-metered deliveries.
pub struct SessionConsumer<T> {
    session: ActiveSession,
    transport: T,
}

impl<T: CommitTransport> SessionConsumer<T> {
    pub fn new(session: ActiveSession, transport: T) -> Self {
        Self { session, transport }
    }

    pub fn session(&self) -> &ActiveSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut ActiveSession {
        &mut self.session
    }

    /// Accept an envelope and return a delivery handle with `ack`/`commit`.
    pub fn accept<P>(&mut self, envelope: MeteredEnvelope<P>) -> Result<MeteredDelivery<'_, T, P>> {
        self.validate_directive(&envelope.metering)?;
        Ok(MeteredDelivery {
            consumer: self,
            payload: envelope.payload,
            metering: envelope.metering,
        })
    }

    /// Commit a directive directly, without constructing a delivery handle.
    pub async fn commit_directive(
        &mut self,
        directive: &MeteringDirective,
    ) -> Result<CommitReceipt> {
        self.validate_directive(directive)?;
        let amount = directive.amount_base_units()?;
        if amount == 0 {
            return Err(Error::Other(
                "metered delivery amount must be greater than zero".to_string(),
            ));
        }

        let voucher = self.session.prepare_increment(amount).await?;
        let payload = CommitPayload {
            delivery_id: directive.delivery_id.clone(),
            voucher,
        };

        let receipt = self.transport.commit(directive, payload.clone()).await?;
        self.session.record_voucher(&payload.voucher)?;
        Ok(receipt)
    }

    fn validate_directive(&self, directive: &MeteringDirective) -> Result<()> {
        let channel_id = self.session.channel_id_str();
        if directive.session_id != channel_id {
            return Err(Error::Other(format!(
                "metered delivery session {} does not match active session {channel_id}",
                directive.session_id
            )));
        }
        Ok(())
    }
}

/// A delivered payload plus its metering directive.
///
/// Call [`ack`](Self::ack) after the application has processed `payload`.
pub struct MeteredDelivery<'a, T: CommitTransport, P> {
    consumer: &'a mut SessionConsumer<T>,
    payload: P,
    metering: MeteringDirective,
}

impl<T: CommitTransport, P> MeteredDelivery<'_, T, P> {
    pub fn payload(&self) -> &P {
        &self.payload
    }

    pub fn metering(&self) -> &MeteringDirective {
        &self.metering
    }

    pub async fn ack(self) -> Result<CommitReceipt> {
        self.consumer.commit_directive(&self.metering).await
    }

    pub async fn commit(self) -> Result<CommitReceipt> {
        self.ack().await
    }

    pub fn into_parts(self) -> (P, MeteringDirective) {
        (self.payload, self.metering)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::intents::session::{CommitStatus, MeteredEnvelope};
    use solana_keychain::MemorySigner;
    use solana_pubkey::Pubkey;
    use std::sync::Mutex;

    struct RecordingTransport {
        commits: Mutex<Vec<CommitPayload>>,
        fail: bool,
    }

    impl CommitTransport for RecordingTransport {
        fn commit<'a>(
            &'a self,
            directive: &'a MeteringDirective,
            payload: CommitPayload,
        ) -> Pin<Box<dyn Future<Output = Result<CommitReceipt>> + Send + 'a>> {
            Box::pin(async move {
                if self.fail {
                    return Err(Error::Other("commit failed".to_string()));
                }
                let cumulative = payload.voucher.data.cumulative.clone();
                self.commits.lock().unwrap().push(payload);
                Ok(CommitReceipt {
                    delivery_id: directive.delivery_id.clone(),
                    session_id: directive.session_id.clone(),
                    amount: directive.amount.clone(),
                    cumulative,
                    status: CommitStatus::Committed,
                })
            })
        }
    }

    fn signer() -> Box<dyn solana_keychain::SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).unwrap())
    }

    fn directive(session_id: String, amount: u64) -> MeteringDirective {
        MeteringDirective {
            delivery_id: "d1".to_string(),
            session_id,
            amount: amount.to_string(),
            currency: "USDC".to_string(),
            sequence: 1,
            expires_at: crate::client::session::DEFAULT_VOUCHER_EXPIRES_AT,
            commit_url: None,
            proof: None,
        }
    }

    #[tokio::test]
    async fn ack_sends_commit_and_advances_local_watermark() {
        let channel_id = Pubkey::new_unique();
        let session = ActiveSession::new(channel_id, signer());
        let transport = RecordingTransport {
            commits: Mutex::new(vec![]),
            fail: false,
        };
        let mut consumer = SessionConsumer::new(session, transport);
        let envelope = MeteredEnvelope {
            payload: "work".to_string(),
            metering: directive(consumer.session().channel_id_str(), 250),
        };

        let delivery = consumer.accept(envelope).unwrap();
        assert_eq!(delivery.payload(), "work");
        let receipt = delivery.ack().await.unwrap();

        assert_eq!(receipt.cumulative, "250");
        assert_eq!(consumer.session().cumulative, 250);
        assert_eq!(consumer.transport.commits.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn commit_alias_sends_commit_and_delivery_exposes_parts() {
        let channel_id = Pubkey::new_unique();
        let session = ActiveSession::new(channel_id, signer());
        let transport = RecordingTransport {
            commits: Mutex::new(vec![]),
            fail: false,
        };
        let mut consumer = SessionConsumer::new(session, transport);
        consumer.session_mut().set_expires_at(1234);
        let envelope = MeteredEnvelope {
            payload: "payload".to_string(),
            metering: directive(consumer.session().channel_id_str(), 50),
        };

        let delivery = consumer.accept(envelope).unwrap();
        assert_eq!(delivery.metering().amount, "50");
        let receipt = delivery.commit().await.unwrap();
        assert_eq!(receipt.cumulative, "50");
        assert_eq!(
            consumer.transport.commits.lock().unwrap()[0]
                .voucher
                .data
                .expires_at,
            1234
        );

        let envelope = MeteredEnvelope {
            payload: "second".to_string(),
            metering: directive(consumer.session().channel_id_str(), 75),
        };
        let delivery = consumer.accept(envelope).unwrap();
        let (payload, metering) = delivery.into_parts();
        assert_eq!(payload, "second");
        assert_eq!(metering.amount, "75");
    }

    #[tokio::test]
    async fn arc_transport_impl_commits() {
        let channel_id = Pubkey::new_unique();
        let session = ActiveSession::new(channel_id, signer());
        let transport = std::sync::Arc::new(RecordingTransport {
            commits: Mutex::new(vec![]),
            fail: false,
        });
        let mut consumer = SessionConsumer::new(session, std::sync::Arc::clone(&transport));
        let directive = directive(consumer.session().channel_id_str(), 25);

        let receipt = consumer.commit_directive(&directive).await.unwrap();
        assert_eq!(receipt.cumulative, "25");
        assert_eq!(transport.commits.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_directives_are_rejected_before_commit() {
        let channel_id = Pubkey::new_unique();
        let session = ActiveSession::new(channel_id, signer());
        let transport = RecordingTransport {
            commits: Mutex::new(vec![]),
            fail: false,
        };
        let mut consumer = SessionConsumer::new(session, transport);

        let wrong_session = MeteredEnvelope {
            payload: (),
            metering: directive("other-session".to_string(), 1),
        };
        let err = match consumer.accept(wrong_session) {
            Ok(_) => panic!("expected wrong-session directive to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("does not match active session"));

        let zero = directive(consumer.session().channel_id_str(), 0);
        let err = consumer.commit_directive(&zero).await.unwrap_err();
        assert!(err.to_string().contains("greater than zero"));

        let mut invalid_amount = directive(consumer.session().channel_id_str(), 1);
        invalid_amount.amount = "bad".to_string();
        let err = consumer
            .commit_directive(&invalid_amount)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid metering amount"));
        assert_eq!(consumer.transport.commits.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn failed_commit_does_not_advance_local_watermark() {
        let channel_id = Pubkey::new_unique();
        let session = ActiveSession::new(channel_id, signer());
        let transport = RecordingTransport {
            commits: Mutex::new(vec![]),
            fail: true,
        };
        let mut consumer = SessionConsumer::new(session, transport);
        let directive = directive(consumer.session().channel_id_str(), 250);

        let err = consumer.commit_directive(&directive).await.unwrap_err();
        assert!(err.to_string().contains("commit failed"));
        assert_eq!(consumer.session().cumulative, 0);
    }
}

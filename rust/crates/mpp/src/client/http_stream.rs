//! HTTP streaming helpers for metered sessions.
//!
//! LLM APIs commonly stream responses over Server-Sent Events (SSE) or chunked
//! HTTP. This module keeps the parser transport-neutral, then layers a small
//! reqwest adapter on top for applications that want batteries included.

use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::protocol::intents::session::{
    CommitPayload, CommitReceipt, MeteringDirective, MeteringUsage,
};

use super::session_consumer::{CommitTransport, SessionConsumer};

/// A parsed Server-Sent Event frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub id: Option<String>,
    pub retry: Option<u64>,
}

#[derive(Default)]
struct PartialSseEvent {
    event: Option<String>,
    data: String,
    id: Option<String>,
    retry: Option<u64>,
}

/// Incremental SSE decoder.
///
/// Feed raw HTTP chunks with [`push_chunk`](Self::push_chunk). It returns all
/// complete events decoded from that chunk and retains partial data internally.
#[derive(Default)]
pub struct SseDecoder {
    buffer: String,
    current: PartialSseEvent,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>> {
        let text = std::str::from_utf8(chunk)
            .map_err(|e| Error::Other(format!("SSE chunk is not valid UTF-8: {e}")))?;
        self.buffer.push_str(text);

        let mut events = vec![];
        while let Some(index) = self.buffer.find('\n') {
            let mut line = self.buffer.drain(..=index).collect::<String>();
            if line.ends_with('\n') {
                line.pop();
            }
            if line.ends_with('\r') {
                line.pop();
            }
            if let Some(event) = self.process_line(&line)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    /// Flush an incomplete final event, if any, at EOF.
    pub fn finish(&mut self) -> Result<Vec<SseEvent>> {
        let mut events = vec![];
        if !self.buffer.is_empty() {
            let line = std::mem::take(&mut self.buffer);
            if let Some(event) = self.process_line(line.trim_end_matches('\r'))? {
                events.push(event);
            }
        }
        if let Some(event) = self.dispatch_current() {
            events.push(event);
        }
        Ok(events)
    }

    fn process_line(&mut self, line: &str) -> Result<Option<SseEvent>> {
        if line.is_empty() {
            return Ok(self.dispatch_current());
        }
        if line.starts_with(':') {
            return Ok(None);
        }

        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };

        match field {
            "event" => self.current.event = Some(value.to_string()),
            "data" => {
                if !self.current.data.is_empty() {
                    self.current.data.push('\n');
                }
                self.current.data.push_str(value);
            }
            "id" => self.current.id = Some(value.to_string()),
            "retry" => {
                self.current.retry = value.parse().ok();
            }
            _ => {}
        }
        Ok(None)
    }

    fn dispatch_current(&mut self) -> Option<SseEvent> {
        if self.current.event.is_none()
            && self.current.data.is_empty()
            && self.current.id.is_none()
            && self.current.retry.is_none()
        {
            return None;
        }

        let current = std::mem::take(&mut self.current);
        Some(SseEvent {
            event: current.event,
            data: current.data,
            id: current.id,
            retry: current.retry,
        })
    }
}

/// Parsed metered SSE event.
#[derive(Debug, Clone, PartialEq)]
pub enum MeteredSseEvent<T> {
    Metering(MeteringDirective),
    Usage(MeteringUsage),
    Message(T),
    Done,
    Other(SseEvent),
}

pub fn parse_metered_sse_event<T: DeserializeOwned>(event: SseEvent) -> Result<MeteredSseEvent<T>> {
    let event_name = event.event.as_deref().unwrap_or("message");
    match event_name {
        "mpp.metering" | "metering" => {
            let directive = serde_json::from_str(&event.data)
                .map_err(|e| Error::Other(format!("invalid mpp.metering event: {e}")))?;
            Ok(MeteredSseEvent::Metering(directive))
        }
        "mpp.usage" | "usage" => {
            let usage = serde_json::from_str(&event.data)
                .map_err(|e| Error::Other(format!("invalid mpp.usage event: {e}")))?;
            Ok(MeteredSseEvent::Usage(usage))
        }
        "done" => Ok(MeteredSseEvent::Done),
        "message" if event.data.trim() == "[DONE]" => Ok(MeteredSseEvent::Done),
        "message" => {
            let message = serde_json::from_str(&event.data)
                .map_err(|e| Error::Other(format!("invalid SSE message event: {e}")))?;
            Ok(MeteredSseEvent::Message(message))
        }
        _ => Ok(MeteredSseEvent::Other(event)),
    }
}

#[derive(Default)]
struct MeteredStreamState {
    directive: Option<MeteringDirective>,
    final_amount: Option<u64>,
    done: bool,
}

impl MeteredStreamState {
    fn apply_event<T: DeserializeOwned>(&mut self, event: SseEvent) -> Result<Option<T>> {
        match parse_metered_sse_event(event)? {
            MeteredSseEvent::Metering(directive) => {
                self.directive = Some(directive);
                Ok(None)
            }
            MeteredSseEvent::Usage(usage) => {
                if let Some(ref directive) = self.directive {
                    if usage.delivery_id != directive.delivery_id {
                        return Err(Error::Other(format!(
                            "usage delivery {} does not match directive {}",
                            usage.delivery_id, directive.delivery_id
                        )));
                    }
                }
                self.final_amount = Some(usage.amount_base_units()?);
                Ok(None)
            }
            MeteredSseEvent::Message(message) => Ok(Some(message)),
            MeteredSseEvent::Done => {
                self.done = true;
                Ok(None)
            }
            MeteredSseEvent::Other(_) => Ok(None),
        }
    }

    fn directive_for_commit(&self) -> Result<MeteringDirective> {
        let mut directive = self
            .directive
            .clone()
            .ok_or_else(|| Error::Other("stream did not include mpp.metering event".to_string()))?;
        if let Some(amount) = self.final_amount {
            directive.amount = amount.to_string();
        }
        Ok(directive)
    }
}

/// Borrowed state machine for a metered SSE stream.
pub struct MeteredSseSession<'a, C: CommitTransport, T> {
    consumer: &'a mut SessionConsumer<C>,
    state: MeteredStreamState,
    _marker: PhantomData<T>,
}

impl<C: CommitTransport> SessionConsumer<C> {
    pub fn metered_sse<T>(&mut self) -> MeteredSseSession<'_, C, T> {
        MeteredSseSession {
            consumer: self,
            state: MeteredStreamState::default(),
            _marker: PhantomData,
        }
    }
}

impl<C: CommitTransport, T: DeserializeOwned> MeteredSseSession<'_, C, T> {
    pub fn accept_event(&mut self, event: SseEvent) -> Result<Option<T>> {
        self.state.apply_event(event)
    }

    pub fn is_done(&self) -> bool {
        self.state.done
    }

    pub async fn ack(self) -> Result<CommitReceipt> {
        let directive = self.state.directive_for_commit()?;
        self.consumer.commit_directive(&directive).await
    }
}

/// Minimal HTTP transport for commit endpoints.
#[derive(Clone)]
pub struct HttpCommitTransport {
    client: reqwest::Client,
    default_commit_url: Option<String>,
    authorization: Option<String>,
}

impl HttpCommitTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            default_commit_url: None,
            authorization: None,
        }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            client,
            default_commit_url: None,
            authorization: None,
        }
    }

    pub fn with_default_commit_url(mut self, url: impl Into<String>) -> Self {
        self.default_commit_url = Some(url.into());
        self
    }

    pub fn with_authorization(mut self, value: impl Into<String>) -> Self {
        self.authorization = Some(value.into());
        self
    }
}

impl Default for HttpCommitTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitTransport for HttpCommitTransport {
    fn commit<'a>(
        &'a self,
        directive: &'a MeteringDirective,
        payload: CommitPayload,
    ) -> Pin<Box<dyn Future<Output = Result<CommitReceipt>> + Send + 'a>> {
        Box::pin(async move {
            let url = directive
                .commit_url
                .as_ref()
                .or(self.default_commit_url.as_ref())
                .ok_or_else(|| Error::Other("metering directive missing commitUrl".to_string()))?;

            let mut request = self.client.post(url).json(&payload);
            if let Some(auth) = &self.authorization {
                request = request.header(reqwest::header::AUTHORIZATION, auth);
            }

            let response = request
                .send()
                .await
                .map_err(|e| Error::Other(format!("commit request failed: {e}")))?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(Error::Other(format!(
                    "commit endpoint returned {status}: {body}"
                )));
            }

            response
                .json::<CommitReceipt>()
                .await
                .map_err(|e| Error::Other(format!("invalid commit receipt: {e}")))
        })
    }
}

/// Reqwest-backed metered SSE stream.
pub struct ReqwestMeteredSseStream<C: CommitTransport, T> {
    consumer: SessionConsumer<C>,
    response: reqwest::Response,
    decoder: SseDecoder,
    pending: VecDeque<T>,
    state: MeteredStreamState,
}

impl<C: CommitTransport, T: DeserializeOwned> ReqwestMeteredSseStream<C, T> {
    pub fn new(consumer: SessionConsumer<C>, response: reqwest::Response) -> Self {
        Self {
            consumer,
            response,
            decoder: SseDecoder::new(),
            pending: VecDeque::new(),
            state: MeteredStreamState::default(),
        }
    }

    pub async fn next(&mut self) -> Result<Option<T>> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                return Ok(Some(message));
            }
            if self.state.done {
                return Ok(None);
            }

            match self
                .response
                .chunk()
                .await
                .map_err(|e| Error::Other(format!("stream read failed: {e}")))?
            {
                Some(chunk) => {
                    for event in self.decoder.push_chunk(chunk.as_ref())? {
                        if let Some(message) = self.state.apply_event(event)? {
                            self.pending.push_back(message);
                        }
                    }
                }
                None => {
                    for event in self.decoder.finish()? {
                        if let Some(message) = self.state.apply_event(event)? {
                            self.pending.push_back(message);
                        }
                    }
                    self.state.done = true;
                }
            }
        }
    }

    pub async fn ack(mut self) -> Result<CommitReceipt> {
        if !self.state.done {
            while self.next().await?.is_some() {}
        }
        let directive = self.state.directive_for_commit()?;
        self.consumer.commit_directive(&directive).await
    }

    pub fn into_consumer(self) -> SessionConsumer<C> {
        self.consumer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::intents::session::CommitStatus;
    use crate::solana_keychain::MemorySigner;
    use axum::extract::State;
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use solana_pubkey::Pubkey;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Delta {
        delta: String,
    }

    struct RecordingTransport {
        commits: Mutex<Vec<CommitPayload>>,
    }

    impl CommitTransport for RecordingTransport {
        fn commit<'a>(
            &'a self,
            directive: &'a MeteringDirective,
            payload: CommitPayload,
        ) -> Pin<Box<dyn Future<Output = Result<CommitReceipt>> + Send + 'a>> {
            Box::pin(async move {
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

    fn signer() -> Box<dyn crate::solana_keychain::SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).unwrap())
    }

    fn directive(session_id: &str) -> MeteringDirective {
        MeteringDirective {
            delivery_id: "stream-1".to_string(),
            session_id: session_id.to_string(),
            amount: "1000".to_string(),
            currency: "USDC".to_string(),
            sequence: 1,
            expires_at: crate::client::session::DEFAULT_VOUCHER_EXPIRES_AT,
            commit_url: None,
            proof: None,
        }
    }

    fn sse_event(event: Option<&str>, data: impl Into<String>) -> SseEvent {
        SseEvent {
            event: event.map(str::to_string),
            data: data.into(),
            id: None,
            retry: None,
        }
    }

    async fn spawn_app(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[derive(Clone, Default)]
    struct CommitServerState {
        commits: Arc<Mutex<Vec<CommitPayload>>>,
    }

    async fn commit_handler(
        State(state): State<CommitServerState>,
        headers: HeaderMap,
        Json(payload): Json<CommitPayload>,
    ) -> Response {
        if headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            != Some("Bearer sdk-test")
        {
            return (StatusCode::UNAUTHORIZED, "missing auth").into_response();
        }

        let receipt = CommitReceipt {
            delivery_id: payload.delivery_id.clone(),
            session_id: payload.voucher.data.channel_id.clone(),
            amount: payload.voucher.data.cumulative.clone(),
            cumulative: payload.voucher.data.cumulative.clone(),
            status: CommitStatus::Committed,
        };
        state.commits.lock().unwrap().push(payload);
        Json(receipt).into_response()
    }

    #[test]
    fn sse_decoder_handles_split_chunks() {
        let mut decoder = SseDecoder::new();
        assert!(decoder
            .push_chunk(b"event: message\ndata: {\"delta\"")
            .unwrap()
            .is_empty());
        let events = decoder
            .push_chunk(b":\"hi\"}\n\n")
            .expect("second chunk dispatches");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event.as_deref(), Some("message"));
        assert_eq!(events[0].data, r#"{"delta":"hi"}"#);
    }

    #[test]
    fn sse_decoder_handles_metadata_crlf_comments_and_finish() {
        let mut decoder = SseDecoder::new();
        let events = decoder
            .push_chunk(
                b": keepalive\r\nid: evt-1\r\nretry: 250\r\ndata: hello\r\ndata: world\r\n\r\n",
            )
            .unwrap();
        assert_eq!(
            events,
            vec![SseEvent {
                event: None,
                data: "hello\nworld".to_string(),
                id: Some("evt-1".to_string()),
                retry: Some(250),
            }]
        );

        assert!(decoder
            .push_chunk(b"retry: nope\nunknown\n\n")
            .unwrap()
            .is_empty());
        assert!(decoder
            .push_chunk(b"event: message\ndata: tail")
            .unwrap()
            .is_empty());
        let events = decoder.finish().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event.as_deref(), Some("message"));
        assert_eq!(events[0].data, "tail");
    }

    #[test]
    fn sse_decoder_rejects_invalid_utf8() {
        let err = SseDecoder::new().push_chunk(&[0xff]).unwrap_err();
        assert!(err.to_string().contains("valid UTF-8"));
    }

    #[test]
    fn parse_metered_sse_events() {
        let metering = SseEvent {
            event: Some("mpp.metering".to_string()),
            data: serde_json::to_string(&directive("chan")).unwrap(),
            id: None,
            retry: None,
        };
        match parse_metered_sse_event::<Delta>(metering).unwrap() {
            MeteredSseEvent::Metering(directive) => assert_eq!(directive.amount, "1000"),
            _ => panic!("expected metering"),
        }

        let message = SseEvent {
            event: Some("message".to_string()),
            data: r#"{"delta":"hello"}"#.to_string(),
            id: None,
            retry: None,
        };
        match parse_metered_sse_event::<Delta>(message).unwrap() {
            MeteredSseEvent::Message(delta) => assert_eq!(delta.delta, "hello"),
            _ => panic!("expected message"),
        }
    }

    #[test]
    fn parse_metered_sse_usage_done_other_and_errors() {
        match parse_metered_sse_event::<Delta>(sse_event(
            Some("mpp.usage"),
            r#"{"deliveryId":"stream-1","amount":"17"}"#,
        ))
        .unwrap()
        {
            MeteredSseEvent::Usage(usage) => assert_eq!(usage.amount_base_units().unwrap(), 17),
            _ => panic!("expected usage"),
        }

        assert!(matches!(
            parse_metered_sse_event::<Delta>(sse_event(Some("done"), "")).unwrap(),
            MeteredSseEvent::Done
        ));
        assert!(matches!(
            parse_metered_sse_event::<Delta>(sse_event(None, " [DONE] ")).unwrap(),
            MeteredSseEvent::Done
        ));
        assert!(matches!(
            parse_metered_sse_event::<Delta>(sse_event(Some("trace"), "ignored")).unwrap(),
            MeteredSseEvent::Other(_)
        ));

        assert!(parse_metered_sse_event::<Delta>(sse_event(Some("metering"), "{")).is_err());
        assert!(parse_metered_sse_event::<Delta>(sse_event(Some("usage"), "{")).is_err());
        assert!(parse_metered_sse_event::<Delta>(sse_event(None, "{")).is_err());
    }

    #[tokio::test]
    async fn metered_sse_ack_uses_final_usage_amount() {
        let channel_id = Pubkey::new_unique();
        let session = super::super::session::ActiveSession::new(channel_id, signer());
        let transport = RecordingTransport {
            commits: Mutex::new(vec![]),
        };
        let mut consumer = SessionConsumer::new(session, transport);
        let mut stream = consumer.metered_sse::<Delta>();
        let directive = directive(&stream.consumer.session().channel_id_str());

        assert!(stream
            .accept_event(SseEvent {
                event: Some("mpp.metering".to_string()),
                data: serde_json::to_string(&directive).unwrap(),
                id: None,
                retry: None,
            })
            .unwrap()
            .is_none());
        let delta = stream
            .accept_event(SseEvent {
                event: Some("message".to_string()),
                data: r#"{"delta":"hello"}"#.to_string(),
                id: None,
                retry: None,
            })
            .unwrap()
            .unwrap();
        assert_eq!(delta.delta, "hello");
        stream
            .accept_event(SseEvent {
                event: Some("mpp.usage".to_string()),
                data: r#"{"deliveryId":"stream-1","amount":"425"}"#.to_string(),
                id: None,
                retry: None,
            })
            .unwrap();

        let receipt = stream.ack().await.unwrap();
        assert_eq!(receipt.amount, "425");
        assert_eq!(receipt.cumulative, "425");
        assert_eq!(consumer.session().cumulative, 425);
    }

    #[tokio::test]
    async fn metered_sse_ack_uses_reserved_amount_without_usage_and_tracks_done() {
        let channel_id = Pubkey::new_unique();
        let session = super::super::session::ActiveSession::new(channel_id, signer());
        let transport = RecordingTransport {
            commits: Mutex::new(vec![]),
        };
        let mut consumer = SessionConsumer::new(session, transport);
        let mut stream = consumer.metered_sse::<Delta>();
        let directive = directive(&stream.consumer.session().channel_id_str());

        stream
            .accept_event(sse_event(
                Some("mpp.metering"),
                serde_json::to_string(&directive).unwrap(),
            ))
            .unwrap();
        stream.accept_event(sse_event(Some("done"), "")).unwrap();
        assert!(stream.is_done());

        let receipt = stream.ack().await.unwrap();
        assert_eq!(receipt.amount, "1000");
        assert_eq!(receipt.cumulative, "1000");
    }

    #[tokio::test]
    async fn metered_sse_reports_missing_metering_and_usage_mismatch() {
        let channel_id = Pubkey::new_unique();
        let session = super::super::session::ActiveSession::new(channel_id, signer());
        let transport = RecordingTransport {
            commits: Mutex::new(vec![]),
        };
        let mut consumer = SessionConsumer::new(session, transport);
        let stream = consumer.metered_sse::<Delta>();
        let err = stream.ack().await.unwrap_err();
        assert!(err.to_string().contains("mpp.metering"));

        let mut stream = consumer.metered_sse::<Delta>();
        let directive = directive(&stream.consumer.session().channel_id_str());
        stream
            .accept_event(sse_event(
                Some("mpp.metering"),
                serde_json::to_string(&directive).unwrap(),
            ))
            .unwrap();
        let err = stream
            .accept_event(sse_event(
                Some("mpp.usage"),
                r#"{"deliveryId":"other","amount":"1"}"#,
            ))
            .unwrap_err();
        assert!(err.to_string().contains("does not match directive"));
    }

    #[tokio::test]
    async fn http_commit_transport_success_and_errors() {
        let state = CommitServerState::default();
        let app = Router::new()
            .route("/commit", post(commit_handler))
            .route(
                "/commit-error",
                post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "commit failed") }),
            )
            .route("/commit-invalid-json", post(|| async { "not json" }))
            .with_state(state.clone());
        let base_url = spawn_app(app).await;

        let channel_id = Pubkey::new_unique();
        let session = super::super::session::ActiveSession::new(channel_id, signer());
        let directive = directive(&session.channel_id_str());
        let voucher = session.prepare_increment(88).await.unwrap();
        let payload = CommitPayload {
            delivery_id: directive.delivery_id.clone(),
            voucher,
        };

        let transport = HttpCommitTransport::with_client(reqwest::Client::new())
            .with_default_commit_url(format!("{base_url}/commit"))
            .with_authorization("Bearer sdk-test");
        let receipt = transport.commit(&directive, payload.clone()).await.unwrap();
        assert_eq!(receipt.cumulative, "88");
        assert_eq!(state.commits.lock().unwrap().len(), 1);

        let missing_url = HttpCommitTransport::new()
            .commit(&directive, payload.clone())
            .await
            .unwrap_err();
        assert!(missing_url.to_string().contains("missing commitUrl"));

        let server_error = HttpCommitTransport::new()
            .with_default_commit_url(format!("{base_url}/commit-error"))
            .commit(&directive, payload.clone())
            .await
            .unwrap_err();
        assert!(server_error.to_string().contains("500"));

        let invalid_json = HttpCommitTransport::new()
            .with_default_commit_url(format!("{base_url}/commit-invalid-json"))
            .commit(&directive, payload)
            .await
            .unwrap_err();
        assert!(invalid_json.to_string().contains("invalid commit receipt"));
    }

    #[tokio::test]
    async fn reqwest_metered_sse_stream_reads_messages_and_ack_drains() {
        let state = CommitServerState::default();
        let channel_id = Pubkey::new_unique();
        let session = super::super::session::ActiveSession::new(channel_id, signer());
        let directive = directive(&session.channel_id_str());
        let stream_body = Arc::new(format!(
            "event: mpp.metering\ndata: {}\n\n\
             event: message\ndata: {{\"delta\":\"first\"}}\n\n\
             event: message\ndata: {{\"delta\":\"second\"}}\n\n\
             event: mpp.usage\ndata: {{\"deliveryId\":\"stream-1\",\"amount\":\"275\"}}\n\n\
             data: [DONE]",
            serde_json::to_string(&directive).unwrap()
        ));
        let body_for_route = Arc::clone(&stream_body);
        let app = Router::new()
            .route("/commit", post(commit_handler))
            .route(
                "/stream",
                get(move || {
                    let body = Arc::clone(&body_for_route);
                    async move {
                        (
                            [(header::CONTENT_TYPE, "text/event-stream")],
                            (*body).clone(),
                        )
                    }
                }),
            )
            .with_state(state.clone());
        let base_url = spawn_app(app).await;

        let transport = HttpCommitTransport::new()
            .with_default_commit_url(format!("{base_url}/commit"))
            .with_authorization("Bearer sdk-test");
        let consumer = SessionConsumer::new(session, transport);
        let response = reqwest::Client::new()
            .get(format!("{base_url}/stream"))
            .send()
            .await
            .unwrap();
        let mut stream = ReqwestMeteredSseStream::<_, Delta>::new(consumer, response);

        assert_eq!(stream.next().await.unwrap().unwrap().delta, "first");
        let receipt = stream.ack().await.unwrap();
        assert_eq!(receipt.amount, "275");
        assert_eq!(receipt.cumulative, "275");
        assert_eq!(state.commits.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn reqwest_metered_sse_stream_can_return_consumer() {
        let channel_id = Pubkey::new_unique();
        let session = super::super::session::ActiveSession::new(channel_id, signer());
        let app = Router::new().route(
            "/stream",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/event-stream")],
                    "data: [DONE]\n\n",
                )
            }),
        );
        let base_url = spawn_app(app).await;
        let response = reqwest::Client::new()
            .get(format!("{base_url}/stream"))
            .send()
            .await
            .unwrap();
        let consumer = SessionConsumer::new(
            session,
            RecordingTransport {
                commits: Mutex::new(vec![]),
            },
        );
        let stream = ReqwestMeteredSseStream::<_, Delta>::new(consumer, response);
        let consumer = stream.into_consumer();
        assert_eq!(consumer.session().cumulative, 0);
    }
}

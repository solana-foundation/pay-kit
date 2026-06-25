//! Reusable OpenTelemetry wiring (feature `otel`), shared by the pay-kit crates
//! and the pay binaries so spans + metrics from every layer (client → proxy →
//! settlement worker) land in one collector under one trace.
//!
//! [`init`] installs a console layer plus, when an OTLP endpoint is supplied,
//! span + metric exporters and the W3C trace-context propagator. Hold the
//! returned [`Guard`] for the process lifetime so the batch exporters flush on
//! exit. Mirrors (and is meant to replace) the bespoke setups in pay's
//! `bench/observability.rs` and `cli/observability.rs`.

use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
use opentelemetry_semantic_conventions::SCHEMA_URL;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Telemetry configuration. Filter fields are `EnvFilter` directive strings
/// (e.g. `"info,hyper=warn"`).
pub struct OtelOptions<'a> {
    pub service_name: &'a str,
    pub service_version: &'a str,
    /// OTLP collector base (`host:port` or full URL). `None` ⇒ console only.
    pub otlp_endpoint: Option<&'a str>,
    /// Console (fmt) layer filter.
    pub console_filter: &'a str,
    /// OTLP export filter (spans + metrics).
    pub trace_filter: &'a str,
}

/// Holds the OTLP providers alive for the process; flushes them on drop. Each
/// is independent — a provider whose endpoint failed to initialize is simply
/// `None`, so the others still export.
#[derive(Default)]
pub struct Guard {
    tracer: Option<SdkTracerProvider>,
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(tracer) = &self.tracer {
            let _ = tracer.force_flush();
            if let Err(e) = tracer.shutdown() {
                eprintln!("OTLP trace shutdown failed: {e:?}");
            }
        }
        if let Some(logger) = &self.logger {
            let _ = logger.force_flush();
            if let Err(e) = logger.shutdown() {
                eprintln!("OTLP log shutdown failed: {e:?}");
            }
        }
        if let Some(meter) = &self.meter {
            if let Err(e) = meter.shutdown() {
                eprintln!("OTLP metric shutdown failed: {e:?}");
            }
        }
    }
}

/// Initialize telemetry. With `otlp_endpoint` set, spans + metrics export to
/// that OTLP collector in addition to the console; otherwise only the console
/// layer is installed. Installs the W3C trace-context propagator either way.
pub fn init(opts: OtelOptions<'_>) -> Guard {
    global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());

    let Some(sidecar) = opts.otlp_endpoint else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(opts.console_filter))
            .with_target(false)
            .with_thread_names(true)
            .try_init();
        return Guard::default();
    };

    let base = normalize_base(sidecar);

    // Initialize each signal independently: a collector endpoint being down for
    // one (e.g. metrics) must not silence the others. A failed provider is left
    // `None` and its layer omitted; the console layer is always installed.
    let tracer_provider = tracer_provider(&format!("{base}/v1/traces"), resource(&opts))
        .inspect_err(|e| eprintln!("OTLP trace init failed ({e}); traces disabled"))
        .ok();
    let meter_provider = meter_provider(&format!("{base}/v1/metrics"), resource(&opts))
        .inspect_err(|e| eprintln!("OTLP metric init failed ({e}); metrics disabled"))
        .ok();
    let logger_provider = logger_provider(&format!("{base}/v1/logs"), resource(&opts))
        .inspect_err(|e| eprintln!("OTLP log init failed ({e}); OTLP logs disabled"))
        .ok();

    let trace_layer = tracer_provider.as_ref().map(|tp| {
        OpenTelemetryLayer::new(tp.tracer(opts.service_name.to_string()))
            .with_filter(EnvFilter::new(opts.trace_filter))
    });
    let metrics_layer = meter_provider
        .as_ref()
        .map(|mp| MetricsLayer::new(mp.clone()).with_filter(EnvFilter::new(opts.trace_filter)));
    // Bridge `tracing` events → OTel logs (→ Loki), correlated to the active
    // span's trace_id.
    let logs_layer = logger_provider.as_ref().map(|lp| {
        OpenTelemetryTracingBridge::new(lp).with_filter(EnvFilter::new(opts.trace_filter))
    });

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_thread_names(true)
                .with_filter(EnvFilter::new(opts.console_filter)),
        )
        .with(trace_layer)
        .with(metrics_layer)
        .with(logs_layer)
        .try_init();

    tracing::info!(
        endpoint = %base,
        service = %opts.service_name,
        traces = tracer_provider.is_some(),
        metrics = meter_provider.is_some(),
        logs = logger_provider.is_some(),
        "OTLP export configured",
    );

    Guard {
        tracer: tracer_provider,
        meter: meter_provider,
        logger: logger_provider,
    }
}

fn resource(opts: &OtelOptions<'_>) -> Resource {
    Resource::builder()
        .with_service_name(opts.service_name.to_string())
        .with_schema_url(
            [KeyValue::new(
                SERVICE_VERSION,
                opts.service_version.to_string(),
            )],
            SCHEMA_URL,
        )
        .build()
}

fn normalize_base(sidecar: &str) -> String {
    let t = sidecar.trim().trim_end_matches('/');
    if t.contains("://") {
        t.to_string()
    } else {
        format!("http://{t}")
    }
}

fn tracer_provider(endpoint: &str, resource: Resource) -> Result<SdkTracerProvider, String> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint.to_string())
        .build()
        .map_err(|e| format!("OTLP span exporter: {e}"))?;
    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            1.0,
        ))))
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();
    global::set_tracer_provider(provider.clone());
    Ok(provider)
}

fn logger_provider(endpoint: &str, resource: Resource) -> Result<SdkLoggerProvider, String> {
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint.to_string())
        .build()
        .map_err(|e| format!("OTLP log exporter: {e}"))?;
    Ok(SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

fn meter_provider(endpoint: &str, resource: Resource) -> Result<SdkMeterProvider, String> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint.to_string())
        .build()
        .map_err(|e| format!("OTLP metric exporter: {e}"))?;
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(15))
        .build();
    let provider = MeterProviderBuilder::default()
        .with_resource(resource)
        .with_reader(reader)
        .build();
    global::set_meter_provider(provider.clone());
    Ok(provider)
}

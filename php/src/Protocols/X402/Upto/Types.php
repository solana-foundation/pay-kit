<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402\Upto;

/**
 * x402 `upto` scheme constants and wire-shape documentation.
 *
 * Field names and amount/timestamp encodings mirror the Rust spine
 * (`protocol/schemes/upto/types.rs`), Go (`go/protocols/x402/upto.go`), and
 * Python (`protocols/x402/upto/types.py`) field-for-field: camelCase JSON
 * keys, amounts as base-10 u64 strings, timestamps as Unix seconds.
 *
 * PHP uses associative arrays at the wire boundary (same as Exact); this
 * class only holds constants so every language SDK shares identical strings.
 */
final class Types
{
    /** The x402 scheme identifier for usage-based `upto` authorizations. */
    public const SCHEME = 'upto';

    /** Default forced-close delay, in seconds, for SVM payment channels. */
    public const DEFAULT_WITHDRAW_DELAY_SECONDS = 900;

    /**
     * Settlement error when the metered actual exceeds the signed ceiling.
     * Identical string to Rust/Go/Python for cross-language error parity.
     */
    public const ERROR_SETTLEMENT_EXCEEDS_AMOUNT = 'invalid_upto_svm_payload_settlement_exceeds_amount';

    /** x402 protocol version this server emits for upto challenges. */
    public const X402_VERSION = 2;

    /** Default authorization window (seconds). */
    public const DEFAULT_MAX_TIMEOUT_SECONDS = 300;

    private function __construct()
    {
    }
}

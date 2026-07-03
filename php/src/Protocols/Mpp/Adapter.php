<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp;

use PayKit\Config;
use PayKit\Exception\ConfigurationException;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\PayCore\Network;
use PayKit\Payment;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\ChargeSettlement;
use PayKit\Protocols\Mpp\Server\PaymentRequiredResponse;
use PayKit\Protocols\Mpp\Server\SolanaChargeHandler;
use PayKit\Store\MemoryStore;
use PayKit\Store\Store;
use Psr\Http\Message\ServerRequestInterface;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Rpc\RpcClient;

/**
 * Umbrella adapter that wraps the protocol-level
 * {@see SolanaChargeHandler} behind the PayKit adapter contract.
 *
 *   - detect(headers): does the request carry an MPP credential
 *   - acceptsEntry(gate, request): one entry in the 402 accepts[]
 *   - challengeHeaders(gate, request): headers for the 402 response
 *   - verifyAndSettle(gate, request): returns a Payment, or raises
 *     InvalidProofException with the canonical error string.
 */
final class Adapter
{
    /** @var array<string,array{ChargeServer, SolanaChargeHandler}> */
    private array $handlerCache = [];

    private readonly Store $replayStore;

    /**
     * @param ?Store $replayStore Replay-protection store shared across every
     *        {@see SolanaChargeHandler} this adapter builds. When null (the
     *        default) an in-process {@see MemoryStore} is used. The in-memory
     *        store is single-process, so a second replica or a restart would
     *        accept a replayed signature; off localnet the adapter therefore
     *        fails closed unless the operator injects a shared atomic store
     *        (Redis, Postgres) or opts into single-process scope with
     *        `PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1`. Mirrors the TS
     *        `resolveReplayStore` guard in pay-kit config.
     */
    public function __construct(
        private readonly Config $config,
        ?Store $replayStore = null,
    ) {
        $this->replayStore = $replayStore ?? self::defaultReplayStore($config->network);
    }

    /**
     * Resolve the fallback replay store when the caller passed none.
     *
     * The in-memory default is only safe on localnet (single-process dev). Off
     * localnet it is a replay hole: markers are process-local, so a restart or a
     * second worker/replica would accept a replayed payment. Fail closed unless
     * `PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1` explicitly acknowledges the
     * single-process scope, matching the TS reference guard.
     */
    private static function defaultReplayStore(Network $network): Store
    {
        $allowInMemory = getenv('PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE') === '1';
        if ($network !== Network::SolanaLocalnet && !$allowInMemory) {
            throw new ConfigurationException(
                'pay_kit: a shared replay store is required outside localnet. The default in-memory '
                . 'store is process-local, so a second replica or a restart would accept a replayed '
                . 'payment. Inject a shared, persistent Store (ideally one with an atomic reserve, '
                . 'e.g. Redis SET NX) into the mpp adapter, or set '
                . 'PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 to acknowledge single-process replay scope.',
            );
        }
        if ($network !== Network::SolanaLocalnet && function_exists('error_log')) {
            error_log(
                'pay_kit: WARN: mpp adapter using in-memory replay store off localnet '
                . '(PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1). Replay protection is process-local and '
                . 'does not survive restarts or span replicas.',
            );
        }

        return new MemoryStore();
    }

    public function acceptsEntry(Gate $gate, ServerRequestInterface $request): array
    {
        $coin  = $this->settlementCoin($gate);
        $payTo = $gate->payTo ?? $this->config->effectiveRecipient();
        $entry = [
            'protocol' => 'mpp',
            'scheme'   => 'charge',
            'network'  => $this->config->network->caip2(),
            'amount'   => (string) $this->totalUnits($gate),
            'currency' => $coin,
            'payTo'    => $payTo,
            'realm'    => $this->config->mpp->resolveRealm($payTo),
        ];
        if ($gate->hasFees()) {
            $splits = [];
            foreach ($gate->fees as $f) {
                $splits[] = [
                    'recipient' => $f->recipient,
                    'amount'    => (string) $this->priceUnits($f->price),
                ];
            }
            $entry['splits'] = $splits;
        }
        return $entry;
    }

    /**
     * @return array<string,string>
     */
    public function challengeHeaders(Gate $gate, ServerRequestInterface $request): array
    {
        [$charges, $_handler] = $this->serverFor($gate);
        $chargeRequest = $this->chargeRequestFor($gate);
        $header = $charges->createChallengeHeader($chargeRequest, $this->challengeExpires());
        return ['www-authenticate' => $header];
    }

    /**
     * RFC 3339 `expires` timestamp threaded into issued charge challenges.
     *
     * Derived from {@see MppConfig::$expiresIn}: `now + expiresIn` seconds,
     * UTC. `expiresIn = 0` is the documented dev-only opt-out and yields an
     * empty string, leaving the challenge with no expiry (never expires).
     * Without this wiring `createChallengeHeader` defaulted to `''`, so
     * signed challenges were valid indefinitely (main-audit finding 7).
     */
    private function challengeExpires(): string
    {
        $expiresIn = $this->config->mpp->expiresIn;
        if ($expiresIn <= 0) {
            return '';
        }
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        return $now->add(new \DateInterval('PT' . $expiresIn . 'S'))->format('Y-m-d\TH:i:s\Z');
    }

    public function verifyAndSettle(Gate $gate, ServerRequestInterface $request): Payment
    {
        $authorization = $request->getHeaderLine('Authorization');
        if ($authorization === '') {
            throw new InvalidProofException('pay_kit: payment required');
        }

        [$_charges, $handler] = $this->serverFor($gate);
        $chargeRequest = $this->chargeRequestFor($gate);
        $result = $handler->handle($authorization, $chargeRequest);

        if ($result instanceof PaymentRequiredResponse) {
            throw new InvalidProofException(
                'pay_kit: ' . ($result->body['error'] ?? 'payment_invalid'),
            );
        }

        return new Payment(
            protocol: Protocol::Mpp,
            transaction: (string) ($result->body['signature'] ?? ''),
            gateName: null,
            settlementHeaders: $result->headers,
            raw: $authorization,
        );
    }

    private function chargeRequestFor(Gate $gate): ChargeRequest
    {
        $coin  = $this->settlementCoin($gate);
        $payTo = $gate->payTo ?? $this->config->effectiveRecipient();
        // Charge the gate total (base + any fee-on-top), matching the amount
        // advertised in acceptsEntry. The MPP wire derives the primary
        // recipient share as amount - sum(splits), so pinning the bare base
        // here while advertising the total would let the verifier accept a
        // payment short by the on-top fee. fee-within gates are unaffected
        // (total == base).
        $amount = (string) $this->totalUnits($gate);
        // Pay's MPP client reads request.methodDetails.network as the
        // short network slug ("mainnet" / "devnet" / "localnet") when
        // filtering challenges by active wallet
        // (rust/crates/core/src/client/mpp.rs:83). Advertise the same
        // slug `Mints::resolve` uses so `pay --sandbox --mpp curl`
        // matches against its sandbox network.
        $methodDetails = ['network' => $this->config->network->mintsLabel()];
        if ($gate->hasFees()) {
            $splits = [];
            foreach ($gate->fees as $f) {
                $splits[] = [
                    'recipient' => $f->recipient,
                    'amount'    => (string) $this->priceUnits($f->price),
                ];
            }
            $methodDetails['splits'] = $splits;
        }
        $sgn = $this->config->operator->signer;
        if ($this->config->operator->feePayer && $sgn !== null) {
            $methodDetails['feePayer']    = true;
            $methodDetails['feePayerKey'] = $sgn->pubkey();
        }
        return new ChargeRequest(
            amount: $amount,
            currency: $coin,
            recipient: $payTo,
            description: $gate->description ?? '',
            externalId: $gate->externalId ?? '',
            methodDetails: $methodDetails,
        );
    }

    /**
     * @return array{ChargeServer, SolanaChargeHandler}
     */
    private function serverFor(Gate $gate): array
    {
        $coin  = $this->settlementCoin($gate);
        $payTo = $gate->payTo ?? $this->config->effectiveRecipient();
        $key = $payTo . '|' . $coin;
        if (isset($this->handlerCache[$key])) {
            return $this->handlerCache[$key];
        }
        // Pin the route's known currency/recipient/network/decimals so
        // ChargeServer::validateChargeRequest enforces the field-match checks
        // unconditionally at issuance on the real route (audit #19 parity with
        // Rust `validate_charge_request`, which pins to its own
        // currency/network/decimals). The in-SDK request is built from this
        // same route config (chargeRequestFor), so these are correct by
        // construction; pinning makes the enforcement explicit and rejects any
        // off-route request that reaches this oracle. Decimals is the SDK's
        // fixed 6-dp micro-unit convention (matches the X402 adapter and
        // priceUnits()).
        $charges = new ChargeServer(
            secretKey: $this->config->mpp->challengeBindingSecret ?? '',
            realm: $this->config->mpp->resolveRealm($payTo),
            method: 'solana',
            blockhashProvider: null,
            pinnedCurrency: $coin,
            pinnedRecipient: $payTo,
            pinnedNetwork: $this->config->network->mintsLabel(),
            pinnedDecimals: 6,
        );
        $rpc = new RpcClient($this->config->rpcUrl);
        $feePayer = null;
        $sgn = $this->config->operator->signer;
        if ($this->config->operator->feePayer && $sgn !== null) {
            $feePayer = Keypair::fromSecretKey($sgn->secretKey());
        }
        $handler = new SolanaChargeHandler(
            challenges: $charges,
            rpc: $rpc,
            feePayer: $feePayer,
            network: $this->config->network->mintsLabel(),
            replayStore: $this->replayStore,
            acceptPushMode: $this->config->mpp->acceptPushMode,
        );
        $this->handlerCache[$key] = [$charges, $handler];
        return $this->handlerCache[$key];
    }

    private function settlementCoin(Gate $gate): string
    {
        $primary = $gate->amount->primaryCoin();
        return $primary?->value ?? $this->config->stablecoins[0]->value;
    }

    private function totalUnits(Gate $gate): int
    {
        return $this->priceUnits($gate->total());
    }

    private function priceUnits(Price $price): int
    {
        return $price->amount->multipliedBy(1_000_000)->toInt();
    }
}

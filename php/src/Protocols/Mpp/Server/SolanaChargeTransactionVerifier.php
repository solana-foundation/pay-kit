<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

use InvalidArgumentException;
use Throwable;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\PayCore\Solana\Mints;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\PayCore\Wire\Json;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\AssociatedTokenProgram;
use SolanaPhpSdk\Programs\MemoProgram;
use SolanaPhpSdk\Programs\SystemProgram;
use SolanaPhpSdk\Programs\TokenProgram;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use SolanaPhpSdk\Util\Base58;

/**
 * Verifies Solana charge transaction payloads before server co-sign/broadcast.
 *
 * Successful results intentionally do not carry a receipt reference. Broadcast
 * the co-signed transaction first, then create the receipt from the settled
 * on-chain signature with ChargeServer::createReceiptHeaderForReference().
 *
 * The verifier supports both pull-mode (`type=transaction`) credentials,
 * where the client signs a transaction the server still has to broadcast,
 * and push-mode (`type=signature`) credentials, where the client has already
 * broadcast and confirmed a transaction on-chain and only sends the
 * signature. Push-mode credentials only get a shape check at the credential
 * layer (signature length); the handler is responsible for fetching the
 * settled transaction and re-running {@see verifyTransactionPayload} against
 * the on-chain artifact.
 */
final class SolanaChargeTransactionVerifier implements PaymentVerifier, TransactionPayloadVerifier
{
    private const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
    private const MAX_COMPUTE_UNIT_LIMIT = 200_000;
    private const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000;
    // Tight cap for fee-sponsored pull mode, where the server signs before
    // broadcast and pays the priority fee. Worst-case priority fee at this cap
    // is ceil(10_000 * 200_000 / 1_000_000) = 2_000 lamports (~20% of the
    // per-signature base fee) — enough headroom for honest clients to bump
    // priority during congestion without exposing the merchant fee-payer to a
    // drain. Client-paid mode keeps the general 5M ceiling (audit #25).
    private const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED = 10_000;

    /**
     * @param bool $acceptPushMode Opt-in for push-mode (`type=signature`)
     *        credentials. Default `false` (off), matching the Rust reference.
     *        Push mode accepts the first presented on-chain signature (spec
     *        §13.5), a trade-off operators must consciously take on; routes
     *        that never opt in reject signature credentials outright instead of
     *        exposing the surface by default (audit #5).
     */
    public function __construct(
        private readonly bool $acceptPushMode = false,
    ) {
    }

    /**
     * Verify a pull- or push-mode credential against its challenge.
     *
     * Pull mode (`type=transaction`): runs the full pre-broadcast shape
     * check now, before the handler co-signs and broadcasts.
     *
     * Push mode (`type=signature`): the wire transaction is not in the
     * credential, so only the signature shape is validated here. The
     * handler MUST fetch the settled transaction by signature and call
     * {@see verifyTransactionPayload} against the on-chain artifact to
     * enforce the same shape contract pull mode does.
     */
    public function verify(Credential $credential, Challenge $challenge): VerificationResult
    {
        $transaction = $credential->payload['transaction'] ?? null;
        if (is_string($transaction) && $transaction !== '') {
            try {
                $request = ChargeRequest::fromArray($challenge->decodeRequest());
                // Pull-mode pre-broadcast: enforce the compute-budget caps.
                return $this->runVerification($transaction, $request, onChain: false);
            } catch (Throwable $error) {
                // Surface the message from any failure (the SDK's own
                // InvalidArgumentException, an upstream solana-php SolanaException
                // for malformed pubkeys/transactions, etc.); they all describe a
                // protocol-level reason the credential should be rejected.
                return VerificationResult::failure($error->getMessage());
            }
        }

        $signature = $credential->payload['signature'] ?? null;
        if (is_string($signature) && $signature !== '') {
            if (!$this->acceptPushMode) {
                // §13.5 push mode is off by default; reject before any shape
                // check so a non-opting route never accepts a push credential.
                return VerificationResult::failure('push-mode credentials are not accepted by this server');
            }
            try {
                $this->validateSignature($signature);
            } catch (Throwable $error) {
                return VerificationResult::failure($error->getMessage());
            }

            return VerificationResult::success(reference: $signature);
        }

        return VerificationResult::failure('missing transaction or signature payload');
    }

    /**
     * Verify a base64-encoded Solana transaction against the expected charge.
     *
     * Used both by pull-mode pre-broadcast (via {@see verify()}) and by the
     * push-mode handler path after it has fetched the settled transaction
     * from the RPC by signature.
     */
    public function verifyTransactionPayload(string $transactionBase64, ChargeRequest $request): VerificationResult
    {
        // Push-mode on-chain re-verification. The transaction has already
        // landed and confirmed, so the compute-budget caps no longer gate
        // anything; mirror Rust validate_parsed_instruction_allowlist
        // (rust/crates/mpp/src/server/charge.rs:1873-1876), which skips the
        // unit-limit/price caps on the parsed (settled) path.
        return $this->runVerification($transactionBase64, $request, onChain: true);
    }

    private function runVerification(string $transactionBase64, ChargeRequest $request, bool $onChain): VerificationResult
    {
        try {
            $this->verifyTransaction($transactionBase64, $request, $onChain);
        } catch (Throwable $error) {
            return VerificationResult::failure($error->getMessage());
        }

        return VerificationResult::success(reference: '');
    }

    /**
     * Shape check for a base58 ed25519 signature. The on-chain verification
     * happens later in the handler via getTransaction; this is a cheap
     * pre-RPC gate so obviously-malformed credentials reject without any
     * network round-trip.
     */
    private function validateSignature(string $signature): void
    {
        if (strlen($signature) < 87 || strlen($signature) > 88) {
            throw new InvalidArgumentException('invalid signature length');
        }
        $decoded = Base58::decode($signature);
        if (strlen($decoded) !== 64) {
            throw new InvalidArgumentException('invalid signature length');
        }
    }

    private function verifyTransaction(string $transactionBase64, ChargeRequest $request, bool $onChain = false): void
    {
        $wire = base64_decode($transactionBase64, true);
        if ($wire === false || $wire === '') {
            throw new InvalidArgumentException('invalid transaction payload');
        }

        $decoded = $this->decodeTransaction($wire);
        $methodDetails = $this->methodDetails($request);
        $splits = $this->splits($methodDetails);
        if (count($splits) > 8) {
            throw new InvalidArgumentException('too many splits');
        }

        $totalAmount = $this->parseAmount($request->amount, 'amount');
        $splitTotal = 0;
        foreach ($splits as $split) {
            $splitTotal += $this->parseAmount(Json::string($split['amount'] ?? null, 'split.amount'), 'split amount');
        }
        $primaryAmount = $totalAmount - $splitTotal;
        if ($primaryAmount <= 0) {
            throw new InvalidArgumentException('split amounts exceed total amount');
        }
        if ($request->recipient === '') {
            throw new InvalidArgumentException('recipient is required');
        }

        $feePayer = $this->expectedFeePayer($decoded['accountKeys'], $methodDetails);
        $matched = [];
        $createdAtaOwners = [];
        $requiredAtaOwners = $this->requiredAtaOwners($splits);

        if (strtoupper($request->currency) === 'SOL') {
            if ($requiredAtaOwners !== []) {
                throw new InvalidArgumentException('ataCreationRequired requires an SPL token charge');
            }
            $this->matchSolTransfer($decoded, $request->recipient, $primaryAmount, $feePayer, $matched);
            foreach ($splits as $split) {
                $this->matchSolTransfer(
                    $decoded,
                    Json::string($split['recipient'] ?? null, 'split.recipient'),
                    $this->parseAmount(Json::string($split['amount'] ?? null, 'split.amount'), 'split amount'),
                    $feePayer,
                    $matched,
                );
            }
            $this->verifyMemos($decoded, $request, $splits, $matched);
            $this->validateInstructionAllowlist(
                $decoded,
                $matched,
                expectedMint: null,
                allowedAtaOwners: [],
                expectedTokenProgram: null,
                expectedAtaPayer: $feePayer,
                requiredAtaOwners: [],
                createdAtaOwners: $createdAtaOwners,
                onChain: $onChain,
                feeSponsored: $feePayer !== null,
            );
            return;
        }

        $network = Json::optionalString($methodDetails['network'] ?? null, 'methodDetails.network', 'mainnet');
        $resolvedMint = Mints::resolve($request->currency, $network) ?? $request->currency;
        $mint = new PublicKey($resolvedMint);
        // audit #28: for a known stablecoin the static table is authoritative;
        // for an arbitrary, unknown mint address we cannot infer the owning
        // token program (the legacy default is wrong for any unknown Token-2022
        // mint), so the embedded methodDetails.tokenProgram is REQUIRED. There
        // is no RPC on this verifier path to resolve the owner on-chain.
        $embeddedTokenProgram = Json::optionalString($methodDetails['tokenProgram'] ?? null, 'methodDetails.tokenProgram', '');
        if ($embeddedTokenProgram !== '') {
            $tokenProgram = new PublicKey($embeddedTokenProgram);
        } elseif (Mints::isKnownMint($request->currency, $network)) {
            $tokenProgram = new PublicKey(Mints::tokenProgramFor($request->currency, $network));
        } else {
            throw new InvalidArgumentException(
                'methodDetails.tokenProgram is required for an unknown mint address; '
                . 'the token program cannot be inferred for arbitrary mints (audit #28)',
            );
        }
        $decimals = Json::optionalInt($methodDetails['decimals'] ?? null, 'methodDetails.decimals');
        $allowedAtaOwners = $this->allowedAtaOwners($splits, $feePayer);
        if ($requiredAtaOwners !== [] && $resolvedMint !== $mint->toBase58()) {
            throw new InvalidArgumentException('ataCreationRequired requires currency to be an SPL token mint address');
        }

        $this->matchSplTransfer(
            $decoded,
            $request->recipient,
            $mint,
            $tokenProgram,
            $primaryAmount,
            $decimals,
            $feePayer,
            $matched,
        );
        foreach ($splits as $split) {
            $this->matchSplTransfer(
                $decoded,
                Json::string($split['recipient'] ?? null, 'split.recipient'),
                $mint,
                $tokenProgram,
                $this->parseAmount(Json::string($split['amount'] ?? null, 'split.amount'), 'split amount'),
                $decimals,
                $feePayer,
                $matched,
            );
        }
        $this->verifyMemos($decoded, $request, $splits, $matched);
        // The expected ATA payer defaults to the transaction fee payer when no
        // route fee payer is configured (client-pays-fees mode). Mirrors Rust
        // expected_ata_payer = fee_payer.unwrap_or(tx_fee_payer)
        // (rust/crates/mpp/src/server/charge.rs:1299-1305); otherwise a
        // client-pays charge would skip the ATA-payer binding entirely.
        $expectedAtaPayer = $feePayer ?? ($decoded['accountKeys'][0] ?? null);
        $this->validateInstructionAllowlist(
            $decoded,
            $matched,
            expectedMint: $mint,
            allowedAtaOwners: $allowedAtaOwners,
            expectedTokenProgram: $tokenProgram,
            expectedAtaPayer: $expectedAtaPayer,
            requiredAtaOwners: $requiredAtaOwners,
            createdAtaOwners: $createdAtaOwners,
            onChain: $onChain,
            feeSponsored: $feePayer !== null,
        );
    }

    /**
     * @return array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>}
     */
    private function decodeTransaction(string $wire): array
    {
        $version = VersionedTransaction::peekVersion($wire);
        if ($version === 'legacy') {
            $transaction = Transaction::deserialize($wire);
            return [
                'accountKeys' => $transaction->message->accountKeys,
                'instructions' => $transaction->message->instructions,
            ];
        }

        if ($version !== 0) {
            throw new InvalidArgumentException('unsupported transaction version');
        }

        $transaction = VersionedTransaction::deserialize($wire);
        if ($transaction->message->addressTableLookups !== []) {
            throw new InvalidArgumentException('v0 address lookup tables are not supported');
        }

        return [
            'accountKeys' => $transaction->message->staticAccountKeys,
            'instructions' => array_map(
                static fn (object $instruction): array => [
                    'programIdIndex' => $instruction->programIdIndex,
                    'accounts' => $instruction->accountKeyIndexes,
                    'data' => $instruction->data,
                ],
                $transaction->message->compiledInstructions,
            ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function methodDetails(ChargeRequest $request): array
    {
        return is_array($request->methodDetails) ? $request->methodDetails : [];
    }

    /**
     * @param array<string, mixed> $methodDetails
     * @return array<int, array<string, mixed>>
     */
    private function splits(array $methodDetails): array
    {
        $splits = $methodDetails['splits'] ?? [];
        if (!is_array($splits)) {
            throw new InvalidArgumentException('splits must be an array');
        }

        $normalized = [];
        foreach ($splits as $split) {
            $split = Json::object($split, 'split');
            if (!isset($split['recipient'], $split['amount'])) {
                throw new InvalidArgumentException('split recipient and amount are required');
            }
            $normalized[] = $split;
        }

        return $normalized;
    }

    /**
     * @param array<int, PublicKey> $accountKeys
     * @param array<string, mixed> $methodDetails
     */
    private function expectedFeePayer(array $accountKeys, array $methodDetails): ?PublicKey
    {
        if (($methodDetails['feePayer'] ?? false) !== true) {
            return null;
        }
        $feePayerKey = $methodDetails['feePayerKey'] ?? null;
        if (!is_string($feePayerKey) || $feePayerKey === '') {
            throw new InvalidArgumentException('feePayer=true requires feePayerKey');
        }
        $feePayer = new PublicKey($feePayerKey);
        if (($accountKeys[0] ?? null)?->toBase58() !== $feePayer->toBase58()) {
            throw new InvalidArgumentException('transaction fee payer mismatch');
        }

        return $feePayer;
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     * @param array<int, bool> $matched
     */
    private function matchSolTransfer(array $decoded, string $recipient, int $amount, ?PublicKey $feePayer, array &$matched): void
    {
        $systemProgram = SystemProgram::programId()->toBase58();
        foreach ($decoded['instructions'] as $index => $instruction) {
            if (isset($matched[$index]) || $this->programId($decoded, $instruction) !== $systemProgram) {
                continue;
            }
            if (strlen($instruction['data']) < 12 || $this->readU32Le(substr($instruction['data'], 0, 4)) !== 2) {
                continue;
            }
            if ($this->readU64Le(substr($instruction['data'], 4, 8)) !== $amount) {
                continue;
            }
            $source = $this->accountKey($decoded, $instruction['accounts'][0] ?? null, 'source');
            $destination = $this->accountKey($decoded, $instruction['accounts'][1] ?? null, 'destination');
            if ($destination->toBase58() !== $recipient) {
                continue;
            }
            if ($feePayer !== null && $source->toBase58() === $feePayer->toBase58()) {
                throw new InvalidArgumentException('fee payer cannot fund the SOL payment transfer');
            }
            $matched[$index] = true;
            return;
        }

        throw new InvalidArgumentException(sprintf('No matching SOL transfer of %d lamports to %s', $amount, $recipient));
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     * @param array<int, bool> $matched
     */
    private function matchSplTransfer(
        array $decoded,
        string $recipient,
        PublicKey $mint,
        PublicKey $tokenProgram,
        int $amount,
        ?int $expectedDecimals,
        ?PublicKey $feePayer,
        array &$matched,
    ): void {
        foreach ($decoded['instructions'] as $index => $instruction) {
            if (isset($matched[$index]) || $this->programId($decoded, $instruction) !== $tokenProgram->toBase58()) {
                continue;
            }
            if (strlen($instruction['data']) < 10 || ord($instruction['data'][0]) !== 12) {
                continue;
            }
            if ($this->readU64Le(substr($instruction['data'], 1, 8)) !== $amount) {
                continue;
            }
            if ($expectedDecimals !== null && ord($instruction['data'][9]) !== $expectedDecimals) {
                continue;
            }

            $source = $this->accountKey($decoded, $instruction['accounts'][0] ?? null, 'token source');
            $instructionMint = $this->accountKey($decoded, $instruction['accounts'][1] ?? null, 'token mint');
            $destination = $this->accountKey($decoded, $instruction['accounts'][2] ?? null, 'token destination');
            $authority = $this->accountKey($decoded, $instruction['accounts'][3] ?? null, 'token authority');
            if ($instructionMint->toBase58() !== $mint->toBase58()) {
                continue;
            }
            if ($feePayer !== null && $authority->toBase58() === $feePayer->toBase58()) {
                throw new InvalidArgumentException('fee payer cannot authorize the SPL payment transfer');
            }
            $expectedAta = $this->associatedTokenAddress(new PublicKey($recipient), $mint, $tokenProgram);
            if ($destination->toBase58() !== $expectedAta->toBase58()) {
                continue;
            }
            if ($feePayer !== null) {
                $feePayerAta = $this->associatedTokenAddress($feePayer, $mint, $tokenProgram);
                if ($source->toBase58() === $feePayerAta->toBase58()) {
                    throw new InvalidArgumentException('fee payer token account cannot fund the SPL payment transfer');
                }
            }

            $matched[$index] = true;
            return;
        }

        throw new InvalidArgumentException(sprintf('No matching SPL transferChecked of %d to %s', $amount, $recipient));
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     * @param array<int, array<string, mixed>> $splits
     * @param array<int, bool> $matched
     */
    private function verifyMemos(array $decoded, ChargeRequest $request, array $splits, array &$matched): void
    {
        foreach ($this->expectedMemos($request, $splits) as $label => $memo) {
            if (strlen($memo) > 566) {
                throw new InvalidArgumentException('memo cannot exceed 566 bytes');
            }
            foreach ($decoded['instructions'] as $index => $instruction) {
                if (isset($matched[$index]) || !$this->isMemoInstruction($decoded, $instruction)) {
                    continue;
                }
                if ($instruction['data'] === $memo) {
                    $matched[$index] = true;
                    continue 2;
                }
            }
            throw new InvalidArgumentException(sprintf('No memo instruction found for %s memo "%s"', $label, $memo));
        }
    }

    /**
     * @param array<int, array<string, mixed>> $splits
     * @return array<string, string>
     */
    private function expectedMemos(ChargeRequest $request, array $splits): array
    {
        $memos = [];
        if ($request->externalId !== '') {
            $memos['externalId'] = $request->externalId;
        }
        foreach ($splits as $index => $split) {
            if (isset($split['memo']) && $split['memo'] !== '') {
                $memos['split-' . $index] = Json::string($split['memo'], 'split.memo');
            }
        }

        return $memos;
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     * @param array<int, bool> $matched
     * @param array<string, bool> $allowedAtaOwners
     * @param array<string, bool> $requiredAtaOwners
     * @param array<string, bool> $createdAtaOwners
     */
    private function validateInstructionAllowlist(
        array $decoded,
        array $matched,
        ?PublicKey $expectedMint,
        array $allowedAtaOwners,
        ?PublicKey $expectedTokenProgram,
        ?PublicKey $expectedAtaPayer,
        array $requiredAtaOwners,
        array &$createdAtaOwners,
        bool $onChain = false,
        bool $feeSponsored = false,
    ): void {
        $allowedPrograms = [
            self::COMPUTE_BUDGET_PROGRAM,
            SystemProgram::PROGRAM_ID,
            TokenProgram::PROGRAM_ID,
            TokenProgram::TOKEN_2022_PROGRAM_ID,
            AssociatedTokenProgram::PROGRAM_ID,
            MemoProgram::PROGRAM_ID_V2,
        ];
        foreach ($decoded['instructions'] as $index => $instruction) {
            $programId = $this->programId($decoded, $instruction);
            if (!in_array($programId, $allowedPrograms, true)) {
                throw new InvalidArgumentException('Unexpected program instruction in payment transaction: ' . $programId);
            }
            if ($programId === self::COMPUTE_BUDGET_PROGRAM) {
                // On the push/on-chain path the transaction has already
                // landed, so the unit-limit/price caps are no longer a gate.
                // Rust validate_parsed_instruction_allowlist does a bare
                // `continue` here (charge.rs:1873-1876); only the pull-mode
                // pre-broadcast path enforces the caps.
                if (!$onChain) {
                    $this->validateComputeBudgetInstruction($instruction, $feeSponsored);
                }
                continue;
            }
            if (isset($matched[$index])) {
                continue;
            }
            if ($programId === AssociatedTokenProgram::PROGRAM_ID) {
                $owner = $this->validateAtaInstruction(
                    $decoded,
                    $instruction,
                    $expectedMint,
                    $allowedAtaOwners,
                    $expectedTokenProgram,
                    $expectedAtaPayer,
                );
                $createdAtaOwners[$owner] = true;
                continue;
            }
            throw new InvalidArgumentException('Unexpected payment instruction in transaction');
        }

        foreach (array_keys($requiredAtaOwners) as $owner) {
            if (!isset($createdAtaOwners[$owner])) {
                throw new InvalidArgumentException('Missing required ATA creation instruction for split recipient ' . $owner);
            }
        }
    }

    /**
     * @param array{programIdIndex: int, accounts: array<int, int>, data: string} $instruction
     */
    private function validateComputeBudgetInstruction(array $instruction, bool $feeSponsored = false): void
    {
        if ($instruction['accounts'] !== []) {
            throw new InvalidArgumentException('compute budget instruction must not have accounts');
        }

        $data = $instruction['data'];
        $kind = $data === '' ? null : ord($data[0]);
        // Keep this aligned with the Rust/TypeScript MPP charge verifier.
        // Generic Solana compute-budget instructions may be valid, but MPP
        // charge payments currently only allow limit and price instructions.
        if ($kind === 2 && strlen($data) === 5) {
            $units = $this->readU32Le(substr($data, 1, 4));
            if ($units > self::MAX_COMPUTE_UNIT_LIMIT) {
                throw new InvalidArgumentException('compute unit limit exceeds maximum');
            }
            return;
        }
        if ($kind === 3 && strlen($data) === 9) {
            $price = $this->readU64Le(substr($data, 1, 8));
            // In fee-sponsored pull mode the server pays the priority fee, so
            // an attacker can otherwise pick a price up to the general 5M cap
            // and drain the merchant fee-payer (audit #25). Apply the tight cap
            // when the server is the fee payer; keep the 5M ceiling otherwise.
            $cap = $feeSponsored
                ? self::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED
                : self::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS;
            if ($price > $cap) {
                throw new InvalidArgumentException('compute unit price exceeds maximum');
            }
            return;
        }

        throw new InvalidArgumentException('unsupported compute budget instruction');
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     * @param array{programIdIndex: int, accounts: array<int, int>, data: string} $instruction
     * @param array<string, bool> $allowedAtaOwners
     */
    private function validateAtaInstruction(
        array $decoded,
        array $instruction,
        ?PublicKey $expectedMint,
        array $allowedAtaOwners,
        ?PublicKey $expectedTokenProgram,
        ?PublicKey $expectedPayer,
    ): string {
        if ($expectedMint === null) {
            throw new InvalidArgumentException('ATA creation is not allowed for native SOL payments');
        }
        if ($instruction['data'] !== "\x01") {
            throw new InvalidArgumentException('Only idempotent ATA creation is allowed');
        }
        if (count($instruction['accounts']) !== 6) {
            throw new InvalidArgumentException('Unexpected ATA creation account layout');
        }

        $payer = $this->accountKey($decoded, $instruction['accounts'][0], 'ATA payer');
        $ata = $this->accountKey($decoded, $instruction['accounts'][1], 'ATA address');
        $owner = $this->accountKey($decoded, $instruction['accounts'][2], 'ATA owner');
        $mint = $this->accountKey($decoded, $instruction['accounts'][3], 'ATA mint');
        $systemProgram = $this->accountKey($decoded, $instruction['accounts'][4], 'ATA system program');
        $tokenProgram = $this->accountKey($decoded, $instruction['accounts'][5], 'ATA token program');

        if ($expectedPayer !== null && $payer->toBase58() !== $expectedPayer->toBase58()) {
            throw new InvalidArgumentException('ATA payer must match the transaction fee payer');
        }
        if ($mint->toBase58() !== $expectedMint->toBase58()) {
            throw new InvalidArgumentException('ATA creation mint does not match the charge currency');
        }
        if ($systemProgram->toBase58() !== SystemProgram::PROGRAM_ID) {
            throw new InvalidArgumentException('ATA creation must reference the System Program');
        }
        if ($expectedTokenProgram !== null && $tokenProgram->toBase58() !== $expectedTokenProgram->toBase58()) {
            throw new InvalidArgumentException('ATA creation token program does not match methodDetails.tokenProgram');
        }
        if (!isset($allowedAtaOwners[$owner->toBase58()])) {
            throw new InvalidArgumentException('ATA creation owner is not authorized by the challenge');
        }
        $expectedAta = $this->associatedTokenAddress($owner, $mint, $tokenProgram);
        if ($ata->toBase58() !== $expectedAta->toBase58()) {
            throw new InvalidArgumentException('ATA creation address does not match owner/mint/token program');
        }

        return $owner->toBase58();
    }

    /**
     * @param array<int, array<string, mixed>> $splits
     * @return array<string, bool>
     */
    private function requiredAtaOwners(array $splits): array
    {
        $owners = [];
        foreach ($splits as $split) {
            if (($split['ataCreationRequired'] ?? false) === true) {
                $owners[Json::string($split['recipient'] ?? null, 'split.recipient')] = true;
            }
        }

        return $owners;
    }

    /**
     * @param array<int, array<string, mixed>> $splits
     * @return array<string, bool>
     */
    private function allowedAtaOwners(array $splits, ?PublicKey $feePayer): array
    {
        if ($feePayer !== null) {
            return $this->requiredAtaOwners($splits);
        }

        $owners = [];
        foreach ($splits as $split) {
            $owners[Json::string($split['recipient'] ?? null, 'split.recipient')] = true;
        }

        return $owners;
    }

    private function associatedTokenAddress(PublicKey $owner, PublicKey $mint, PublicKey $tokenProgram): PublicKey
    {
        return AssociatedTokenProgram::findAssociatedTokenAddress($owner, $mint, $tokenProgram)[0];
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     * @param array{programIdIndex: int, accounts: array<int, int>, data: string} $instruction
     */
    private function programId(array $decoded, array $instruction): string
    {
        return $this->accountKey($decoded, $instruction['programIdIndex'], 'program id')->toBase58();
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     */
    private function accountKey(array $decoded, mixed $index, string $label): PublicKey
    {
        if (!is_int($index) || !isset($decoded['accountKeys'][$index])) {
            throw new InvalidArgumentException('Invalid ' . $label . ' index');
        }

        return $decoded['accountKeys'][$index];
    }

    /**
     * @param array{accountKeys: array<int, PublicKey>, instructions: array<int, array{programIdIndex: int, accounts: array<int, int>, data: string}>} $decoded
     * @param array{programIdIndex: int, accounts: array<int, int>, data: string} $instruction
     */
    private function isMemoInstruction(array $decoded, array $instruction): bool
    {
        $programId = $this->programId($decoded, $instruction);
        return $programId === MemoProgram::PROGRAM_ID_V2;
    }

    private function parseAmount(string $amount, string $field): int
    {
        if ($amount === '' || !ctype_digit($amount)) {
            throw new InvalidArgumentException($field . ' must be a base-unit integer');
        }
        if ($this->decimalStringGreaterThan($amount, (string) PHP_INT_MAX)) {
            throw new InvalidArgumentException($field . ' exceeds PHP integer range');
        }

        return (int) $amount;
    }

    private function decimalStringGreaterThan(string $left, string $right): bool
    {
        $left = ltrim($left, '0');
        $right = ltrim($right, '0');
        if (strlen($left) !== strlen($right)) {
            return strlen($left) > strlen($right);
        }

        return strcmp($left, $right) > 0;
    }

    private function readU32Le(string $bytes): int
    {
        if (strlen($bytes) !== 4) {
            throw new InvalidArgumentException('expected 4 bytes');
        }

        $unpacked = unpack('Vvalue', $bytes);
        if ($unpacked === false) {
            throw new InvalidArgumentException('expected 4 bytes');
        }
        $value = $unpacked['value'];
        if (!is_int($value)) {
            throw new InvalidArgumentException('expected 4 bytes');
        }

        return $value;
    }

    private function readU64Le(string $bytes): int
    {
        if (strlen($bytes) !== 8) {
            throw new InvalidArgumentException('expected 8 bytes');
        }
        if ((ord($bytes[7]) & 0x80) !== 0) {
            throw new InvalidArgumentException('u64 value exceeds PHP integer range');
        }

        $value = 0;
        for ($i = 7; $i >= 0; $i -= 1) {
            $value = ($value << 8) + ord($bytes[$i]);
        }

        return $value;
    }
}

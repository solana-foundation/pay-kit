<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore\Rpc;

use PayKit\PayCore\Rpc\RpcGateway;

/**
 * Test double mirroring ruby/test/server_test.rb's FakeRpc. Scripted
 * responses for each method; failure modes are produced by setting the
 * appropriate flag.
 *
 * @internal
 */
final class FakeRpcGateway implements RpcGateway
{
    /** @var list<string> */
    public array $sentTransactions = [];
    /** @var list<array{0:string,1:array<int|string,mixed>}> */
    public array $calls = [];

    private int $statusIdx = 0;
    private int $callIdx = 0;

    /**
     * @param list<array<string,mixed>|null> $statuses    Sequence returned by getSignatureStatuses; last entry repeats.
     * @param list<mixed>                    $callResults Sequence returned by call(); once exhausted returns null.
     */
    public function __construct(
        private readonly string $signature = '5sigStubBASE58Signature1111111111111111111',
        private readonly array $statuses = [['err' => null, 'confirmationStatus' => 'confirmed']],
        private readonly array $callResults = [],
        private readonly ?\Throwable $sendError = null,
    ) {
    }

    public function call(string $method, array $params = []): mixed
    {
        $this->calls[] = [$method, $params];
        if ($this->callResults === []) {
            return null;
        }
        $idx = min($this->callIdx, array_key_last($this->callResults));
        $this->callIdx += 1;
        return $this->callResults[$idx];
    }

    public function sendRawTransaction(string $wireBytes, array $options = []): string
    {
        $this->sentTransactions[] = $wireBytes;
        if ($this->sendError !== null) {
            throw $this->sendError;
        }
        return $this->signature;
    }

    public function getSignatureStatuses(array $signatures, bool $searchTransactionHistory = false): array
    {
        $idx = min($this->statusIdx, array_key_last($this->statuses));
        $this->statusIdx += 1;
        return [$this->statuses[$idx]];
    }
}

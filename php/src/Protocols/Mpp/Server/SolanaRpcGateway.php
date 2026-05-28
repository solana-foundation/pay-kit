<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

use SolanaPhpSdk\Rpc\RpcClient;

/**
 * Default {@see RpcGateway} that delegates to a concrete
 * {@see RpcClient}. Holds no state of its own.
 */
final class SolanaRpcGateway implements RpcGateway
{
    public function __construct(private readonly RpcClient $rpc)
    {
    }

    public function call(string $method, array $params = []): mixed
    {
        return $this->rpc->call($method, $params);
    }

    public function sendRawTransaction(string $wireBytes, array $options = []): string
    {
        return $this->rpc->sendRawTransaction($wireBytes, $options);
    }

    public function getSignatureStatuses(array $signatures, bool $searchTransactionHistory = false): array
    {
        return $this->rpc->getSignatureStatuses($signatures, $searchTransactionHistory);
    }
}

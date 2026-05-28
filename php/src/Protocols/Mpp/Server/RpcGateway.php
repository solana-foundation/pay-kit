<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

/**
 * Narrow abstraction over the subset of Solana RPC methods that the
 * MPP server uses for settlement and confirmation. Lets the handler
 * be unit-tested with a fake gateway (mirrors Ruby's FakeRpc test
 * helper at ruby/test/server_test.rb).
 *
 * The default implementation {@see SolanaRpcGateway} delegates to
 * {@see \SolanaPhpSdk\Rpc\RpcClient}; consumers passing a concrete
 * RpcClient to the handler are wrapped transparently at construction.
 */
interface RpcGateway
{
    /**
     * Generic RPC dispatch. Used for methods not covered by the
     * dedicated wrappers below (e.g. `getTransaction`).
     *
     * @param array<int|string,mixed> $params
     */
    public function call(string $method, array $params = []): mixed;

    /**
     * Submit the already-signed wire-format transaction. Returns the
     * base58 signature.
     *
     * @param array<string,mixed> $options
     */
    public function sendRawTransaction(string $wireBytes, array $options = []): string;

    /**
     * Look up signature confirmation statuses.
     *
     * @param list<string>             $signatures
     * @return array<int,array<string,mixed>|null>
     */
    public function getSignatureStatuses(array $signatures, bool $searchTransactionHistory = false): array;
}

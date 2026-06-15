<?php

declare(strict_types=1);

return [
    'network'    => env('PAY_KIT_NETWORK', 'solana_devnet'),
    'rpc_url'    => env('PAY_KIT_RPC_URL'),
    'accept'     => ['x402', 'mpp'],
    'stablecoins' => ['USDC'],
    'operator' => [
        'recipient' => env('PAY_KIT_OPERATOR_RECIPIENT'),
        'key'       => env('PAY_KIT_OPERATOR_KEY'),
        'fee_payer' => true,
    ],
    'x402_facilitator_url'         => env('PAY_KIT_X402_FACILITATOR_URL'),
    'mpp_challenge_binding_secret' => env('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET'),
    'mpp' => [
        // Leave unset to derive a per-recipient realm (audit #15). Set
        // PAY_KIT_MPP_REALM only when you want an explicit, app-specific realm.
        'realm'      => env('PAY_KIT_MPP_REALM'),
        'expires_in' => 120,
    ],
    'preflight' => env('PAY_KIT_PREFLIGHT', true),
];

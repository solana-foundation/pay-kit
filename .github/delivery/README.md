# Delivery ledgers

Delivery ledgers inventory source work without treating file presence as proof of
semantic delivery. `pr216-ledger.json` is pinned to the authoritative
`49dc797..45ad8c9` commit and path sets. Validate it with:

```sh
node scripts/validate-pr216-ledger.mjs
node scripts/validate-pr216-ledger_test.mjs
```

Only use `integrated` with independently checkable evidence. Keep unresolved
work as `open_pr` or `missing` with an owner and concrete follow-up.

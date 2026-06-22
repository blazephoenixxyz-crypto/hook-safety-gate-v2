# HookSafetyGate

A standalone, default-closed admission gate for routing through Uniswap v4 pools.

`HookSafetyGate` lets any v4 integrator (a router, aggregator, periphery contract,
or off-chain solver) decide whether a pool's hook is safe to route through —
**before any token moves** — using three independent checks:

- **Layer 1 — delta-permission screen (immutable).** A hook is only ever routable
  if its address carries neither of the two return-delta permission flags
  (`BEFORE_SWAP_RETURNS_DELTA`, `AFTER_SWAP_RETURNS_DELTA`). These are the only two
  of v4's 14 hook flags that let a hook modify swap accounting. Pure: reads only
  the hook's own address, never calls the hook.

- **Layer 2 — default-closed allow-list (governed).** A hook is routable only if it
  has been explicitly admitted by the owner. Anything not admitted is denied.

- **Layer 3 — code-hash pinning (immutable).** When a hook is admitted, the
  `EXTCODEHASH` of its address is recorded. The hook is only routable while its
  current code hash equals the pinned value. If the code behind the address
  changes — a proxy upgrade, or selfdestruct-and-redeploy — the pin no longer
  matches and the hook is automatically treated as unsafe until an owner
  re-reviews and re-admits it. This closes the "approved hook upgrades to
  malicious logic" vector.

The contract **holds no funds, makes no external calls into hook code, and cannot
move tokens.** It is purely a predicate (`isRoutableHook`) plus an owner-managed
allow-list with code-hash pinning.

## Why this exists

v4 hooks are arbitrary third-party code in the swap path. Existing protections —
the PoolManager's flag enforcement, slippage bounds, and off-chain interface
allow-lists — are each necessary but leave the routing layer without a
deterministic, on-chain, default-closed gate. Real losses have already occurred at
the hook/router layer (Cork Protocol, $11M, May 2025; z0r0z V4 Router, $42K, March
2026). This gate is the missing enforcement piece.

## Threat coverage (honest scope)

| Vector | Covered? | By |
|---|---|---|
| Hook returns a delta to skim swap accounting | Fully | Layer 1 (structural, unfakeable) |
| Unknown / unvetted hook routed | Fully | Layer 2 (default-closed) |
| Approved hook upgrades to malicious code | Fully | Layer 3 (code-hash pin) |
| Reverting / gas-griefing hook | Partially | Layer 2 (must be curated out) |
| Misbehaviour by an allow-listed, unchanged hook | Not covered | Out of scope — requires behavioural monitoring |

The gate closes the deterministic, address- and code-level vectors. It does not
claim to detect arbitrary runtime behaviour of an admitted, unchanged hook.

## Design principles

1. **Zero external dependencies.** Flag values are redeclared verbatim from
   `Uniswap/v4-core` `Hooks.sol` and pinned by a test (`test_constants_matchV4Core`).
2. **Auditable in minutes.** No assembly, no proxies, no delegatecall, no token
   handling. Every branch maps to a stated invariant.
3. **Fail closed.** Unknown hooks, delta-flagged hooks, and hooks whose code has
   changed since admission are all denied.

## Integration

```solidity
// Before routing a v4 leg:
if (!hookSafetyGate.isRoutableHook(address(key.hooks))) {
    // skip this pool (off-chain), or revert (on-chain execution)
}
```

## Build & test

```bash
forge install foundry-rs/forge-std --no-git
forge test -vvv
```

## Invariants (all covered by the test suite)

- `isRoutableHook(h) == true` ⇒ `h` carries no delta flags AND its code is
  unchanged since admission.
- A delta-flagged hook is never routable and never allow-listable.
- Unknown hooks return `false` (default-closed).
- A hook whose code changes after admission becomes non-routable with no owner
  action (`isStale` reports it).
- `address(0)` (hookless pools) is always routable.
- Only the owner can modify the allow-list.
- The contract cannot hold or move funds.

## License

MIT. Published as a public good; no exclusivity is claimed.

## Author

Blaze Phoenix

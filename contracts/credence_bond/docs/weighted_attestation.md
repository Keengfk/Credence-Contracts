# Weighted Attestation

## Overview

Attestation weight quantifies an attester's credibility at the moment they submit an attestation. It is derived from the attester's configured stake, a basis-point multiplier, and a protocol-level cap.

## Formula

```
raw    = floor(stake * multiplier_bps / 10_000)
weight = clamp(raw, DEFAULT_ATTESTATION_WEIGHT, min(config_max, MAX_ATTESTATION_WEIGHT))
```

| Constant | Value | Description |
|---|---|---|
| `DEFAULT_ATTESTATION_WEIGHT` | 1 | Minimum weight; returned when stake is 0 or raw rounds to 0 |
| `MAX_ATTESTATION_WEIGHT` | 1_000_000 | Protocol hard cap; cannot be exceeded regardless of config |
| `DEFAULT_WEIGHT_MULTIPLIER_BPS` | 100 | Default multiplier (1%) used when config is not set |
| `DEFAULT_MAX_WEIGHT` | 100_000 | Default config max used when config is not set |
| `BPS_DENOMINATOR` | 10_000 | Basis-point denominator |

## Rounding Invariants

1. **Floor division** — integer division truncates toward zero. `stake=9_999, mult=100` → `floor(99.99) = 99`.
2. **Lower bound** — weight is always `>= 1`. A raw result of 0 is clamped up to `DEFAULT_ATTESTATION_WEIGHT`.
3. **Upper bound** — weight is always `<= MAX_ATTESTATION_WEIGHT` (1_000_000). Both the config max and the protocol hard cap are enforced.
4. **Determinism** — identical `(stake, multiplier_bps, config_max)` inputs always produce the same output.
5. **Monotonicity** — for a fixed config, increasing stake never decreases weight (until the cap is reached).
6. **Immutability of stored weights** — once an attestation is written to storage its `weight` field is never mutated. Subsequent stake or config changes only affect future attestations.
7. **Config clamping** — `set_weight_config` silently clamps `max_weight` to `MAX_ATTESTATION_WEIGHT`; the stored value reflects the clamped result.

## Regression Vectors

The table below lists fixed `(stake, multiplier_bps, config_max, expected_weight)` triples that are enforced by the test suite (`regression_vectors_compute_weight`):

| stake | multiplier_bps | config_max | expected |
|---|---|---|---|
| 0 | 100 | 100_000 | 1 (zero stake → default) |
| 1 | 1 | 100_000 | 1 (rounds to 0 → clamped) |
| 10_000 | 100 | 100_000 | 100 (exact) |
| 9_999 | 100 | 100_000 | 99 (floor) |
| 10_001 | 100 | 100_000 | 100 (floor) |
| 1_000_000 | 100 | 5_000 | 5_000 (config cap) |
| 50_000 | 200 | 100_000 | 1_000 |
| 33_333 | 300 | 100_000 | 999 (floor) |
| 33_334 | 300 | 100_000 | 1_000 |
| 1_000_000 | 0 | 100_000 | 1 (zero multiplier → clamped) |
| 1_000_000 | 10_000 | 1 | 1 (config_max=1) |
| 100 | 10_000 | 100_000 | 100 |

## Security Notes

- Stake is stored as `i128` but cast to `u64` via `unsigned_abs()` before the BPS multiplication. The negative-stake guard in `set_attester_stake` ensures this cast is always safe.
- Weight config is admin-only; callers must enforce authorization before calling `set_weight_config` or `set_attester_stake`.
- Stored attestation weights are immutable — an attacker cannot retroactively inflate past attestations by increasing their stake.

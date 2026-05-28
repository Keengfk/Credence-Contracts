# Tier System

Identity tiers (Bronze, Silver, Gold, Platinum) based on bonded amount thresholds.

## Thresholds (Admin-configurable with Fallback Constants)

All thresholds are internally represented and checked in **normalized 18-decimal format**. This ensures consistent boundary checks across different tokens regardless of their native decimal precision.

### Exact Boundary Table

| Tier | Lower Bound (Inclusive) | Upper Bound (Exclusive) | Default Threshold Value (Code Constant) |
|---|---|---|---|
| **Bronze** | `0` | `< 1,000 * 10^18` | `TIER_BRONZE_MAX = 1,000,000,000,000,000,000,000` |
| **Silver** | `1,000 * 10^18` | `< 5,000 * 10^18` | `TIER_SILVER_MAX = 5,000,000,000,000,000,000,000` |
| **Gold** | `5,000 * 10^18` | `< 20,000 * 10^18` | `TIER_GOLD_MAX = 20,000,000,000,000,000,000,000` |
| **Platinum** | `20,000 * 10^18` | `i128::MAX` | N/A (Catch-all) |

### Boundary Semantics

- **Bronze**: Any amount $A$ where $0 \le A < 1,000 \times 10^{18}$. Negative amounts map to Bronze but are rejected by validation on ingress.
- **Silver**: Any amount $A$ where $1,000 \times 10^{18} \le A < 5,000 \times 10^{18}$.
- **Gold**: Any amount $A$ where $5,000 \times 10^{18} \le A < 20,000 \times 10^{18}$.
- **Platinum**: Any amount $A$ where $A \ge 20,000 \times 10^{18}$ (up to `i128::MAX`).

---

## Admin Configuration

The contract admin can update the tier thresholds at runtime using the `set_tier_thresholds` function.

### Method Signature

```rust
pub fn set_tier_thresholds(
    e: Env,
    admin: Address,
    bronze_max: i128,
    silver_max: i128,
    gold_max: i128,
)
```

### Constraints and Validation

To ensure mathematical consistency, the contract validates the proposed thresholds and panics if any of the following bounds are violated:
1. `bronze_max > 0` (The Bronze boundary must be positive).
2. `silver_max > bronze_max` (Silver boundary must exceed Bronze).
3. `gold_max > silver_max` (Gold boundary must exceed Silver).

### Events

Updating the thresholds emits a `tier_thresholds_changed` event:
- **Topics**: `("tier_thresholds_changed",)`
- **Data**: `(old_thresholds, new_thresholds)` where each is a `TierThresholds` struct.

---

## Behaviour

- **get_tier()**: Returns current tier for the bond’s `bonded_amount` using the configured thresholds.
- Tier is derived dynamically from amount; there is no separate tier storage.
- On **create_bond**, **top_up**, **withdraw** (and **withdraw_early**), a **tier_changed** event is emitted only when the tier actually changes.
- **Slashing**: Slashing increases `slashed_amount` but does not modify `bonded_amount`. Therefore, a slashed bond does not lose its tier rank (reputation is preserved).

## Upgrade / Downgrade

- **Upgrade**: Increasing bonded amount (create_bond or top_up) can move to a higher tier.
- **Downgrade**: Decreasing amount (withdraw / withdraw_early) can move to a lower tier.
- Partial withdrawals that keep the amount in the same band do not trigger a tier change or emit events.


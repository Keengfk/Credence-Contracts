# Early Exit Penalty

Penalty charged when users withdraw before the lock-up period ends.
Penalty is configurable and attributed to the protocol treasury.

## Configuration

| Field | Description |
|-------|-------------|
| `treasury` | Address that receives penalty amounts. |
| `penalty_bps` | Rate in basis points. **Must be in `[0, 10 000]`** (0 % – 100 %). Values above 10 000 are rejected with `ContractError::InvalidPenaltyBps` (211). |

Set via `set_early_exit_config(admin, treasury, penalty_bps)`. Admin-only.

### Config-changed event

Every successful call to `set_early_exit_config` emits `"early_exit_cfg_set"` with:

```
(old_penalty_bps: u32, new_penalty_bps: u32, treasury: Address)
```

`old_penalty_bps` is `0` when no previous configuration existed.

## Penalty Formula

```
penalty = (amount × penalty_bps / 10_000) × (remaining_time / total_duration)
```

- **remaining_time** — seconds left until lock-up end (`end - now`).
- **total_duration** — bond duration at creation.

The penalty is proportional to the fraction of the lock period that remains.

### Clamping guarantee

The computed penalty is **always clamped to `[0, amount]`**.  
This means:
- The user's net withdrawal (`amount - penalty`) is always ≥ 0.
- An operator cannot accidentally configure a penalty that exceeds 100 % of the
  withdrawn amount, even if `calculate_penalty` is called directly with a large
  `penalty_bps` value.

## Validation rules

| Check | Error |
|-------|-------|
| `penalty_bps > 10_000` | `ContractError::InvalidPenaltyBps` (211) |
| Config not set when `withdraw_early` is called | `ContractError::EarlyExitConfigNotSet` (210) |

## Functions

### `set_early_exit_config(admin, treasury, penalty_bps)`

Stores the early-exit configuration. Rejects `penalty_bps > 10_000`.
Emits `"early_exit_cfg_set"`.

### `withdraw_early(amount)`

Withdraws `amount` before lock-up end. Computes and clamps the penalty,
then emits `"early_exit_penalty"` with `(identity, amount, penalty, treasury)`.
In a full implementation the token transfer sends `amount - penalty` to the user
and `penalty` to the treasury.

### `withdraw(amount)`

Use after lock-up or after the rolling-bond notice period. No penalty.

## Events

| Event | Payload |
|-------|---------|
| `"early_exit_cfg_set"` | `(old_penalty_bps, new_penalty_bps, treasury)` |
| `"early_exit_penalty"` | `(identity, withdraw_amount, penalty_amount, treasury)` |

## Security

- `penalty_bps` is validated at write time — no invalid value can ever be stored.
- Penalty is clamped in `calculate_penalty` as a defence-in-depth measure.
- Config can only be set by the admin (`admin.require_auth()`).
- Withdrawing after lock-up must use `withdraw`, not `withdraw_early`.

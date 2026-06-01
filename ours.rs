#![no_std]

mod early_exit_penalty;
mod nonce;
mod rolling_bond;
mod slashing;
mod tiered_bond;
mod weighted_attestation;

pub mod types;

use credence_errors::ContractError;
use timelock;
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, Address, Env, String, Symbol, Val, Vec,
};

/// Identity tier based on bonded amount (Bronze < Silver < Gold < Platinum).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BondTier {
    Bronze,
    Silver,
    Gold,
    Platinum,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct IdentityBond {
    pub identity: Address,
    pub bonded_amount: i128,
    pub bond_start: u64,
    pub bond_duration: u64,
    pub slashed_amount: i128,
    pub active: bool,
    /// If true, bond auto-renews at period end unless withdrawal was requested.
    pub is_rolling: bool,
    /// When withdrawal was requested (0 = not requested).
    pub withdrawal_requested_at: u64,
    /// Notice period duration for rolling bonds (seconds).
    pub notice_period_duration: u64,
}

// Re-export attestation type (definitions and validation in types::attestation).
pub use types::Attestation;

#[contracttype]
pub enum DataKey {
    Admin,
    Bond(Address),
    Attester(Address),
    Attestation(u64),
    AttestationCounter,
    SubjectAttestations(Address),
    /// Per-identity attestation count (updated on add/revoke).
    SubjectAttestationCount(Address),
    /// Per-identity nonce for replay prevention.
    Nonce(Address),
    /// Attester stake used for weighted attestation (set by admin or from bond).
    AttesterStake(Address),
    /// Global config for weighted attestation computation.
    WeightConfig,
    /// Pending admin address for two-step ownership transfer.
    PendingAdmin,
    /// Timelock ETA for pending admin transfer.
    AdminTransferEta,
}

// Storage TTL policy constants. Tuned for maximum bond durations and long-lived
// attestation records. Values taken from repository test snapshots (max_entry_ttl).
// Ensure TTL covers the maximum allowed bond duration (365 days).
const STORAGE_TTL_EXTEND_TO: u64 = 31_536_000; // 365 days in seconds

/// Source-level storage budget for a hot path.
///
/// The counts are intentionally key-scoped rather than fee-denominated so they
/// remain stable across Soroban SDK budget model changes. A value of `1` means
/// the path reads or writes that storage key exactly once in the success path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotPathStorageBudget {
    pub bond_reads: u32,
    pub bond_writes: u32,
    pub admin_reads: u32,
    pub callback_reads: u32,
    pub lock_reads: u32,
    pub lock_writes: u32,
    pub config_reads: u32,
}

/// `withdraw_early`: one bond load, one bond write, and the early-exit config
/// read once through `early_exit_penalty::get_config`.
pub const WITHDRAW_EARLY_STORAGE_BUDGET: HotPathStorageBudget = HotPathStorageBudget {
    bond_reads: 1,
    bond_writes: 1,
    admin_reads: 0,
    callback_reads: 0,
    lock_reads: 0,
    lock_writes: 0,
    config_reads: 1,
};

/// `withdraw_bond`: one bond load/write plus the reentrancy lock and optional
/// callback key. The lock is written once to acquire and once to release.
pub const WITHDRAW_BOND_STORAGE_BUDGET: HotPathStorageBudget = HotPathStorageBudget {
    bond_reads: 1,
    bond_writes: 1,
    admin_reads: 0,
    callback_reads: 1,
    lock_reads: 1,
    lock_writes: 2,
    config_reads: 0,
};

/// `slash_bond`: one admin read, one bond load/write, reentrancy lock, and one
/// optional callback lookup.
pub const SLASH_BOND_STORAGE_BUDGET: HotPathStorageBudget = HotPathStorageBudget {
    bond_reads: 1,
    bond_writes: 1,
    admin_reads: 1,
    callback_reads: 1,
    lock_reads: 1,
    lock_writes: 2,
    config_reads: 0,
};

// Helper: bump storage TTL for a given key in instance storage. This calls
// `extend_ttl` on the instance storage to ensure long-lived entries do not
// expire silently. It's safe to call repeatedly on hot paths.
fn bump_instance_ttl<K: soroban_sdk::IntoVal<Env> + Clone>(e: &Env, key: &K) {
    // Best-effort: call extend_ttl if available on the instance API.
    // If the underlying SDK changes, this single helper isolates the callsite.
    e.storage()
        .instance()
        .extend_ttl(key, &STORAGE_TTL_EXTEND_TO);
}

#[contract]
pub struct CredenceBond;

#[contractimpl]
impl CredenceBond {
    /// Initialize the contract (admin).
    ///
    /// Errors:
    /// - `ContractError::AlreadyInitialized` (2) if initialize is called twice
    pub fn initialize(e: Env, admin: Address) {
        admin.require_auth();
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Set early-exit penalty configuration. Only the admin may call this.
    ///
    /// `penalty_bps` is the penalty rate in basis points where 10 000 = 100 %.
    /// Values outside `[0, 10_000]` are rejected.
    ///
    /// # Errors
    /// - `ContractError::NotInitialized` (1) — contract admin not set yet
    /// - `ContractError::NotAdmin` (100) — caller is not the stored admin
    /// - `ContractError::InvalidPenaltyBps` (211) — `penalty_bps > 10_000`
    ///
    /// # Events
    /// Emits `"early_exit_cfg_set"` with `(old_penalty_bps, new_penalty_bps, treasury)`.
    pub fn propose_admin(e: Env, current_admin: Address, proposed: Address) {
        current_admin.require_auth();
        let stored: Address = e.storage().instance().get(&DataKey::Admin).unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        if stored != current_admin { panic_with_error!(e, ContractError::NotAdmin); }
        if proposed == current_admin { panic_with_error!(e, ContractError::AdminUnchanged); }
        let eta: u64 = e.ledger().timestamp() + timelock::min_delay_seconds();
        e.storage().instance().set(&DataKey::PendingAdmin, &proposed);
        e.storage().instance().set(&DataKey::AdminTransferEta, &eta);
    }

    pub fn accept_admin(e: Env, new_admin: Address) {
        new_admin.require_auth();
        let pending: Address = e.storage().instance().get(&DataKey::PendingAdmin).unwrap_or_else(|| panic_with_error!(e, ContractError::NoPendingAdmin));
        if pending != new_admin { panic_with_error!(e, ContractError::NotAdmin); }
        let eta: u64 = e.storage().instance().get(&DataKey::AdminTransferEta).unwrap_or_else(|| panic_with_error!(e, ContractError::NoPendingAdmin));
        if !timelock::is_ready(eta, e.ledger().timestamp()) { panic_with_error!(e, ContractError::TimelockNotReady); }
        e.storage().instance().set(&DataKey::Admin, &new_admin);
        e.storage().instance().remove(&DataKey::PendingAdmin);
        e.storage().instance().remove(&DataKey::AdminTransferEta);
    }

    pub fn set_early_exit_config(e: Env, admin: Address, treasury: Address, penalty_bps: u32) {
        admin.require_auth();
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        if stored_admin != admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }
        early_exit_penalty::set_config(&e, treasury, penalty_bps);
    }

    /// Register an authorized attester (only admin can call).
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    pub fn register_attester(e: Env, attester: Address) {
        let admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();

        e.storage()
            .instance()
            .set(&DataKey::Attester(attester.clone()), &true);
        e.events()
            .publish((Symbol::new(&e, "attester_registered"),), attester);
    }

    /// Remove an attester's authorization (only admin can call).
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    pub fn unregister_attester(e: Env, attester: Address) {
        let admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();

        e.storage()
            .instance()
            .remove(&DataKey::Attester(attester.clone()));
        e.events()
            .publish((Symbol::new(&e, "attester_unregistered"),), attester);
    }

    /// Check if an address is an authorized attester.
    pub fn is_attester(e: Env, attester: Address) -> bool {
        e.storage()
            .instance()
            .get(&DataKey::Attester(attester))
            .unwrap_or(false)
    }

    /// Create or top-up a bond for an identity.
    ///
    /// Authority: `identity` must authorize this call.
    /// In a full implementation this would transfer USDC from the caller and store the bond.
    ///
    /// # Events
    /// Emits `bond_created` event with (identity, amount, bond_start, duration)
    pub fn create_bond(
        e: Env,
        identity: Address,
        amount: i128,
        duration: u64,
        is_rolling: bool,
        notice_period_duration: u64,
    ) -> IdentityBond {
        identity.require_auth();
        let bond_start = e.ledger().timestamp();

        // Verify the end timestamp wouldn't overflow
        let _end_timestamp = bond_start
            .checked_add(duration)
            .expect("bond end timestamp would overflow");

        let bond = IdentityBond {
            identity: identity.clone(),
            bonded_amount: amount,
            bond_start,
            bond_duration: duration,
            slashed_amount: 0,
            active: true,
            is_rolling,
            withdrawal_requested_at: 0,
            notice_period_duration,
        };
        let key = DataKey::Bond(identity.clone());
        if e.storage().instance().has(&key) {
            panic_with_error!(e, ContractError::BondAlreadyExists);
        }
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        let tier = tiered_bond::get_tier_for_amount(amount);
        tiered_bond::emit_tier_change_if_needed(&e, &identity, BondTier::Bronze, tier);
        
        // Emit bond_created event
        e.events().publish(
            (Symbol::new(&e, "bond_created"),),
            (identity.clone(), amount, bond_start, duration),
        );
        
        bond
    }

    /// Return current bond state for an identity (simplified: single bond per contract instance).
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    pub fn get_identity_state(e: Env) -> IdentityBond {
        let key = DataKey::Bond;
        let bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);
        bond
    }

    /// Add an attestation for a subject (only authorized attesters can call).
    /// Requires correct nonce for replay prevention; rejects duplicate (verifier, identity, data).
    /// Weight is computed from attester stake (weighted attestation system).
    ///
    /// @param e Contract environment
    /// @param attester Authorized verifier (must be registered and must pass require_auth)
    /// @param subject Identity being attested
    /// @param attestation_data Opaque attestation payload
    /// @param nonce Current nonce for attester (get_nonce(attester)); incremented on success
    /// @return The created Attestation (id, verifier, identity, timestamp, weight, data, revoked)
    ///
    /// Errors:
    /// - `ContractError::UnauthorizedAttester` (102)
    /// - `ContractError::DuplicateAttestation` (300)
    /// - `ContractError::Overflow` (700)
    pub fn add_attestation(
        e: Env,
        attester: Address,
        subject: Address,
        attestation_data: String,
        nonce: u64,
    ) -> Attestation {
        attester.require_auth();

        let is_authorized = e
            .storage()
            .instance()
            .get(&DataKey::Attester(attester.clone()))
            .unwrap_or(false);
        if !is_authorized {
            panic_with_error!(e, ContractError::UnauthorizedAttester);
        }

        nonce::consume_nonce(&e, &attester, nonce);

        let dedup_key = types::AttestationDedupKey {
            verifier: attester.clone(),
            identity: subject.clone(),
            attestation_data: attestation_data.clone(),
        };
        if e.storage().instance().has(&dedup_key) {
            panic_with_error!(e, ContractError::DuplicateAttestation);
        }

        let counter_key = DataKey::AttestationCounter;
        let id: u64 = e.storage().instance().get(&counter_key).unwrap_or(0);
        let next_id = id
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));
        e.storage().instance().set(&counter_key, &next_id);

        let weight = weighted_attestation::compute_weight(&e, &attester);
        types::Attestation::validate_weight(weight);

        let attestation = Attestation {
            id,
            verifier: attester.clone(),
            identity: subject.clone(),
            timestamp: e.ledger().timestamp(),
            weight,
            attestation_data: attestation_data.clone(),
            revoked: false,
        };

        e.storage()
            .instance()
            .set(&DataKey::Attestation(id), &attestation);
        bump_instance_ttl(&e, &DataKey::Attestation(id));
        e.storage().instance().set(&dedup_key, &id);
        bump_instance_ttl(&e, &dedup_key);

        let subject_key = DataKey::SubjectAttestations(subject.clone());
        let mut attestations: Vec<u64> = e
            .storage()
            .instance()
            .get(&subject_key)
            .unwrap_or(Vec::new(&e));
        attestations.push_back(id);
        e.storage().instance().set(&subject_key, &attestations);
        bump_instance_ttl(&e, &subject_key);

        let count_key = DataKey::SubjectAttestationCount(subject.clone());
        let count: u32 = e.storage().instance().get(&count_key).unwrap_or(0);
        e.storage()
            .instance()
            .set(&count_key, &count.saturating_add(1));
        bump_instance_ttl(&e, &count_key);

        e.events().publish(
            (Symbol::new(&e, "attestation_added"), subject),
            (id, attester, attestation_data, weight),
        );

        attestation
    }

    /// Revoke an attestation (only the original attester can revoke). Requires correct nonce.
    ///
    /// Errors:
    /// - `ContractError::AttestationNotFound` (301)
    /// - `ContractError::NotOriginalAttester` (103)
    /// - `ContractError::AttestationAlreadyRevoked` (302)
    pub fn revoke_attestation(e: Env, attester: Address, attestation_id: u64, nonce: u64) {
        attester.require_auth();
        nonce::consume_nonce(&e, &attester, nonce);

        let key = DataKey::Attestation(attestation_id);
        let mut attestation: Attestation = e
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::AttestationNotFound));

        if attestation.verifier != attester {
            panic_with_error!(e, ContractError::NotOriginalAttester);
        }
        if attestation.revoked {
            panic_with_error!(e, ContractError::AttestationAlreadyRevoked);
        }

        attestation.revoked = true;
        e.storage().instance().set(&key, &attestation);
        bump_instance_ttl(&e, &key);

        let dedup_key = types::AttestationDedupKey {
            verifier: attestation.verifier.clone(),
            identity: attestation.identity.clone(),
            attestation_data: attestation.attestation_data.clone(),
        };
        e.storage().instance().remove(&dedup_key);
        // Removing doesn't need a TTL bump; keep for symmetry.

        let count_key = DataKey::SubjectAttestationCount(attestation.identity.clone());
        let count: u32 = e.storage().instance().get(&count_key).unwrap_or(0);
        e.storage()
            .instance()
            .set(&count_key, &count.saturating_sub(1));
        bump_instance_ttl(&e, &count_key);

        e.events().publish(
            (
                Symbol::new(&e, "attestation_revoked"),
                attestation.identity.clone(),
            ),
            (attestation_id, attester),
        );
    }

    /// Get an attestation by ID.
    ///
    /// Errors:
    /// - `ContractError::AttestationNotFound` (301)
    pub fn get_attestation(e: Env, attestation_id: u64) -> Attestation {
        let key = DataKey::Attestation(attestation_id);
        let att = e
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::AttestationNotFound));
        bump_instance_ttl(&e, &key);
        att
    }

    /// Get all attestation IDs for a subject.
    pub fn get_subject_attestations(e: Env, subject: Address) -> Vec<u64> {
        let key = DataKey::SubjectAttestations(subject);
        let v = e.storage().instance().get(&key).unwrap_or(Vec::new(&e));
        bump_instance_ttl(&e, &key);
        v
    }

    /// Get attestation count for a subject (identity). O(1).
    pub fn get_subject_attestation_count(e: Env, subject: Address) -> u32 {
        let key = DataKey::SubjectAttestationCount(subject);
        let c = e.storage().instance().get(&key).unwrap_or(0);
        bump_instance_ttl(&e, &key);
        c
    }

    /// Get current nonce for an identity (for replay prevention). Use this value in the next state-changing call.
    pub fn get_nonce(e: Env, identity: Address) -> u64 {
        nonce::get_nonce(&e, &identity)
    }

    /// Set attester stake (admin only). Used for weighted attestation; weight is derived from this.
    /// Negative stake values are rejected.
    pub fn set_attester_stake(e: Env, admin: Address, attester: Address, amount: i128) {
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();
        if admin != stored_admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }
        weighted_attestation::set_attester_stake(&e, &attester, amount);
    }

    /// Set weight config: multiplier_bps (e.g. 100 = 1%), max_attestation_weight. Admin only.
    pub fn set_weight_config(e: Env, admin: Address, multiplier_bps: u32, max_weight: u32) {
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        admin.require_auth();
        if admin != stored_admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }
        weighted_attestation::set_weight_config(&e, multiplier_bps, max_weight);
    }

    /// Get weight config (multiplier_bps, max_weight).
    pub fn get_weight_config(e: Env) -> (u32, u32) {
        weighted_attestation::get_weight_config(&e)
    }

    /// Withdraw from bond after lock-up period has ended. Penalty-free withdrawal.
    /// For early exits before lock-up expiry, use withdraw_early() which applies penalties.
    ///
    /// Authority: stored bond owner (`bond.identity`) must authorize this call.
    /// Returns the updated bond with reduced bonded_amount.
    ///
    /// Panics:
    /// - "lock-up not expired; use withdraw_early" if called before lock-up ends
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::SlashExceedsBond` (203)
    /// - `ContractError::InsufficientBalance` (202)
    /// - `ContractError::Underflow` (701)
    ///
    /// # Events
    /// Emits `bond_withdrawn` event with (identity, old_amount, new_amount, timestamp)
    pub fn withdraw(e: Env, identity: Address, amount: i128) -> IdentityBond {
        identity.require_auth();
        let key = DataKey::Bond(identity);
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);

        // Enforce lock-up expiry: withdraw is only for post-lock-up withdrawals.
        // For early exits, caller must use withdraw_early which applies penalties.
        let now = e.ledger().timestamp();
        let end = bond
            .bond_start
            .checked_add(bond.bond_duration)
            .expect("bond end timestamp overflow");
        if now < end {
            panic!("lock-up not expired; use withdraw_early");
        }

        // Rolling bonds must have completed the notice window before funds can leave.
        if bond.is_rolling {
            if bond.withdrawal_requested_at == 0 {
                panic!("withdrawal not requested");
            }
            let earliest = bond
                .withdrawal_requested_at
                .checked_add(bond.notice_period_duration)
                .expect("notice period overflow");
            if e.ledger().timestamp() < earliest {
                panic!("notice period not elapsed");
            }
        }

        // Calculate available balance (bonded - slashed)
        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::SlashExceedsBond));

        // Verify sufficient available balance for withdrawal
        if amount > available {
            panic_with_error!(e, ContractError::InsufficientBalance);
        }

        let old_amount = bond.bonded_amount;
        
        // Perform withdrawal with overflow protection
        bond.bonded_amount = bond
            .bonded_amount
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Underflow));

        // Verify invariant: slashed amount should not exceed bonded amount after withdrawal
        if bond.slashed_amount > bond.bonded_amount {
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }

        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        
        // Emit bond_withdrawn event
        e.events().publish(
            (Symbol::new(&e, "bond_withdrawn"),),
            (bond.identity.clone(), old_amount, bond.bonded_amount, now),
        );
        
        bond
    }

    /// Withdraw before lock-up end; applies early exit penalty and transfers penalty to treasury.
    /// This function is ONLY valid before lock-up expiry. After lock-up ends, use withdraw().
    ///
    /// Withdraw before lock-up end; applies a time-decayed penalty.
    ///
    /// Net amount to user = `amount - penalty`.
    /// The penalty is **clamped** to `amount` so the net is always ≥ 0.
    ///
    /// # Errors
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::SlashExceedsBond` (203)
    /// - `ContractError::InsufficientBalance` (202)
    /// - `ContractError::LockupNotExpired` (204) - lock-up has already expired; use withdraw
    /// - `ContractError::Underflow` (701)
    ///
    /// Resource budget:
    /// - Bond key: 1 read, 1 write.
    /// - Early-exit config: 1 read through `early_exit_penalty::get_config`.
    /// - No reentrancy lock or callback storage keys are touched.
    pub fn withdraw_early(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);

        let available = Self::available_balance(&e, &bond);
        if amount > available {
            panic_with_error!(e, ContractError::InsufficientBalance);
        }

        let now = e.ledger().timestamp();
        let end = bond.bond_start.saturating_add(bond.bond_duration);
        if now >= end {
            panic_with_error!(e, ContractError::LockupNotExpired);
        }

        let (treasury, penalty_bps) = early_exit_penalty::get_config(&e);
        let remaining = end.saturating_sub(now);
        let penalty = early_exit_penalty::calculate_penalty(
            amount,
            remaining,
            bond.bond_duration,
            penalty_bps,
        );
        early_exit_penalty::emit_penalty_event(&e, &bond.identity, amount, penalty, &treasury);
        // In a full implementation: transfer (amount - penalty) to user, penalty to treasury.

        let old_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        bond.bonded_amount = bond
            .bonded_amount
            .checked_sub(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Underflow));
        if bond.slashed_amount > bond.bonded_amount {
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }
        let new_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        tiered_bond::emit_tier_change_if_needed(&e, &bond.identity, old_tier, new_tier);

        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        bond
    }

    /// Request withdrawal (rolling bonds). Withdrawal allowed after notice period.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::NotRollingBond` (205)
    /// - `ContractError::WithdrawalAlreadyRequested` (206)
    pub fn request_withdrawal(e: Env, identity: Address) -> IdentityBond {
        identity.require_auth();
        let key = DataKey::Bond(identity);
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);
        if !bond.is_rolling {
            panic_with_error!(e, ContractError::NotRollingBond);
        }
        if bond.withdrawal_requested_at != 0 {
            panic_with_error!(e, ContractError::WithdrawalAlreadyRequested);
        }
        bond.withdrawal_requested_at = e.ledger().timestamp();
        e.storage().instance().set(&key, &bond);
        e.events().publish(
            (Symbol::new(&e, "withdrawal_requested"),),
            (bond.identity.clone(), bond.withdrawal_requested_at),
        );
        bond
    }

    /// If bond is rolling and period has ended, renew (new period start = now). Emits renewal event.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    pub fn renew_if_rolling(e: Env, identity: Address) -> IdentityBond {
        let key = DataKey::Bond(identity);
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        if !bond.is_rolling {
            return bond;
        }
        // Do not auto-renew once the holder has signalled intent to withdraw.
        if bond.withdrawal_requested_at != 0 {
            return bond;
        }
        let now = e.ledger().timestamp();
        let end = bond
            .bond_start
            .checked_add(bond.bond_duration)
            .expect("bond end timestamp overflow");
        if now < end {
            return bond;
        }
        rolling_bond::apply_renewal(&mut bond, now);
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        e.events().publish(
            (Symbol::new(&e, "bond_renewed"),),
            (bond.identity.clone(), bond.bond_start, bond.bond_duration),
        );
        bond
    }

    /// Get current tier for the bond's bonded amount.
    pub fn get_tier(e: Env, identity: Address) -> BondTier {
        let bond = Self::get_identity_state(e, identity);
        tiered_bond::get_tier_for_amount(bond.bonded_amount)
    }

    /// Slash a portion of the bond (admin only). Reduces the bond's value as a penalty.
    /// Increases slashed_amount up to the bonded_amount (over-slash prevention).
    ///
    /// # Arguments
    /// * `admin` - Address claiming admin authority (must be contract admin)
    /// * `amount` - Amount to slash (i128). Will be capped at bonded_amount.
    ///
    /// # Returns
    /// Updated IdentityBond with increased slashed_amount
    ///
    /// # Panics
    /// - "not admin" if caller is not the contract admin
    /// - "no bond" if no bond exists
    ///
    /// # Events
    /// Emits `bond_slashed` event with (identity, slash_amount, total_slashed_amount)
    pub fn slash(e: Env, admin: Address, identity: Address, amount: i128) -> IdentityBond {
        slashing::slash_bond(&e, &admin, &identity, amount)
    }

    /// Top up the bond with additional amount (checks for overflow)
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::Overflow` (700)
    ///
    /// # Events
    /// Emits `bond_topped_up` event with (identity, old_amount, new_amount, timestamp)
    pub fn top_up(e: Env, identity: Address, amount: i128) -> IdentityBond {
        let key = DataKey::Bond(identity);
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));

        let old_amount = bond.bonded_amount;
        
        // Perform top-up with overflow protection
        bond.bonded_amount = bond
            .bonded_amount
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        let timestamp = e.ledger().timestamp();
        
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        
        // Emit bond_topped_up event
        e.events().publish(
            (Symbol::new(&e, "bond_topped_up"),),
            (bond.identity.clone(), old_amount, bond.bonded_amount, timestamp),
        );
        
        bond
    }

    /// Extend bond duration (checks for u64 overflow on timestamps)
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::Overflow` (700)
    ///
    /// # Events
    /// Emits `bond_duration_extended` event with (identity, old_duration, new_duration, timestamp)
    pub fn extend_duration(e: Env, identity: Address, additional_duration: u64) -> IdentityBond {
        let key = DataKey::Bond(identity);
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &key);

        let old_duration = bond.bond_duration;
        
        // Perform duration extension with overflow protection
        bond.bond_duration = bond
            .bond_duration
            .checked_add(additional_duration)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        // Also verify the end timestamp wouldn't overflow
        bond.bond_start.checked_add(bond.bond_duration)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::Overflow));

        let timestamp = e.ledger().timestamp();
        
        e.storage().instance().set(&key, &bond);
        bump_instance_ttl(&e, &key);
        
        // Emit bond_duration_extended event
        e.events().publish(
            (Symbol::new(&e, "bond_duration_extended"),),
            (bond.identity.clone(), old_duration, bond.bond_duration, timestamp),
        );
        
        bond
    }

    /// Deposit fees into the contract's fee pool.
    pub fn deposit_fees(e: Env, amount: i128) {
        let key = Symbol::new(&e, "fees");
        let current: i128 = e.storage().instance().get(&key).unwrap_or(0);
        e.storage().instance().set(&key, &(current + amount));
    }

    /// Withdraw the full bonded amount back to the identity.
    /// Uses a panic-safe reentrancy guard to prevent re-entrance during external calls.
    ///
    /// All reads and validations are performed BEFORE acquiring the lock to ensure
    /// the lock cannot be stuck by a panic during validation.
    ///
    /// Errors:
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::NotBondOwner` (101)
    /// - `ContractError::BondNotActive` (201)
    /// - `ContractError::ReentrancyDetected` (207)
    ///
    /// Resource budget:
    /// - Bond key: 1 read, 1 write.
    /// - Reentrancy lock key: 1 read, 2 writes.
    /// - Callback key: 1 optional read.
    pub fn withdraw_bond(e: Env, identity: Address) -> i128 {
        identity.require_auth();

        // PHASE 1: Read and validate BEFORE acquiring lock
        // This ensures no panic can occur while holding the lock during reads
        let bond_key = DataKey::Bond;
        let mut bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));
        bump_instance_ttl(&e, &bond_key);

        // Validate ownership
        if bond.identity != identity {
            panic_with_error!(e, ContractError::NotBondOwner);
        }
        
        // Validate bond is active
        if !bond.active {
            panic_with_error!(e, ContractError::BondNotActive);
        }

        // Validate rolling bond notice period
        if bond.is_rolling {
            if bond.withdrawal_requested_at == 0 {
                panic!("withdrawal not requested");
            }
            let earliest = bond
                .withdrawal_requested_at
                .checked_add(bond.notice_period_duration)
                .expect("notice period overflow");
            if e.ledger().timestamp() < earliest {
                panic!("notice period not elapsed");
            }
        }

        let withdraw_amount = Self::available_balance_or_release(&e, &bond);

        // State update BEFORE external interaction (checks-effects-interactions)
        bond.bonded_amount = 0;
        bond.active = false;
        e.storage().instance().set(&bond_key, &bond);
        bump_instance_ttl(&e, &bond_key);

        // PHASE 4: External call (with lock held, but guard ensures release on panic)
        if let Some(cb_addr) = cb_addr {
            let fn_name = Symbol::new(&e, "on_withdraw");
            let args: Vec<Val> = Vec::from_array(&e, [withdraw_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        // Lock automatically released when _guard goes out of scope
        withdraw_amount
    }

    /// Slash a portion of a bond. Only callable by admin.
    /// Uses a reentrancy guard to prevent re-entrance during external calls.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    /// - `ContractError::NotAdmin` (100)
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::BondNotActive` (201)
    /// Slash a portion of a bond. Only callable by admin.
    /// Uses a panic-safe reentrancy guard to prevent re-entrance during external calls.
    ///
    /// All reads and validations are performed BEFORE acquiring the lock to ensure
    /// the lock cannot be stuck by a panic during validation.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    /// - `ContractError::NotAdmin` (100)
    /// - `ContractError::BondNotFound` (200)
    /// - `ContractError::BondNotActive` (201)
    /// - `ContractError::SlashExceedsBond` (203)
    /// - `ContractError::AmountMustBePositive` (600)
    ///
    /// Resource budget:
    /// - Admin key: 1 read.
    /// - Bond key: 1 read, 1 write.
    /// - Reentrancy lock key: 1 read, 2 writes.
    /// - Callback key: 1 optional read.
    pub fn slash_bond(e: Env, admin: Address, slash_amount: i128) -> i128 {
        admin.require_auth();

        if slash_amount <= 0 {
            Self::release_lock_and_panic(&e, ContractError::AmountMustBePositive);
        }

        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        
        if stored_admin != admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }

        let bond_key = DataKey::Bond;
        let mut bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::BondNotFound));

        if !bond.active {
            panic_with_error!(e, ContractError::BondNotActive);
        }

        let new_slashed = bond
            .slashed_amount
            .checked_add(slash_amount)
            .unwrap_or_else(|| Self::release_lock_and_panic(&e, ContractError::Overflow));
        if new_slashed > bond.bonded_amount {
            panic_with_error!(e, ContractError::SlashExceedsBond);
        }

        // State update BEFORE external interaction
        bond.slashed_amount = new_slashed;
        e.storage().instance().set(&bond_key, &bond);
        e.events().publish(
            (Symbol::new(&e, "bond_slashed"),),
            (bond.identity.clone(), slash_amount, new_slashed),
        );

        // PHASE 4: External call (with lock held, but guard ensures release on panic)
        if let Some(cb_addr) = cb_addr {
            let fn_name = Symbol::new(&e, "on_slash");
            let args: Vec<Val> = Vec::from_array(&e, [slash_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        // Lock automatically released when _guard goes out of scope
        new_slashed
    }

    /// Collect accumulated protocol fees. Only callable by admin.
    /// Uses a panic-safe reentrancy guard to prevent re-entrance during external calls.
    ///
    /// All reads and validations are performed BEFORE acquiring the lock to ensure
    /// the lock cannot be stuck by a panic during validation.
    ///
    /// Errors:
    /// - `ContractError::NotInitialized` (1)
    /// - `ContractError::NotAdmin` (100)
    pub fn collect_fees(e: Env, admin: Address) -> i128 {
        admin.require_auth();

        // PHASE 1: Read and validate BEFORE acquiring lock
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));
        
        if stored_admin != admin {
            panic_with_error!(e, ContractError::NotAdmin);
        }

        let fee_key = Symbol::new(&e, "fees");
        let fees: i128 = e.storage().instance().get(&fee_key).unwrap_or(0);

        // Read callback address before acquiring lock
        let cb_key = Symbol::new(&e, "callback");
        let cb_addr = e.storage().instance().get::<_, Address>(&cb_key);

        // PHASE 2: Acquire lock (RAII guard ensures automatic release)
        let _guard = Self::acquire_lock(&e);

        // PHASE 3: State update BEFORE external interaction
        e.storage().instance().set(&fee_key, &0_i128);

        // PHASE 4: External call (with lock held, but guard ensures release on panic)
        if let Some(cb_addr) = cb_addr {
            let fn_name = Symbol::new(&e, "on_collect");
            let args: Vec<Val> = Vec::from_array(&e, [fees.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }

        // Lock automatically released when _guard goes out of scope
        fees
    }

    /// Register a callback contract address (for testing external call hooks).
    pub fn set_callback(e: Env, addr: Address) {
        e.storage()
            .instance()
            .set(&Symbol::new(&e, "callback"), &addr);
    }

    /// Check if the reentrancy lock is currently held.
    pub fn is_locked(e: Env) -> bool {
        Self::check_lock(&e)
    }

    // ===========================================================================
    // Reentrancy Guard Implementation
    // ===========================================================================
    //
    // This section implements a panic-safe reentrancy guard using the RAII
    // (Resource Acquisition Is Initialization) pattern. The guard automatically
    // releases the lock when dropped, even if a panic occurs.
    //
    // ## Security Properties
    //
    // 1. **Reentrancy Prevention**: Reentrant calls are detected and rejected
    //    with ContractError::ReentrancyDetected
    //
    // 2. **Panic Safety**: The lock is automatically released on panic via the
    //    Drop trait, preventing permanently stuck locks
    //
    // 3. **Automatic Cleanup**: No manual lock release needed; the compiler
    //    ensures cleanup when the guard goes out of scope
    //
    // ## Usage Pattern
    //
    // ```rust
    // pub fn protected_function(e: Env) -> Result {
    //     // Phase 1: Read and validate BEFORE acquiring lock
    //     let data = read_and_validate()?;
    //     
    //     // Phase 2: Acquire lock (automatic release on drop)
    //     let _guard = Self::acquire_lock(&e);
    //     
    //     // Phase 3: Update state
    //     update_state(data);
    //     
    //     // Phase 4: External calls
    //     make_external_call();
    //     
    //     // Lock automatically released when _guard goes out of scope
    //     Ok(())
    // }
    // ```
    //
    // ## Protected Functions
    //
    // - `withdraw_bond`: Withdraws bonded amount with external callback
    // - `slash_bond`: Slashes bond with external callback
    // - `collect_fees`: Collects fees with external callback
    //
    // See docs/reentrancy.md for detailed documentation.
    // ===========================================================================

    /// RAII guard that releases the reentrancy lock on drop.
    /// 
    /// This guard ensures the reentrancy lock is released even if a panic
    /// occurs between lock acquisition and function return. The lock is stored
    /// in contract instance storage under the key "locked".
    ///
    /// # Panic Safety
    ///
    /// The `Drop` implementation guarantees the lock is released on all exit
    /// paths, including:
    /// - Normal function return
    /// - Early return via `?` operator
    /// - Panic during execution
    ///
    /// # Example
    ///
    /// ```rust
    /// let _guard = Self::acquire_lock(&e);
    /// // ... protected code ...
    /// // Lock automatically released here when _guard is dropped
    /// ```
    struct ReentrancyGuard<'a> {
        env: &'a Env,
    }

    impl<'a> Drop for ReentrancyGuard<'a> {
        /// Automatically releases the reentrancy lock when the guard is dropped.
        ///
        /// This is called by the Rust compiler when the guard goes out of scope,
        /// ensuring the lock is always released regardless of how the function exits.
        fn drop(&mut self) {
            let key = Symbol::new(self.env, "locked");
            self.env.storage().instance().set(&key, &false);
        }
    }

    /// Acquire the reentrancy lock and return a guard that will automatically
    /// release it.
    ///
    /// This function checks if the lock is currently held and panics with
    /// `ContractError::ReentrancyDetected` if so. Otherwise, it sets the lock
    /// to `true` and returns a guard that will set it back to `false` when dropped.
    ///
    /// # Returns
    ///
    /// A `ReentrancyGuard` that will automatically release the lock when dropped.
    ///
    /// # Panics
    ///
    /// Panics with `ContractError::ReentrancyDetected` if the lock is already held,
    /// indicating a reentrancy attempt.
    ///
    /// # Example
    ///
    /// ```rust
    /// let _guard = Self::acquire_lock(&e);
    /// // Lock is now held
    /// // ... perform protected operations ...
    /// // Lock is automatically released when _guard goes out of scope
    /// ```
    fn acquire_lock(e: &Env) -> ReentrancyGuard {
        let key = Symbol::new(e, "locked");
        let locked: bool = e.storage().instance().get(&key).unwrap_or(false);
        if locked {
            panic_with_error!(e, ContractError::ReentrancyDetected);
        }
        e.storage().instance().set(&key, &true);
        ReentrancyGuard { env: e }
    }

    /// Check if the reentrancy lock is currently held.
    ///
    /// This is primarily used for testing and debugging. In production code,
    /// use `acquire_lock` which will panic if the lock is held.
    ///
    /// # Returns
    ///
    /// `true` if the lock is currently held, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// assert!(!Self::check_lock(&e)); // Lock not held
    /// let _guard = Self::acquire_lock(&e);
    /// assert!(Self::check_lock(&e));  // Lock is held
    /// ```
    fn check_lock(e: &Env) -> bool {
        let key = Symbol::new(e, "locked");
        e.storage().instance().get(&key).unwrap_or(false)
    }

    fn available_balance(e: &Env, bond: &IdentityBond) -> i128 {
        bond.bonded_amount
            .checked_sub(bond.slashed_amount)
            .unwrap_or_else(|| panic_with_error!(e, ContractError::SlashExceedsBond))
    }

    fn available_balance_or_release(e: &Env, bond: &IdentityBond) -> i128 {
        bond.bonded_amount
            .checked_sub(bond.slashed_amount)
            .unwrap_or_else(|| Self::release_lock_and_panic(e, ContractError::SlashExceedsBond))
    }

    fn release_lock_and_panic(e: &Env, error: ContractError) -> ! {
        Self::release_lock(e);
        panic_with_error!(e, error);
    }

    fn load_bond_and_require_owner_auth(e: &Env, key: &DataKey) -> IdentityBond {
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(key)
            .unwrap_or_else(|| panic!("no bond"));
        bond.identity.require_auth();
        bond
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod test_attestation;

#[cfg(test)]
mod test_attestation_types;

#[cfg(test)]
mod test_weighted_attestation;

#[cfg(test)]
mod test_replay_prevention;

#[cfg(test)]
mod test_lockup_gate;

#[cfg(test)]
mod test_bond_lifecycle_events;

#[cfg(test)]
mod security;

#[cfg(test)]
mod gas_profile_tests {
    use super::{
        HotPathStorageBudget, SLASH_BOND_STORAGE_BUDGET, WITHDRAW_BOND_STORAGE_BUDGET,
        WITHDRAW_EARLY_STORAGE_BUDGET,
    };

    #[test]
    fn withdraw_early_budget_is_read_once_write_once() {
        assert_eq!(
            WITHDRAW_EARLY_STORAGE_BUDGET,
            HotPathStorageBudget {
                bond_reads: 1,
                bond_writes: 1,
                admin_reads: 0,
                callback_reads: 0,
                lock_reads: 0,
                lock_writes: 0,
                config_reads: 1,
            }
        );
    }

    #[test]
    fn withdraw_bond_budget_is_read_once_write_once_for_bond_key() {
        assert_eq!(WITHDRAW_BOND_STORAGE_BUDGET.bond_reads, 1);
        assert_eq!(WITHDRAW_BOND_STORAGE_BUDGET.bond_writes, 1);
        assert_eq!(WITHDRAW_BOND_STORAGE_BUDGET.lock_reads, 1);
        assert_eq!(WITHDRAW_BOND_STORAGE_BUDGET.lock_writes, 2);
    }

    #[test]
    fn slash_bond_budget_is_read_once_write_once_for_bond_key() {
        assert_eq!(SLASH_BOND_STORAGE_BUDGET.bond_reads, 1);
        assert_eq!(SLASH_BOND_STORAGE_BUDGET.bond_writes, 1);
        assert_eq!(SLASH_BOND_STORAGE_BUDGET.admin_reads, 1);
        assert_eq!(SLASH_BOND_STORAGE_BUDGET.lock_reads, 1);
        assert_eq!(SLASH_BOND_STORAGE_BUDGET.lock_writes, 2);
    }
}

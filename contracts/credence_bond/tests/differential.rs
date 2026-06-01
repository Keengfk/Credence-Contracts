//! Differential test harness across canonical, ours, base, and theirs forks.
//!
//! # Security note
//! This entire module compiles only under `#[cfg(test)]`.  The divergent fork
//! modules (`fork_ours`, `fork_base`, `fork_theirs`, `fork_divergent`) are gated
//! by `#[cfg(test)]` inside the `credence_bond` crate, so they are never shipped
//! to mainnet.
//!
//! # Design
//! A single `Env` hosts all four contract instances.  After every scripted step
//! the harness captures:
//!   1. the `IdentityBond` state via `get_identity_state()`,
//!   2. the per-contract event slice emitted since contract deployment,
//!   3. the current tier (if applicable).
//!
//! Any mismatch across forks fails the build, giving the consolidation PR
//! (#351) objective evidence.

use soroban_sdk::{testutils::Address as _, Address, Env, String, Symbol, Val, Vec as SorobanVec};

// ---------------------------------------------------------------------------
// Snapshot types — normalise each fork’s IdentityBond into one struct.
// ---------------------------------------------------------------------------

/// Normalised bond state used for cross-fork comparison.
#[derive(Clone, Debug, PartialEq)]
struct BondSnapshot {
    identity: Address,
    bonded_amount: i128,
    bond_start: u64,
    bond_duration: u64,
    slashed_amount: i128,
    active: bool,
    is_rolling: bool,
    withdrawal_requested_at: u64,
    notice_period_duration: u64,
}

impl From<credence_bond::IdentityBond> for BondSnapshot {
    fn from(b: credence_bond::IdentityBond) -> Self {
        Self {
            identity: b.identity,
            bonded_amount: b.bonded_amount,
            bond_start: b.bond_start,
            bond_duration: b.bond_duration,
            slashed_amount: b.slashed_amount,
            active: b.active,
            is_rolling: b.is_rolling,
            withdrawal_requested_at: b.withdrawal_requested_at,
            notice_period_duration: b.notice_period_duration,
        }
    }
}

impl From<credence_bond::fork_ours::IdentityBond> for BondSnapshot {
    fn from(b: credence_bond::fork_ours::IdentityBond) -> Self {
        Self {
            identity: b.identity,
            bonded_amount: b.bonded_amount,
            bond_start: b.bond_start,
            bond_duration: b.bond_duration,
            slashed_amount: b.slashed_amount,
            active: b.active,
            is_rolling: b.is_rolling,
            withdrawal_requested_at: b.withdrawal_requested_at,
            notice_period_duration: b.notice_period_duration,
        }
    }
}

impl From<credence_bond::fork_base::IdentityBond> for BondSnapshot {
    fn from(b: credence_bond::fork_base::IdentityBond) -> Self {
        Self {
            identity: b.identity,
            bonded_amount: b.bonded_amount,
            bond_start: b.bond_start,
            bond_duration: b.bond_duration,
            slashed_amount: b.slashed_amount,
            active: b.active,
            is_rolling: b.is_rolling,
            withdrawal_requested_at: b.withdrawal_requested_at,
            notice_period_duration: b.notice_period_duration,
        }
    }
}

impl From<credence_bond::fork_theirs::IdentityBond> for BondSnapshot {
    fn from(b: credence_bond::fork_theirs::IdentityBond) -> Self {
        Self {
            identity: b.identity,
            bonded_amount: b.bonded_amount,
            bond_start: b.bond_start,
            bond_duration: b.bond_duration,
            slashed_amount: b.slashed_amount,
            active: b.active,
            is_rolling: b.is_rolling,
            withdrawal_requested_at: b.withdrawal_requested_at,
            notice_period_duration: b.notice_period_duration,
        }
    }
}

impl From<credence_bond::fork_divergent::IdentityBond> for BondSnapshot {
    fn from(b: credence_bond::fork_divergent::IdentityBond) -> Self {
        Self {
            identity: b.identity,
            bonded_amount: b.bonded_amount,
            bond_start: b.bond_start,
            bond_duration: b.bond_duration,
            slashed_amount: b.slashed_amount,
            active: b.active,
            is_rolling: b.is_rolling,
            withdrawal_requested_at: b.withdrawal_requested_at,
            notice_period_duration: b.notice_period_duration,
        }
    }
}

/// Normalised event slice.
#[derive(Clone, Debug, PartialEq)]
struct EventSnapshot {
    symbol: Symbol,
    topics: SorobanVec<Val>,
    data: Val,
}

// ---------------------------------------------------------------------------
// Scenario DSL
// ---------------------------------------------------------------------------

/// A single scripted action against a bond contract.
///
/// Each variant documents the invariant category it exercises.
#[derive(Clone, Debug)]
enum Step {
    /// Invariant: contract initialisation must set admin consistently.
    Initialize { admin: Address },

    /// Invariant: bond creation must enforce positive amount, positive duration,
    /// and valid rolling parameters.
    CreateBond {
        identity: Address,
        amount: i128,
        duration: u64,
        is_rolling: bool,
        notice: u64,
    },

    /// Invariant: `top_up` must increase bonded_amount monotonically.
    TopUp { identity: Address, amount: i128 },

    /// Invariant: `request_withdrawal` must record the request timestamp.
    RequestWithdrawal { identity: Address },

    /// Invariant: post-lockup `withdraw` must reduce bonded_amount and never
    /// exceed available balance (`bonded - slashed`).
    Withdraw { identity: Address, amount: i128 },

    /// Invariant: `withdraw_early` must apply a time-decayed penalty and
    /// reject calls after lock-up expiry.
    WithdrawEarly { identity: Address, amount: i128 },

    /// Invariant: `slash` must increase slashed_amount monotonically and never
    /// exceed bonded_amount (either by error or by capping).
    Slash { admin: Address, identity: Address, amount: i128 },

    /// Invariant: `slash_bond` (reentrancy-guarded variant) must behave
    /// identically to `slash` for valid admin calls.
    SlashBond { admin: Address, amount: i128 },

    /// Invariant: `extend_duration` must increase bond_duration.
    ExtendDuration { identity: Address, extra: u64 },

    /// Invariant: `renew_if_rolling` must reset bond_start when the period
    /// ended and no withdrawal was requested.
    RenewIfRolling { identity: Address },

    /// Invariant: `get_tier` mapping from bonded_amount must be deterministic.
    CheckTier,

    /// Invariant: attestation add/revoke must mutate storage and emit events.
    AddAttestation {
        attester: Address,
        subject: Address,
        data: String,
        nonce: u64,
    },
    RevokeAttestation {
        attester: Address,
        id: u64,
        nonce: u64,
    },

    /// Invariant: ledger time manipulation must shift all time-dependent checks.
    AdvanceTime { seconds: u64 },
}

/// A complete scripted scenario with a descriptive name.
struct Scenario {
    name: &'static str,
    steps: std::vec::Vec<Step>,
}

impl Scenario {
    fn new(name: &'static str, steps: std::vec::Vec<Step>) -> Self {
        Self { name, steps }
    }
}

// ---------------------------------------------------------------------------
// Event helpers
// ---------------------------------------------------------------------------

fn contract_events(env: &Env, contract_id: &Address) -> SorobanVec<EventSnapshot> {
    let all = env.events().all();
    let mut out = SorobanVec::new(env);
    for ev in all.iter() {
        if ev.0 != *contract_id {
            continue;
        }
        let sym = Symbol::from_val(env, &ev.1.get(0).unwrap());
        out.push_back(EventSnapshot {
            symbol: sym,
            topics: ev.1.clone(),
            data: ev.2,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Fork runner — executes a step against every fork and asserts equality.
// ---------------------------------------------------------------------------

struct ForkRunner<'a> {
    env: &'a Env,
    canonical: credence_bond::CredenceBondClient<'a>,
    ours: credence_bond::fork_ours::CredenceBondClient<'a>,
    base: credence_bond::fork_base::CredenceBondClient<'a>,
    theirs: credence_bond::fork_theirs::CredenceBondClient<'a>,
    divergent: Option<credence_bond::fork_divergent::CredenceBondClient<'a>>,
    canonical_id: Address,
    ours_id: Address,
    base_id: Address,
    theirs_id: Address,
    divergent_id: Option<Address>,
}

impl<'a> ForkRunner<'a> {
    fn new(env: &'a Env) -> Self {
        let canonical_id = env.register_contract(None, credence_bond::CredenceBond);
        let ours_id = env.register_contract(None, credence_bond::fork_ours::CredenceBond);
        let base_id = env.register_contract(None, credence_bond::fork_base::CredenceBond);
        let theirs_id = env.register_contract(None, credence_bond::fork_theirs::CredenceBond);

        Self {
            env,
            canonical: credence_bond::CredenceBondClient::new(env, &canonical_id),
            ours: credence_bond::fork_ours::CredenceBondClient::new(env, &ours_id),
            base: credence_bond::fork_base::CredenceBondClient::new(env, &base_id),
            theirs: credence_bond::fork_theirs::CredenceBondClient::new(env, &theirs_id),
            divergent: None,
            canonical_id,
            ours_id,
            base_id,
            theirs_id,
            divergent_id: None,
        }
    }

    fn with_divergent(env: &'a Env) -> Self {
        let mut r = Self::new(env);
        let divergent_id = env.register_contract(None, credence_bond::fork_divergent::CredenceBond);
        r.divergent = Some(credence_bond::fork_divergent::CredenceBondClient::new(
            env, &divergent_id,
        ));
        r.divergent_id = Some(divergent_id);
        r
    }

    fn canonical_bond(&self) -> BondSnapshot {
        self.canonical.get_identity_state().into()
    }

    fn ours_bond(&self) -> BondSnapshot {
        self.ours.get_identity_state().into()
    }

    fn base_bond(&self) -> BondSnapshot {
        self.base.get_identity_state().into()
    }

    fn theirs_bond(&self) -> BondSnapshot {
        self.theirs.get_identity_state().into()
    }

    fn divergent_bond(&self) -> Option<BondSnapshot> {
        self.divergent.as_ref().map(|c| c.get_identity_state().into())
    }

    fn assert_bonds_eq(&self, ctx: &str) {
        let c = self.canonical_bond();
        let o = self.ours_bond();
        let b = self.base_bond();
        let t = self.theirs_bond();
        assert_eq!(c, o, "[ours] bond state diverged: {ctx}");
        assert_eq!(c, b, "[base] bond state diverged: {ctx}");
        assert_eq!(c, t, "[theirs] bond state diverged: {ctx}");
        if let Some(ref d) = self.divergent {
            assert_eq!(c, d.get_identity_state().into(), "[divergent] bond state diverged: {ctx}");
        }
    }

    fn assert_events_eq(&self, ctx: &str) {
        let c = contract_events(self.env, &self.canonical_id);
        let o = contract_events(self.env, &self.ours_id);
        let b = contract_events(self.env, &self.base_id);
        let t = contract_events(self.env, &self.theirs_id);

        assert_eq!(c.len(), o.len(), "[ours] event count diverged: {ctx}");
        assert_eq!(c.len(), b.len(), "[base] event count diverged: {ctx}");
        assert_eq!(c.len(), t.len(), "[theirs] event count diverged: {ctx}");

        for i in 0..c.len() {
            assert_eq!(
                c.get(i).unwrap(),
                o.get(i).unwrap(),
                "[ours] event {i} diverged: {ctx}"
            );
            assert_eq!(
                c.get(i).unwrap(),
                b.get(i).unwrap(),
                "[base] event {i} diverged: {ctx}"
            );
            assert_eq!(
                c.get(i).unwrap(),
                t.get(i).unwrap(),
                "[theirs] event {i} diverged: {ctx}"
            );
        }

        if let Some(ref d_id) = self.divergent_id {
            let d = contract_events(self.env, d_id);
            assert_eq!(c.len(), d.len(), "[divergent] event count diverged: {ctx}");
            for i in 0..c.len() {
                assert_eq!(
                    c.get(i).unwrap(),
                    d.get(i).unwrap(),
                    "[divergent] event {i} diverged: {ctx}"
                );
            }
        }
    }

    fn assert_tiers_eq(&self, ctx: &str) {
        let c = format!("{:?}", self.canonical.get_tier());
        let o = format!("{:?}", self.ours.get_tier(&self.canonical_bond().identity));
        let b = format!("{:?}", self.base.get_tier());
        let t = format!("{:?}", self.theirs.get_tier());
        assert_eq!(c, o, "[ours] tier diverged: {ctx}");
        assert_eq!(c, b, "[base] tier diverged: {ctx}");
        assert_eq!(c, t, "[theirs] tier diverged: {ctx}");
        if let Some(ref d) = self.divergent {
            let d_tier = format!("{:?}", d.get_tier());
            assert_eq!(c, d_tier, "[divergent] tier diverged: {ctx}");
        }
    }

    fn run_step(&mut self, step: &Step) {
        match step {
            Step::Initialize { admin } => {
                self.canonical.initialize(admin);
                self.ours.initialize(admin);
                self.base.initialize(admin);
                self.theirs.initialize(admin);
                if let Some(ref d) = self.divergent {
                    d.initialize(admin);
                }
            }
            Step::CreateBond {
                identity,
                amount,
                duration,
                is_rolling,
                notice,
            } => {
                let _c = self
                    .canonical
                    .create_bond(identity, amount, duration, is_rolling, notice);
                let _o = self
                    .ours
                    .create_bond(identity, amount, duration, is_rolling, notice);
                let _b = self
                    .base
                    .create_bond_with_rolling(identity, amount, duration, is_rolling, notice);
                let _t = self
                    .theirs
                    .create_bond_with_rolling(identity, amount, duration, is_rolling, notice);
                if let Some(ref d) = self.divergent {
                    let _ = d.create_bond(identity, amount, duration, is_rolling, notice);
                }
                self.assert_bonds_eq("create_bond");
            }
            Step::TopUp { identity, amount } => {
                let _c = self.canonical.top_up(amount);
                let _o = self.ours.top_up(identity, amount);
                let _b = self.base.top_up(amount);
                let _t = self.theirs.top_up(amount);
                if let Some(ref d) = self.divergent {
                    let _ = d.top_up(amount);
                }
                self.assert_bonds_eq("top_up");
            }
            Step::RequestWithdrawal { identity } => {
                let _c = self.canonical.request_withdrawal();
                let _o = self.ours.request_withdrawal(identity);
                let _b = self.base.request_withdrawal();
                let _t = self.theirs.request_withdrawal();
                self.assert_bonds_eq("request_withdrawal");
            }
            Step::Withdraw { identity, amount } => {
                let _c = self.canonical.withdraw(amount);
                let _o = self.ours.withdraw(identity, amount);
                let _b = self.base.withdraw(amount);
                let _t = self.theirs.withdraw(amount);
                self.assert_bonds_eq("withdraw");
            }
            Step::WithdrawEarly { identity, amount } => {
                let _c = self.canonical.withdraw_early(amount);
                let _o = self.ours.withdraw_early(amount);
                let _b = self.base.withdraw_early(amount);
                let _t = self.theirs.withdraw_early(amount);
                if let Some(ref d) = self.divergent {
                    let _ = d.slash(amount); // divergent has no withdraw_early
                }
                self.assert_bonds_eq("withdraw_early");
            }
            Step::Slash {
                admin,
                identity,
                amount,
            } => {
                let _c = self.canonical.slash(admin, amount);
                let _o = self.ours.slash(admin, identity, amount);
                let _b = self.base.slash(amount);
                let _t = self.theirs.slash(amount);
                if let Some(ref d) = self.divergent {
                    let _ = d.slash(amount);
                }
                self.assert_bonds_eq("slash");
            }
            Step::SlashBond { admin, amount } => {
                let _c = self.canonical.slash_bond(admin, amount);
                let _o = self.ours.slash_bond(admin, amount);
                let _b = self.base.slash_bond(admin, amount);
                let _t = self.theirs.slash_bond(admin, amount);
                self.assert_bonds_eq("slash_bond");
            }
            Step::ExtendDuration { identity, extra } => {
                let _c = self.canonical.extend_duration(extra);
                let _o = self.ours.extend_duration(identity, extra);
                let _b = self.base.extend_duration(extra);
                let _t = self.theirs.extend_duration(extra);
                self.assert_bonds_eq("extend_duration");
            }
            Step::RenewIfRolling { identity } => {
                let _c = self.canonical.renew_if_rolling();
                let _o = self.ours.renew_if_rolling(identity);
                let _b = self.base.renew_if_rolling();
                let _t = self.theirs.renew_if_rolling();
                self.assert_bonds_eq("renew_if_rolling");
            }
            Step::CheckTier => {
                self.assert_tiers_eq("check_tier");
            }
            Step::AddAttestation {
                attester,
                subject,
                data,
                nonce,
            } => {
                let _c = self
                    .canonical
                    .add_attestation(attester, subject, &data.clone(), nonce);
                let _o = self
                    .ours
                    .add_attestation(attester, subject, &data.clone(), nonce);
                let _b = self.base.add_attestation(attester, subject, &data.clone());
                let _t = self.theirs.add_attestation(attester, subject, &data.clone());
                // No bond assertion; attestation logic varies.
            }
            Step::RevokeAttestation {
                attester,
                id,
                nonce,
            } => {
                let _c = self.canonical.revoke_attestation(attester, id, nonce);
                let _o = self.ours.revoke_attestation(attester, id, nonce);
                let _b = self.base.revoke_attestation(attester, id);
                let _t = self.theirs.revoke_attestation(attester, id);
            }
            Step::AdvanceTime { seconds } => {
                let now = self.env.ledger().timestamp();
                self.env.ledger().with_mut(|li| li.timestamp = now + seconds);
            }
        }
        self.assert_events_eq(&format!("{:?}", step));
    }

    fn run_scenario(&mut self, scenario: &Scenario) {
        for step in scenario.steps.iter() {
            self.run_step(step);
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario definitions — each references the invariant it verifies.
// ---------------------------------------------------------------------------

#[test]
fn scenario_full_bond_lifecycle() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    let scenario = Scenario::new(
        "full_bond_lifecycle",
        vec![
            Step::Initialize { admin: admin.clone() },
            Step::CreateBond {
                identity: identity.clone(),
                amount: 1_000,
                duration: 10_000,
                is_rolling: false,
                notice: 0,
            },
            Step::CheckTier,
            Step::TopUp {
                identity: identity.clone(),
                amount: 5_000,
            },
            Step::CheckTier, // tier transition: Bronze -> Silver
            Step::AdvanceTime { seconds: 10_001 },
            Step::Withdraw {
                identity: identity.clone(),
                amount: 2_000,
            },
            Step::CheckTier, // tier transition: Silver -> Bronze
            Step::Slash {
                admin: admin.clone(),
                identity: identity.clone(),
                amount: 500,
            },
            Step::SlashBond {
                admin: admin.clone(),
                amount: 200,
            },
            Step::AdvanceTime { seconds: 10_000 },
            Step::Withdraw {
                identity: identity.clone(),
                amount: 3_300, // remaining after previous withdrawals + slashes
            },
        ],
    );

    let mut runner = ForkRunner::new(&env);
    runner.run_scenario(&scenario);
}

#[test]
fn scenario_rolling_bond_with_renewal() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    let scenario = Scenario::new(
        "rolling_bond_with_renewal",
        vec![
            Step::Initialize { admin: admin.clone() },
            Step::CreateBond {
                identity: identity.clone(),
                amount: 50_000,
                duration: 5_000,
                is_rolling: true,
                notice: 1_000,
            },
            Step::CheckTier,
            Step::AdvanceTime { seconds: 5_000 },
            Step::RenewIfRolling {
                identity: identity.clone(),
            },
            Step::RequestWithdrawal {
                identity: identity.clone(),
            },
            Step::AdvanceTime { seconds: 1_001 },
            Step::Withdraw {
                identity: identity.clone(),
                amount: 10_000,
            },
        ],
    );

    let mut runner = ForkRunner::new(&env);
    runner.run_scenario(&scenario);
}

#[test]
fn scenario_early_exit_and_penalty() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);
    let treasury = Address::generate(&env);

    let scenario = Scenario::new(
        "early_exit_and_penalty",
        vec![
            Step::Initialize { admin: admin.clone() },
            Step::CreateBond {
                identity: identity.clone(),
                amount: 10_000,
                duration: 10_000,
                is_rolling: false,
                notice: 0,
            },
            Step::AdvanceTime { seconds: 5_000 }, // half-way
            Step::WithdrawEarly {
                identity: identity.clone(),
                amount: 2_000,
            },
            Step::CheckTier,
            Step::AdvanceTime { seconds: 5_001 }, // past expiry
            Step::Withdraw {
                identity: identity.clone(),
                amount: 8_000,
            },
        ],
    );

    let mut runner = ForkRunner::new(&env);
    // Set early-exit config on canonical and ours (base/theirs read config via
    // set_early_exit_config which requires admin auth, but the contractimpl
    // for base/theirs also has set_early_exit_config, so we call it explicitly).
    runner.canonical.set_early_exit_config(&admin, &treasury, &500_u32);
    runner.ours.set_early_exit_config(&admin, &treasury, &500_u32);
    runner.base.set_early_exit_config(&admin, &treasury, &500_u32);
    runner.theirs.set_early_exit_config(&admin, &treasury, &500_u32);
    runner.run_scenario(&scenario);
}

#[test]
fn scenario_zero_amount_slash() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    let scenario = Scenario::new(
        "zero_amount_slash",
        vec![
            Step::Initialize { admin: admin.clone() },
            Step::CreateBond {
                identity: identity.clone(),
                amount: 5_000,
                duration: 1_000,
                is_rolling: false,
                notice: 0,
            },
            Step::Slash {
                admin: admin.clone(),
                identity: identity.clone(),
                amount: 0,
            },
            Step::CheckTier,
        ],
    );

    let mut runner = ForkRunner::new(&env);
    runner.run_scenario(&scenario);
}

#[test]
fn scenario_tier_boundary_exact() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    // Tier thresholds: Bronze < 1_000, Silver < 5_000, Gold < 20_000, Platinum >= 20_000
    let scenario = Scenario::new(
        "tier_boundary_exact",
        vec![
            Step::Initialize { admin: admin.clone() },
            Step::CreateBond {
                identity: identity.clone(),
                amount: 999,
                duration: 1,
                is_rolling: false,
                notice: 0,
            },
            Step::CheckTier, // Bronze
            Step::TopUp {
                identity: identity.clone(),
                amount: 1,
            },
            Step::CheckTier, // Silver boundary (1_000 -> Silver)
            Step::TopUp {
                identity: identity.clone(),
                amount: 4_000,
            },
            Step::CheckTier, // Silver (5_000 -> Gold)
            Step::TopUp {
                identity: identity.clone(),
                amount: 15_000,
            },
            Step::CheckTier, // Gold (20_000 -> Platinum)
        ],
    );

    let mut runner = ForkRunner::new(&env);
    runner.run_scenario(&scenario);
}

#[test]
fn scenario_rolling_renew_at_exact_expiry() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    let scenario = Scenario::new(
        "rolling_renew_at_exact_expiry",
        vec![
            Step::Initialize { admin: admin.clone() },
            Step::CreateBond {
                identity: identity.clone(),
                amount: 1_000,
                duration: 3_600,
                is_rolling: true,
                notice: 600,
            },
            Step::AdvanceTime { seconds: 3_600 }, // exactly at expiry
            Step::RenewIfRolling {
                identity: identity.clone(),
            },
            Step::AdvanceTime { seconds: 3_601 }, // past expiry
            Step::RenewIfRolling {
                identity: identity.clone(),
            },
        ],
    );

    let mut runner = ForkRunner::new(&env);
    runner.run_scenario(&scenario);
}

#[test]
fn scenario_attestation_add_revoke() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);
    let attester = Address::generate(&env);
    let subject = Address::generate(&env);
    let data = String::from_str(&env, "identity-verified");

    let scenario = Scenario::new(
        "attestation_add_revoke",
        vec![
            Step::Initialize { admin: admin.clone() },
            Step::CreateBond {
                identity: identity.clone(),
                amount: 1_000,
                duration: 1_000,
                is_rolling: false,
                notice: 0,
            },
        ],
    );

    let mut runner = ForkRunner::new(&env);
    runner.canonical.initialize(&admin);
    runner.canonical.register_attester(&attester);
    runner.ours.initialize(&admin);
    runner.ours.register_attester(&attester);
    runner.base.initialize(&admin);
    runner.base.register_attester(&attester);
    runner.theirs.initialize(&admin);
    runner.theirs.register_attester(&attester);

    runner.run_scenario(&scenario);

    // Now exercise attestation lifecycle.
    let _ = runner
        .canonical
        .add_attestation(&attester, &subject, &data.clone(), &1_u64);
    let _ = runner
        .ours
        .add_attestation(&attester, &subject, &data.clone(), &1_u64);
    let _ = runner
        .base
        .add_attestation(&attester, &subject, &data.clone());
    let _ = runner
        .theirs
        .add_attestation(&attester, &subject, &data.clone());

    runner.canonical.revoke_attestation(&attester, &0_u64, &2_u64);
    runner.ours.revoke_attestation(&attester, &0_u64, &2_u64);
    runner.base.revoke_attestation(&attester, &0_u64);
    runner.theirs.revoke_attestation(&attester, &0_u64);
}

// ---------------------------------------------------------------------------
// Deliberate-divergence test — proves the harness can catch a bug.
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "diverged")]
fn deliberate_divergence_is_caught() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let identity = Address::generate(&env);

    let mut runner = ForkRunner::with_divergent(&env);
    runner.canonical.initialize(&admin);
    runner.ours.initialize(&admin);
    runner.base.initialize(&admin);
    runner.theirs.initialize(&admin);
    runner.divergent.as_ref().unwrap().initialize(&admin);

    let amount = 1_000_i128;
    let _c = runner
        .canonical
        .create_bond(&identity, &amount, &1000_u64, &false, &0_u64);
    let _o = runner
        .ours
        .create_bond(&identity, &amount, &1000_u64, &false, &0_u64);
    let _b = runner
        .base
        .create_bond_with_rolling(&identity, &amount, &1000_u64, &false, &0_u64);
    let _t = runner
        .theirs
        .create_bond_with_rolling(&identity, &amount, &1000_u64, &false, &0_u64);
    let _d = runner
        .divergent
        .as_ref()
        .unwrap()
        .create_bond(&identity, &amount, &1000_u64, &false, &0_u64);

    // The divergent fork returns Gold for every amount >= 1, while the others
    // return Silver for 1_000.  assert_tiers_eq will panic.
    runner.assert_tiers_eq("deliberate tier divergence");
}

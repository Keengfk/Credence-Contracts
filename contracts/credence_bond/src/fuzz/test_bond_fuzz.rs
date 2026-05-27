extern crate std;

use proptest::prelude::*;

#[derive(Debug, Clone)]
enum BondAction {
    Create(i128),
    TopUp(i128),
    Slash(i128),
    Withdraw(i128),
}

impl BondAction {
    fn arb() -> impl Strategy<Value = Self> {
        prop_oneof![
            any::<i128>().prop_map(BondAction::Create),
            any::<i128>().prop_map(BondAction::TopUp),
            any::<i128>().prop_map(BondAction::Slash),
            any::<i128>().prop_map(BondAction::Withdraw),
        ]
    }
}

#[derive(Debug, Clone)]
struct BondState {
    bonded_amount: i128,
    slashed_amount: i128,
    created: bool,
}

impl BondState {
    fn new() -> Self {
        Self {
            bonded_amount: 0,
            slashed_amount: 0,
            created: false,
        }
    }

    /// Asserts core bond accounting invariants after every operation:
    /// - `bonded_amount >= 0`
    /// - `slashed_amount >= 0`
    /// - `slashed_amount <= bonded_amount`
    /// - withdrawals never exceed `bonded_amount - slashed_amount`
    fn assert_invariants(&self) {
        assert!(
            self.bonded_amount >= 0,
            "bonded_amount must be non-negative: {:?}",
            self
        );
        assert!(
            self.slashed_amount >= 0,
            "slashed_amount must be non-negative: {:?}",
            self
        );
        assert!(
            self.slashed_amount <= self.bonded_amount,
            "slashed_amount cannot exceed bonded_amount: {:?}",
            self
        );
        assert!(
            self.available_balance() >= 0,
            "available balance must be non-negative: {:?}",
            self
        );
    }

    /// Returns the available withdrawable balance after slashing.
    fn available_balance(&self) -> i128 {
        self.bonded_amount - self.slashed_amount
    }

    fn tier_for_amount(amount: i128) -> u8 {
        match amount {
            x if x <= 0 => 0,
            1..=1_000_000_000_000_000_000 => 1,
            1_000_000_000_000_000_001..=10_000_000_000_000_000_000 => 2,
            10_000_000_000_000_000_001..=100_000_000_000_000_000_000 => 3,
            _ => 4,
        }
    }

    /// Verifies that the bond tier mapping is monotonic with bonded amount.
    ///
    /// When bonded amount increases, tier must not decrease.
    /// When bonded amount decreases, tier must not increase.
    fn assert_tier_monotonicity(&self, previous_bonded: i128) {
        let previous_tier = Self::tier_for_amount(previous_bonded);
        let current_tier = Self::tier_for_amount(self.bonded_amount);

        if self.bonded_amount >= previous_bonded {
            assert!(
                current_tier >= previous_tier,
                "tier must not decrease when bonded_amount increases: prev={} current={} state={:?}",
                previous_bonded,
                self.bonded_amount,
                self
            );
        } else {
            assert!(
                current_tier <= previous_tier,
                "tier must not increase when bonded_amount decreases: prev={} current={} state={:?}",
                previous_bonded,
                self.bonded_amount,
                self
            );
        }
    }

    fn create(self, amount: i128) -> Result<Self, &'static str> {
        if amount <= 0 {
            return Err("create amount must be positive");
        }

        Ok(Self {
            bonded_amount: amount,
            slashed_amount: 0,
            created: true,
        })
    }

    fn top_up(self, amount: i128) -> Result<Self, &'static str> {
        if !self.created {
            return Err("top_up requires an existing bond");
        }
        if amount <= 0 {
            return Err("top_up amount must be positive");
        }

        let bonded_amount = self
            .bonded_amount
            .checked_add(amount)
            .ok_or("bonded_amount overflow")?;

        Ok(Self {
            bonded_amount,
            ..self
        })
    }

    fn slash(self, amount: i128) -> Result<Self, &'static str> {
        if !self.created {
            return Err("slash requires an existing bond");
        }
        if amount < 0 {
            return Err("slash amount must be non-negative");
        }

        let new_slashed = self
            .slashed_amount
            .checked_add(amount)
            .ok_or("slashed_amount overflow")?;

        let slashed_amount = if new_slashed > self.bonded_amount {
            self.bonded_amount
        } else {
            new_slashed
        };

        Ok(Self {
            slashed_amount,
            ..self
        })
    }

    fn withdraw(self, amount: i128) -> Result<Self, &'static str> {
        if !self.created {
            return Err("withdraw requires an existing bond");
        }
        if amount < 0 {
            return Err("withdraw amount must be non-negative");
        }

        let available = self.available_balance();
        if amount > available {
            return Err("withdraw amount exceeds available balance");
        }

        let bonded_amount = self
            .bonded_amount
            .checked_sub(amount)
            .ok_or("bonded_amount underflow")?;

        Ok(Self {
            bonded_amount,
            ..self
        })
    }
}

proptest! {
    #[test]
    fn test_bond_fuzz(actions in prop::collection::vec(BondAction::arb(), 1..100)) {
        let mut state = BondState::new();
        let mut previous_bonded = state.bonded_amount;

        for action in actions {
            let next_state = match action {
                BondAction::Create(amount) => state.clone().create(amount).unwrap_or(state),
                BondAction::TopUp(amount) => state.clone().top_up(amount).unwrap_or(state),
                BondAction::Slash(amount) => state.clone().slash(amount).unwrap_or(state),
                BondAction::Withdraw(amount) => state.clone().withdraw(amount).unwrap_or(state),
            };

            next_state.assert_invariants();
            next_state.assert_tier_monotonicity(previous_bonded);

            previous_bonded = next_state.bonded_amount;
            state = next_state;
        }
    }

    #[test]
    fn test_tier_for_amount_is_monotonic(a in any::<i128>(), b in any::<i128>()) {
        prop_assume!(a <= b);
        assert!(BondState::tier_for_amount(a) <= BondState::tier_for_amount(b));
    }
}

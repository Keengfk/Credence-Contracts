use credence_bond::{CredenceBond, CredenceBondClient};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{testutils::Address as _, Address, Env, String};

fn setup(env: &Env) -> (CredenceBondClient<'_>, Address, Address, Address) {
    env.mock_all_auths();

    let contract_id = env.register(CredenceBond, ());
    let client = CredenceBondClient::new(env, &contract_id);

    let admin = Address::generate(env);
    let user = Address::generate(env);
    let attacker = Address::generate(env);

    client.initialize(&admin);

    // Register token
    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    client.set_token(&admin, &token_id);

    // 🔹 Use StellarAssetClient for minting
    let asset = soroban_sdk::token::StellarAssetClient::new(env, &token_id);
    asset.mint(&user, &10_000_000_i128);

    // 🔹 Use TokenClient for approval
    let token = soroban_sdk::token::TokenClient::new(env, &token_id);
    token.approve(&user, &contract_id, &10_000_000_i128, &0_u32);

    (client, admin, user, attacker)
}

#[test]
#[should_panic]
fn unauthorized_cannot_add_attestation() {
    let env = Env::default();
    let (client, _admin, user, attacker) = setup(&env);

    let fake = String::from_str(&env, "fake");
    let contract_id = env.register(credence_bond::CredenceBond, ());
    let deadline = env.ledger().timestamp() + 100_000;
    let nonce = client.get_nonce(&attacker);

    client.add_attestation(&attacker, &user, &fake, &contract_id, &deadline, &nonce);
}

#[test]
fn authorized_attester_can_add_attestation() {
    let env = Env::default();
    let (client, _admin, user, attacker) = setup(&env);

    client.register_attester(&attacker);

    let valid = String::from_str(&env, "valid");
    // get the actual contract_id from the client
    let contract_id = client.address.clone();
    let deadline = env.ledger().timestamp() + 100_000;
    let nonce = client.get_nonce(&attacker);
    let att = client.add_attestation(&attacker, &user, &valid, &contract_id, &deadline, &nonce);

    assert_eq!(att.identity, user);
}

#[test]
#[should_panic]
fn wrong_attester_cannot_revoke() {
    let env = Env::default();
    let (client, _admin, user, attacker) = setup(&env);

    client.register_attester(&attacker);

    let valid = String::from_str(&env, "valid");
    let contract_id = client.address.clone();
    let deadline = env.ledger().timestamp() + 100_000;
    let nonce = client.get_nonce(&attacker);
    let att = client.add_attestation(&attacker, &user, &valid, &contract_id, &deadline, &nonce);

    let other = Address::generate(&env);
    let other_nonce = client.get_nonce(&other);

    client.revoke_attestation(&other, &att.id, &contract_id, &deadline, &other_nonce);
}

#[test]
fn owner_can_withdraw_bond() {
    let env = Env::default();
    let (client, _admin, user, _) = setup(&env);

    client.create_bond_with_rolling(&user, &10_000_000_i128, &86400_u64, &false, &0_u64);

    // advance time past lock-up period
    env.ledger().with_mut(|l| {
        l.timestamp += 86401;
    });

    let bond = client.withdraw_bond(&1_000_000_000_000_000_000_i128);
    assert_eq!(bond.bonded_amount, 0);
}

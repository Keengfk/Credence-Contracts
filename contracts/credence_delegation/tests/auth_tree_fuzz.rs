#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    vec, Address, Env, IntoVal, String, Symbol,
};
use credence_delegation::{CredenceDelegation, CredenceDelegationClient};
use credence_bond::{CredenceBond, CredenceBondClient};

/// A proxy contract to simulate the cross-contract auth tree.
#[soroban_sdk::contract]
pub struct AuthProxy;

#[soroban_sdk::contractimpl]
impl AuthProxy {
    pub fn delegated_action(
        e: Env,
        bond_id: Address,
        owner: Address,
        subject: Address,
        nonce: u64,
    ) {
        owner.require_auth();
        let bond_client = CredenceBondClient::new(&e, &bond_id);
        bond_client.add_attestation(&owner, &subject, &String::from_str(&e, "fuzz_data"), &nonce);
    }
}

fn setup(e: &Env) -> (Address, Address, Address, Address) {
    let admin = Address::generate(e);
    
    let delegation_id = e.register_contract(None, CredenceDelegation);
    let delegation_client = CredenceDelegationClient::new(e, &delegation_id);
    delegation_client.initialize(&admin);

    let bond_id = e.register_contract(None, CredenceBond);
    let bond_client = CredenceBondClient::new(e, &bond_id);
    bond_client.initialize(&admin);

    let owner = Address::generate(e);
    let subject = Address::generate(e);
    let proxy_id = e.register_contract(None, AuthProxy);

    (bond_id, proxy_id, owner, subject)
}

#[test]
fn test_auth_tree_valid() {
    let e = Env::default();
    let (bond_id, proxy_id, owner, subject) = setup(&e);

    // Root invoke: AuthProxy::delegated_action
    let root_invoke = MockAuthInvoke {
        contract_id: proxy_id.clone(),
        fn_name: Symbol::new(&e, "delegated_action"),
        args: vec![&e, bond_id.to_val(), owner.to_val(), subject.to_val(), 0_u64.into_val(&e)],
        sub_invokes: vec![&e, MockAuth {
            address: owner.clone(),
            invoke: MockAuthInvoke {
                contract_id: bond_id.clone(),
                fn_name: Symbol::new(&e, "add_attestation"),
                args: vec![&e, owner.to_val(), subject.to_val(), String::from_str(&e, "fuzz_data").to_val(), 0_u64.into_val(&e)],
                sub_invokes: vec![&e],
            }
        }],
    };

    e.mock_auths(&[MockAuth {
        address: owner.clone(),
        invoke: root_invoke,
    }]);

    let proxy_client = AuthProxyClient::new(&e, &proxy_id);
    proxy_client.delegated_action(&bond_id, &owner, &subject, &0);
}

#[test]
#[should_panic]
fn test_auth_tree_missing_leaf() {
    let e = Env::default();
    let (bond_id, proxy_id, owner, subject) = setup(&e);

    e.mock_auths(&[MockAuth {
        address: owner.clone(),
        invoke: MockAuthInvoke {
            contract_id: proxy_id.clone(),
            fn_name: Symbol::new(&e, "delegated_action"),
            args: vec![&e, bond_id.to_val(), owner.to_val(), subject.to_val(), 0_u64.into_val(&e)],
            sub_invokes: vec![&e],
        },
    }]);

    let proxy_client = AuthProxyClient::new(&e, &proxy_id);
    proxy_client.delegated_action(&bond_id, &owner, &subject, &0);
}

use cosmwasm_std::{ensure, Addr, Deps};

use crate::ContractError;

pub mod custodian;
pub mod merchant;
pub mod owner;

pub enum Role {
    Owner,
    Merchant,
    Custodian,
}

pub fn allow_only(roles: &[Role], address: &Addr, deps: Deps) -> Result<(), ContractError> {
    for role in roles {
        let is_authorized = match role {
            Role::Owner => owner::is_owner(deps, address)?,
            Role::Merchant => merchant::is_merchant(deps, address.as_str())?,
            Role::Custodian => custodian::is_custodian(deps, address.as_str())?,
        };
        ensure!(is_authorized, ContractError::Unauthorized {});
    }
    Ok(())
}

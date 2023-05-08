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
            Role::Merchant => merchant::is_merchant(deps, address)?,
            Role::Custodian => custodian::is_custodian(deps, address)?,
        };
        ensure!(is_authorized, ContractError::Unauthorized {});
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn test_allow_only() {
        let mut deps = mock_dependencies();
        let owner_address = "osmo1owner";
        let merchant_address = "osmo1merchant";
        let custodian_address = "osmo1custodian";
        let non_owner_address = "osmo1nonowner";
        let non_merchant_address = "osmo1nonmerchant";
        let non_custodian_address = "osmo1noncustodian";

        // initialize owner
        owner::initialize_owner(deps.as_mut(), &owner_address).unwrap();

        // initialize merchant
        merchant::add_merchant(
            deps.as_mut(),
            mock_info(owner_address, &[]),
            merchant_address,
        )
        .unwrap();

        // initialize custodian
        custodian::set_custodian(deps.as_mut(), custodian_address).unwrap();

        // no error when address has the role
        allow_only(
            &[Role::Owner],
            &Addr::unchecked(owner_address),
            deps.as_ref(),
        )
        .unwrap();

        allow_only(
            &[Role::Merchant],
            &Addr::unchecked(merchant_address),
            deps.as_ref(),
        )
        .unwrap();

        allow_only(
            &[Role::Custodian],
            &Addr::unchecked(custodian_address),
            deps.as_ref(),
        )
        .unwrap();

        // error unauthorized when address does not have the role
        let err = allow_only(
            &[Role::Owner],
            &Addr::unchecked(non_owner_address),
            deps.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "Unauthorized");

        let err = allow_only(
            &[Role::Merchant],
            &Addr::unchecked(non_merchant_address),
            deps.as_ref(),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "Unauthorized");

        let err = allow_only(
            &[Role::Custodian],
            &Addr::unchecked(non_custodian_address),
            deps.as_ref(),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "Unauthorized");

        // error unauthorized when address does not have any of the roles
        let err = allow_only(
            &[Role::Owner, Role::Merchant],
            &Addr::unchecked(owner_address),
            deps.as_ref(),
        );

        assert_eq!(err.unwrap_err().to_string(), "Unauthorized");

        // no error when address has all of the roles

        // add owner as merchant
        merchant::add_merchant(deps.as_mut(), mock_info(owner_address, &[]), owner_address)
            .unwrap();
        allow_only(
            &[Role::Owner, Role::Merchant],
            &Addr::unchecked(owner_address),
            deps.as_ref(),
        )
        .unwrap();
    }
}

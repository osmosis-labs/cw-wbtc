use cosmwasm_std::{ensure, Addr, Deps};

use crate::ContractError;

pub mod custodian;
pub mod governor;
pub mod member_manager;
pub mod merchant;

#[derive(Clone, Copy)]
pub enum Role {
    Governor,
    MemberManager,
    Merchant,
    Custodian,
}

pub fn allow_only(roles: &[Role], address: &Addr, deps: Deps) -> Result<(), ContractError> {
    for role in roles {
        let is_authorized = match role {
            Role::Governor => governor::is_governor(deps, address)?,
            Role::MemberManager => member_manager::is_member_manager(deps, address)?,
            Role::Merchant => merchant::is_merchant(deps, address)?,
            Role::Custodian => custodian::is_custodian(deps, address)?,
        };
        ensure!(is_authorized, ContractError::Unauthorized {});
    }
    Ok(())
}

/// ensure that the address is not a priviledge address, used in context of adding a new priviledge address
fn has_no_priviledged_role(deps: Deps, address: &Addr) -> Result<(), ContractError> {
    let is_previledged_address = governor::is_governor(deps, address)?
        || member_manager::is_member_manager(deps, address)?
        || merchant::is_merchant(deps, address)?
        || custodian::is_custodian(deps, address)?;

    if is_previledged_address {
        Err(ContractError::AlreadyHasPriviledgedRole {
            address: address.to_string(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn test_allow_only() {
        let mut deps = mock_dependencies();
        let governor_address = "osmo1governor";
        let member_manager_address = "osmo1membermanager";
        let merchant_address = "osmo1merchant";
        let custodian_address = "osmo1custodian";
        let non_governor_address = "osmo1nongovernor";
        let non_member_manager_address = "osmo1nonmembermanager";
        let non_merchant_address = "osmo1nonmerchant";
        let non_custodian_address = "osmo1noncustodian";

        // initialize governor
        governor::initialize_governor(deps.as_mut(), governor_address).unwrap();

        // initialize member manager
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor_address, &[]),
            member_manager_address,
        )
        .unwrap();

        // initialize merchant
        merchant::add_merchant(
            deps.as_mut(),
            &mock_info(member_manager_address, &[]),
            merchant_address,
        )
        .unwrap();

        // initialize custodian
        custodian::set_custodian(
            deps.as_mut(),
            &mock_info(member_manager_address, &[]),
            custodian_address,
        )
        .unwrap();

        // no error when address has the role
        allow_only(
            &[Role::Governor],
            &Addr::unchecked(governor_address),
            deps.as_ref(),
        )
        .unwrap();

        allow_only(
            &[Role::MemberManager],
            &Addr::unchecked(member_manager_address),
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
            &[Role::Governor],
            &Addr::unchecked(non_governor_address),
            deps.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let err = allow_only(
            &[Role::MemberManager],
            &Addr::unchecked(non_member_manager_address),
            deps.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let err = allow_only(
            &[Role::Merchant],
            &Addr::unchecked(non_merchant_address),
            deps.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let err = allow_only(
            &[Role::Custodian],
            &Addr::unchecked(non_custodian_address),
            deps.as_ref(),
        )
        .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // error unauthorized when address does not have any of the roles
        let err = allow_only(
            &[Role::Governor, Role::Merchant],
            &Addr::unchecked(governor_address),
            deps.as_ref(),
        );

        assert_eq!(err.unwrap_err().to_string(), "Unauthorized");

        // no error when address has all of the roles

        // add governor as merchant
        merchant::add_merchant(
            deps.as_mut(),
            &mock_info(member_manager_address, &[]),
            governor_address,
        )
        .unwrap();
        allow_only(
            &[Role::Governor, Role::Merchant],
            &Addr::unchecked(governor_address),
            deps.as_ref(),
        )
        .unwrap();
    }

    #[test]
    fn test_has_no_priviledged_role() {
        let mut deps = mock_dependencies();
        let governor_address = "osmo1governor";
        let member_manager_address = "osmo1membermanager";
        let merchant_address = "osmo1merchant";
        let custodian_address = "osmo1custodian";

        // governor
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(governor_address)).unwrap();

        governor::initialize_governor(deps.as_mut(), governor_address).unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(governor_address)).unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: governor_address.to_string()
            }
        );

        // member manager
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(member_manager_address)).unwrap();

        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor_address, &[]),
            member_manager_address,
        )
        .unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(member_manager_address))
                .unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: member_manager_address.to_string()
            }
        );

        // merchant
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(merchant_address)).unwrap();

        merchant::add_merchant(
            deps.as_mut(),
            &mock_info(member_manager_address, &[]),
            merchant_address,
        )
        .unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(merchant_address)).unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: merchant_address.to_string()
            }
        );

        // custodian
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(custodian_address)).unwrap();

        custodian::set_custodian(
            deps.as_mut(),
            &mock_info(member_manager_address, &[]),
            custodian_address,
        )
        .unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(custodian_address))
                .unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: custodian_address.to_string()
            }
        );
    }
}

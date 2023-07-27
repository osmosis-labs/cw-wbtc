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
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_info},
        DepsMut,
    };
    use itertools::Itertools;

    const GOVERNOR_ADDRESS: &str = "osmo1governor";
    const MEMBER_MANAGER_ADDRESS: &str = "osmo1membermanager";
    const MERCHANT_ADDRESS: &str = "osmo1merchant";
    const CUSTODIAN_ADDRESS: &str = "osmo1custodian";
    const NON_GOVERNOR_ADDRESS: &str = "osmo1nongovernor";
    const NON_MEMBER_MANAGER_ADDRESS: &str = "osmo1nonmembermanager";
    const NON_MERCHANT_ADDRESS: &str = "osmo1nonmerchant";
    const NON_CUSTODIAN_ADDRESS: &str = "osmo1noncustodian";

    #[test]
    fn test_allow_only() {
        let mut deps = mock_dependencies();

        // initialize governor
        governor::initialize_governor(deps.as_mut(), GOVERNOR_ADDRESS).unwrap();

        // initialize member manager
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(GOVERNOR_ADDRESS, &[]),
            MEMBER_MANAGER_ADDRESS,
        )
        .unwrap();

        // initialize merchant
        merchant::add_merchant(
            deps.as_mut(),
            &mock_info(MEMBER_MANAGER_ADDRESS, &[]),
            MERCHANT_ADDRESS,
        )
        .unwrap();

        // initialize custodian
        custodian::set_custodian(
            deps.as_mut(),
            &mock_info(MEMBER_MANAGER_ADDRESS, &[]),
            CUSTODIAN_ADDRESS,
        )
        .unwrap();

        // no error when address has the role
        allow_only(
            &[Role::Governor],
            &Addr::unchecked(GOVERNOR_ADDRESS),
            deps.as_ref(),
        )
        .unwrap();

        allow_only(
            &[Role::MemberManager],
            &Addr::unchecked(MEMBER_MANAGER_ADDRESS),
            deps.as_ref(),
        )
        .unwrap();

        allow_only(
            &[Role::Merchant],
            &Addr::unchecked(MERCHANT_ADDRESS),
            deps.as_ref(),
        )
        .unwrap();

        allow_only(
            &[Role::Custodian],
            &Addr::unchecked(CUSTODIAN_ADDRESS),
            deps.as_ref(),
        )
        .unwrap();

        // error unauthorized when address does not have the role
        let err = allow_only(
            &[Role::Governor],
            &Addr::unchecked(NON_GOVERNOR_ADDRESS),
            deps.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let err = allow_only(
            &[Role::MemberManager],
            &Addr::unchecked(NON_MEMBER_MANAGER_ADDRESS),
            deps.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let err = allow_only(
            &[Role::Merchant],
            &Addr::unchecked(NON_MERCHANT_ADDRESS),
            deps.as_ref(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        let err = allow_only(
            &[Role::Custodian],
            &Addr::unchecked(NON_CUSTODIAN_ADDRESS),
            deps.as_ref(),
        )
        .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // error unauthorized when address does not have any of the roles
        let err = allow_only(
            &[Role::Governor, Role::Merchant],
            &Addr::unchecked(GOVERNOR_ADDRESS),
            deps.as_ref(),
        );

        assert_eq!(err.unwrap_err().to_string(), "Unauthorized");

        // no error when address has all of the roles
    }

    #[test]
    fn test_has_no_priviledged_role() {
        let mut deps = mock_dependencies();

        // governor
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(GOVERNOR_ADDRESS)).unwrap();

        governor::initialize_governor(deps.as_mut(), GOVERNOR_ADDRESS).unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(GOVERNOR_ADDRESS)).unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: GOVERNOR_ADDRESS.to_string()
            }
        );

        // member manager
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(MEMBER_MANAGER_ADDRESS)).unwrap();

        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(GOVERNOR_ADDRESS, &[]),
            MEMBER_MANAGER_ADDRESS,
        )
        .unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(MEMBER_MANAGER_ADDRESS))
                .unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: MEMBER_MANAGER_ADDRESS.to_string()
            }
        );

        // merchant
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(MERCHANT_ADDRESS)).unwrap();

        merchant::add_merchant(
            deps.as_mut(),
            &mock_info(MEMBER_MANAGER_ADDRESS, &[]),
            MERCHANT_ADDRESS,
        )
        .unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(MERCHANT_ADDRESS)).unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: MERCHANT_ADDRESS.to_string()
            }
        );

        // custodian
        has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(CUSTODIAN_ADDRESS)).unwrap();

        custodian::set_custodian(
            deps.as_mut(),
            &mock_info(MEMBER_MANAGER_ADDRESS, &[]),
            CUSTODIAN_ADDRESS,
        )
        .unwrap();

        assert_eq!(
            has_no_priviledged_role(deps.as_ref(), &Addr::unchecked(CUSTODIAN_ADDRESS))
                .unwrap_err(),
            ContractError::AlreadyHasPriviledgedRole {
                address: CUSTODIAN_ADDRESS.to_string()
            }
        );

        // permutation of the addresses and setting / transferring functions
        let addresses = vec![
            GOVERNOR_ADDRESS,
            MEMBER_MANAGER_ADDRESS,
            MERCHANT_ADDRESS,
            CUSTODIAN_ADDRESS,
        ];

        type SetterFn = fn(DepsMut, &str) -> Result<(), ContractError>;

        fn _initialize_governor(deps: DepsMut, address: &str) -> Result<(), ContractError> {
            governor::initialize_governor(deps, address)?;
            Ok(())
        }

        fn _set_member_manager(deps: DepsMut, address: &str) -> Result<(), ContractError> {
            member_manager::set_member_manager(deps, &mock_info(GOVERNOR_ADDRESS, &[]), address)?;
            Ok(())
        }

        fn _add_merchant(deps: DepsMut, address: &str) -> Result<(), ContractError> {
            merchant::add_merchant(deps, &mock_info(MEMBER_MANAGER_ADDRESS, &[]), address)?;
            Ok(())
        }

        fn _set_custodian(deps: DepsMut, address: &str) -> Result<(), ContractError> {
            custodian::set_custodian(deps, &mock_info(MEMBER_MANAGER_ADDRESS, &[]), address)?;
            Ok(())
        }

        let setters: Vec<SetterFn> = vec![
            _initialize_governor,
            _set_member_manager,
            _add_merchant,
            _set_custodian,
        ];

        for (address, setter) in pair_permutation_iterator(addresses, setters) {
            assert_eq!(
                setter(deps.as_mut(), address).unwrap_err(),
                ContractError::AlreadyHasPriviledgedRole {
                    address: address.to_string()
                }
            );
        }
    }

    fn pair_permutation_iterator<T, U>(v1: Vec<T>, v2: Vec<U>) -> impl Iterator<Item = (T, U)>
    where
        T: Clone,
        U: Clone,
    {
        let iter1 = v1.clone().into_iter().permutations(v1.len());
        let iter2 = v2.clone().into_iter().permutations(v2.len());

        // Iterate over all permutations of v1 and v2.
        // For each permutation, yield the pair of elements at the same index.
        iter1.zip(iter2).map(|(a, b)| (a[0].clone(), b[0].clone()))
    }
}

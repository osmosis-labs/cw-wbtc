/// `custodian` module provides functionality to manage the custodian address.
use cosmwasm_std::{attr, Addr, Deps, DepsMut, MessageInfo, Response, StdError};

use crate::{attrs::action_attrs, state::auth::CUSTODIAN, ContractError};

use super::{allow_only, has_no_priviledged_role, Role};

/// Set the custodian address.
pub fn set_custodian(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::MemberManager], &info.sender, deps.as_ref())?;

    let address = deps.api.addr_validate(address)?;
    has_no_priviledged_role(deps.as_ref(), &address)?;

    CUSTODIAN.save(deps.storage, &address)?;

    let attrs = action_attrs("set_custodian", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Check if the given address is the custodian.
pub fn is_custodian(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    match CUSTODIAN.may_load(deps.storage)? {
        Some(custodian) => Ok(custodian == address),
        None => Ok(false),
    }
}

/// Get the custodian address.
pub fn get_custodian(deps: Deps) -> Result<Addr, StdError> {
    CUSTODIAN
        .may_load(deps.storage)?
        .ok_or_else(|| StdError::not_found("Custodian"))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use crate::auth::{governor::initialize_governor, member_manager};

    use super::*;

    #[test]
    fn test_manage_custodian() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let non_member_manager = "osmo1nonmembermanager";
        let custodian_address = "osmo1custodian";
        let non_custodian_address = "osmo1noncustodian";

        // setup
        initialize_governor(deps.as_mut(), governor).unwrap();

        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();

        // check before set will fail
        assert!(!is_custodian(deps.as_ref(), &Addr::unchecked(custodian_address)).unwrap());

        let err = get_custodian(deps.as_ref()).unwrap_err();
        assert_eq!(err, StdError::not_found("Custodian"));

        // set custodian by non governor should fail
        let err = set_custodian(
            deps.as_mut(),
            &mock_info(non_member_manager, &[]),
            custodian_address,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // set custodian
        assert_eq!(
            set_custodian(
                deps.as_mut(),
                &mock_info(member_manager, &[]),
                custodian_address
            )
            .unwrap()
            .attributes,
            vec![
                attr("action", "set_custodian"),
                attr("address", custodian_address)
            ]
        );

        // check after set will pass
        assert_eq!(get_custodian(deps.as_ref()).unwrap(), custodian_address);
        assert!(is_custodian(deps.as_ref(), &Addr::unchecked(custodian_address)).unwrap());
        assert!(!is_custodian(deps.as_ref(), &Addr::unchecked(non_custodian_address)).unwrap());
    }
}

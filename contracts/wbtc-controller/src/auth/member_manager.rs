/// `member_manager` module provides functionality to manage the member manager address.
use cosmwasm_std::{attr, Addr, Deps, DepsMut, MessageInfo, Response, StdError};
use cw_storage_plus::Item;

use crate::{helpers::action_attrs, ContractError};

use super::{allow_only, Role};

/// Member manager address storage.
const MEMBER_MANAGER: Item<Addr> = Item::new("member_manager");

/// Set the member manager address.
pub fn set_member_manager(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Governor], &info.sender, deps.as_ref())?;

    MEMBER_MANAGER.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let attrs = action_attrs("set_member_manager", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Check if the given address is the member manager.
pub fn is_member_manager(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    match MEMBER_MANAGER.may_load(deps.storage)? {
        Some(member_manager) => Ok(member_manager == address),
        None => Ok(false),
    }
}

/// Get the member manager address.
pub fn get_member_manager(deps: Deps) -> Result<Addr, StdError> {
    MEMBER_MANAGER
        .may_load(deps.storage)?
        .ok_or_else(|| StdError::not_found("MemberManager"))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use crate::auth::governor::initialize_governor;

    use super::*;

    #[test]
    fn test_manage_member_manager() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let non_governor = "osmo1nongovernor";
        let member_manager_address = "osmo1membermanager";
        let non_member_manager_address = "osmo1nonmembermanager";

        // setup
        initialize_governor(deps.as_mut(), governor).unwrap();

        // check before set will fail
        assert!(
            !is_member_manager(deps.as_ref(), &Addr::unchecked(member_manager_address)).unwrap()
        );

        let err = get_member_manager(deps.as_ref()).unwrap_err();
        assert_eq!(err, StdError::not_found("MemberManager"));

        // set member manager by non governor should fail
        let err = set_member_manager(
            deps.as_mut(),
            &mock_info(non_governor, &[]),
            member_manager_address,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // set member manager
        assert_eq!(
            set_member_manager(
                deps.as_mut(),
                &mock_info(governor, &[]),
                member_manager_address
            )
            .unwrap()
            .attributes,
            vec![
                attr("action", "set_member_manager"),
                attr("address", member_manager_address)
            ]
        );

        // check after set will pass
        assert_eq!(
            get_member_manager(deps.as_ref()).unwrap(),
            member_manager_address
        );
        assert!(
            is_member_manager(deps.as_ref(), &Addr::unchecked(member_manager_address)).unwrap()
        );
        assert!(
            !is_member_manager(deps.as_ref(), &Addr::unchecked(non_member_manager_address))
                .unwrap()
        );
    }
}

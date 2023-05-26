/// `owner` module provides owner management functionality.
use cosmwasm_std::{attr, Addr, Deps, DepsMut, MessageInfo, Response, StdError};
use cw_storage_plus::Item;

use crate::{helpers::action_attrs, ContractError};

use super::{allow_only, Role};

const OWNER: Item<Addr> = Item::new("owner");

/// Initialize the owner, can only be called once at contract instantiation
pub fn initialize_owner(deps: DepsMut, address: &str) -> Result<Response, ContractError> {
    OWNER.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let attrs = action_attrs("initialize_owner", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Transfer the ownership to another address, only the owner can call this
pub fn transfer_ownership(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Owner], &info.sender, deps.as_ref())?;

    OWNER.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let attrs = action_attrs("transfer_ownership", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Check if the given address is the owner
pub fn is_owner(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    match OWNER.may_load(deps.storage)? {
        Some(owner) => Ok(address == owner),
        None => Ok(false),
    }
}

/// Get the owner address
pub fn get_owner(deps: Deps) -> Result<Addr, StdError> {
    OWNER
        .may_load(deps.storage)?
        .ok_or(StdError::not_found("Owner"))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use super::*;

    #[test]
    fn test_manage_owner() {
        let mut deps = mock_dependencies();
        let owner_address = "osmo1owner";
        let non_owner_address = "osmo1nonowner";
        let new_owner_address = "osmo1newowner";

        // check before set will fail

        assert!(!is_owner(deps.as_ref(), &Addr::unchecked(owner_address)).unwrap(),);

        let err = get_owner(deps.as_ref()).unwrap_err();
        assert_eq!(err, StdError::not_found("Owner"));

        // initialize owner
        assert_eq!(
            initialize_owner(deps.as_mut(), owner_address)
                .unwrap()
                .attributes,
            vec![
                attr("action", "initialize_owner"),
                attr("address", owner_address)
            ]
        );

        // check after set will pass
        assert_eq!(get_owner(deps.as_ref()).unwrap(), owner_address);
        assert!(is_owner(deps.as_ref(), &Addr::unchecked(owner_address)).unwrap(),);
        assert!(!is_owner(deps.as_ref(), &Addr::unchecked(non_owner_address)).unwrap(),);

        // transfer owner right should fail if not called by owner
        let err = transfer_ownership(
            deps.as_mut(),
            &mock_info(new_owner_address, &[]),
            non_owner_address,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        assert_eq!(get_owner(deps.as_ref()).unwrap(), owner_address);
        assert!(is_owner(deps.as_ref(), &Addr::unchecked(owner_address)).unwrap(),);
        assert!(!is_owner(deps.as_ref(), &Addr::unchecked(non_owner_address)).unwrap(),);

        // transfer owner right should pass if called by owner
        assert_eq!(
            transfer_ownership(
                deps.as_mut(),
                &mock_info(owner_address, &[]),
                new_owner_address,
            )
            .unwrap()
            .attributes,
            vec![
                attr("action", "transfer_ownership"),
                attr("address", new_owner_address)
            ]
        );

        assert_eq!(get_owner(deps.as_ref()).unwrap(), new_owner_address);
        assert!(!is_owner(deps.as_ref(), &Addr::unchecked(owner_address)).unwrap(),);
        assert!(!is_owner(deps.as_ref(), &Addr::unchecked(non_owner_address)).unwrap(),);
        assert!(is_owner(deps.as_ref(), &Addr::unchecked(new_owner_address)).unwrap(),);
    }
}

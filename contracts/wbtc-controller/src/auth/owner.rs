use cosmwasm_std::{ensure, Addr, Deps, DepsMut, Event, MessageInfo, Response, StdError};
use cw_storage_plus::Item;

use crate::ContractError;

const OWNER: Item<Addr> = Item::new("owner");

/// Initialize the owner, can only be called once at contract instantiation
pub fn initialize_owner(deps: DepsMut, address: &str) -> Result<Response, ContractError> {
    OWNER.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let event = Event::new("initialize_owner").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

/// Transfer the ownership to another address, only the owner can call this
pub fn transfer_ownership(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    ensure!(
        is_owner(deps.as_ref(), info.sender.as_str())?,
        ContractError::Unauthorized {}
    );
    OWNER.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let event = Event::new("transfer_owner_right").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

/// Check if the given address is the owner
pub fn is_owner(deps: Deps, address: &str) -> Result<bool, StdError> {
    let owner = OWNER.load(deps.storage)?;

    Ok(owner == deps.api.addr_validate(address)?)
}

/// Get the owner address
pub fn get_owner(deps: Deps) -> Result<Addr, StdError> {
    OWNER.load(deps.storage)
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
        let err = is_owner(deps.as_ref(), &owner_address).unwrap_err();
        assert_eq!(err.to_string(), "cosmwasm_std::addresses::Addr not found");

        let err = get_owner(deps.as_ref()).unwrap_err();
        assert_eq!(err.to_string(), "cosmwasm_std::addresses::Addr not found");

        // initialize owner
        assert_eq!(
            initialize_owner(deps.as_mut(), &owner_address)
                .unwrap()
                .events,
            vec![Event::new("initialize_owner").add_attribute("address", owner_address.clone())]
        );

        // check after set will pass
        assert_eq!(get_owner(deps.as_ref()).unwrap(), owner_address);
        assert_eq!(is_owner(deps.as_ref(), &owner_address).unwrap(), true);
        assert_eq!(is_owner(deps.as_ref(), &non_owner_address).unwrap(), false);

        // transfer owner right should fail if not called by owner
        let err = transfer_ownership(
            deps.as_mut(),
            &mock_info(new_owner_address, &[]),
            &non_owner_address,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "Unauthorized");

        assert_eq!(get_owner(deps.as_ref()).unwrap(), owner_address);
        assert_eq!(is_owner(deps.as_ref(), &owner_address).unwrap(), true);
        assert_eq!(is_owner(deps.as_ref(), &non_owner_address).unwrap(), false);

        // transfer owner right should pass if called by owner
        assert_eq!(
            transfer_ownership(
                deps.as_mut(),
                &mock_info(owner_address, &[]),
                &new_owner_address,
            )
            .unwrap()
            .events,
            vec![Event::new("transfer_owner_right")
                .add_attribute("address", new_owner_address.clone())]
        );

        assert_eq!(get_owner(deps.as_ref()).unwrap(), new_owner_address);
        assert_eq!(is_owner(deps.as_ref(), &owner_address).unwrap(), false);
        assert_eq!(is_owner(deps.as_ref(), &non_owner_address).unwrap(), false);
        assert_eq!(is_owner(deps.as_ref(), &new_owner_address).unwrap(), true);
    }
}

use cosmwasm_std::{ensure, Addr, Deps, DepsMut, Event, MessageInfo, Response, StdError};
use cw_storage_plus::Item;

use crate::ContractError;

const ADMIN: Item<Addr> = Item::new("admin");

/// Initialize the admin, can only be called once at contract instantiation
pub fn initialize_admin(deps: DepsMut, address: &str) -> Result<Response, ContractError> {
    ADMIN.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let event = Event::new("initialize_admin").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

/// Transfer the admin right to another address, only the admin can call this
pub fn transfer_admin_right(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    ensure!(
        is_admin(deps.as_ref(), info.sender.as_str())?,
        ContractError::Unauthorized {}
    );
    ADMIN.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let event = Event::new("transfer_admin_right").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

/// Check if the given address is the admin
pub fn is_admin(deps: Deps, address: &str) -> Result<bool, StdError> {
    let admin = ADMIN.load(deps.storage)?;

    Ok(admin == deps.api.addr_validate(address)?)
}

/// Get the admin address
pub fn get_admin(deps: Deps) -> Result<Addr, StdError> {
    ADMIN.load(deps.storage)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use super::*;

    #[test]
    fn test_manage_admin() {
        let mut deps = mock_dependencies();
        let admin_address = "osmo1admin";
        let non_admin_address = "osmo1nonadmin";
        let new_admin_address = "osmo1newadmin";

        // check before set will fail
        let err = is_admin(deps.as_ref(), &admin_address).unwrap_err();
        assert_eq!(err.to_string(), "cosmwasm_std::addresses::Addr not found");

        let err = get_admin(deps.as_ref()).unwrap_err();
        assert_eq!(err.to_string(), "cosmwasm_std::addresses::Addr not found");

        // initialize admin
        assert_eq!(
            initialize_admin(deps.as_mut(), &admin_address)
                .unwrap()
                .events,
            vec![Event::new("initialize_admin").add_attribute("address", admin_address.clone())]
        );

        // check after set will pass
        assert_eq!(get_admin(deps.as_ref()).unwrap(), admin_address);
        assert_eq!(is_admin(deps.as_ref(), &admin_address).unwrap(), true);
        assert_eq!(is_admin(deps.as_ref(), &non_admin_address).unwrap(), false);

        // transfer admin right should fail if not called by admin
        let err = transfer_admin_right(
            deps.as_mut(),
            &mock_info(new_admin_address, &[]),
            &non_admin_address,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "Unauthorized");

        assert_eq!(get_admin(deps.as_ref()).unwrap(), admin_address);
        assert_eq!(is_admin(deps.as_ref(), &admin_address).unwrap(), true);
        assert_eq!(is_admin(deps.as_ref(), &non_admin_address).unwrap(), false);

        // transfer admin right should pass if called by admin
        assert_eq!(
            transfer_admin_right(
                deps.as_mut(),
                &mock_info(admin_address, &[]),
                &new_admin_address,
            )
            .unwrap()
            .events,
            vec![Event::new("transfer_admin_right")
                .add_attribute("address", new_admin_address.clone())]
        );

        assert_eq!(get_admin(deps.as_ref()).unwrap(), new_admin_address);
        assert_eq!(is_admin(deps.as_ref(), &admin_address).unwrap(), false);
        assert_eq!(is_admin(deps.as_ref(), &non_admin_address).unwrap(), false);
        assert_eq!(is_admin(deps.as_ref(), &new_admin_address).unwrap(), true);
    }
}

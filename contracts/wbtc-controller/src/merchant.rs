use cosmwasm_std::{Addr, Deps, DepsMut, Event, MessageInfo, Response, StdError};
use cw_storage_plus::Map;

use crate::ContractError;

/// Merchants storage is a map of merchant addresses to empty values
/// This makes it efficient to check if a merchant exists while not storing any data as value
const MERCHANTS: Map<Addr, ()> = Map::new("merchants");

pub fn add_merchant(
    deps: DepsMut,
    _info: MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    MERCHANTS.save(deps.storage, deps.api.addr_validate(address)?, &())?;

    let event = Event::new("add_merchant").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

pub fn remove_merchant(
    deps: DepsMut,
    _info: MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    MERCHANTS.remove(deps.storage, deps.api.addr_validate(address)?);

    let event = Event::new("remove_merchant").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

pub fn is_merchant(deps: Deps, address: &str) -> Result<bool, StdError> {
    Ok(MERCHANTS
        .may_load(deps.storage, deps.api.addr_validate(address)?)?
        .is_some())
}

// TODO: list_merchants

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn test_manage_merchant() {
        let mut deps = mock_dependencies();
        let admin = "admin";
        let merchant_address_1 = "osmo1merchant1";
        let merchant_address_2 = "osmo1merchant2";

        // check is_merchant before add will return false
        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_1).unwrap(),
            false
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_2).unwrap(),
            false
        );

        // add merchant 1
        assert_eq!(
            add_merchant(deps.as_mut(), mock_info(admin, &[]), merchant_address_1)
                .unwrap()
                .events,
            vec![Event::new("add_merchant").add_attribute("address", merchant_address_1)]
        );

        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_1).unwrap(),
            true
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_2).unwrap(),
            false
        );

        // add merchant 2
        assert_eq!(
            add_merchant(deps.as_mut(), mock_info(admin, &[]), merchant_address_2)
                .unwrap()
                .events,
            vec![Event::new("add_merchant").add_attribute("address", merchant_address_2)]
        );

        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_1).unwrap(),
            true
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_2).unwrap(),
            true
        );

        // remove merchant 1
        assert_eq!(
            remove_merchant(deps.as_mut(), mock_info(admin, &[]), merchant_address_1)
                .unwrap()
                .events,
            vec![Event::new("remove_merchant").add_attribute("address", merchant_address_1)]
        );

        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_1).unwrap(),
            false
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &merchant_address_2).unwrap(),
            true
        );
    }
}

use cosmwasm_std::{Addr, Deps, DepsMut, Event, Response, StdError};
use cw_storage_plus::Item;

use crate::ContractError;

const CUSTODIAN: Item<Addr> = Item::new("custodian");

pub fn set_custodian(deps: DepsMut, address: &str) -> Result<Response, ContractError> {
    CUSTODIAN.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let event = Event::new("set_custodian").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

pub fn is_custodian(deps: Deps, address: &str) -> Result<bool, StdError> {
    let custodian = CUSTODIAN.load(deps.storage)?;

    Ok(custodian == deps.api.addr_validate(address)?)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;

    use super::*;

    #[test]
    fn test_manage_custodian() {
        let mut deps = mock_dependencies();
        let custodian_address = "osmo1custodian";
        let non_custodian_address = "osmo1noncustodian";

        // check before set will fail
        let err = is_custodian(deps.as_ref(), &custodian_address).unwrap_err();
        assert_eq!(err.to_string(), "cosmwasm_std::addresses::Addr not found");

        // set custodian
        assert_eq!(
            set_custodian(deps.as_mut(), &custodian_address)
                .unwrap()
                .events,
            vec![Event::new("set_custodian").add_attribute("address", custodian_address.clone())]
        );

        // check after set will pass
        assert_eq!(
            is_custodian(deps.as_ref(), &custodian_address).unwrap(),
            true
        );
        assert_eq!(
            is_custodian(deps.as_ref(), &non_custodian_address).unwrap(),
            false
        );
    }
}

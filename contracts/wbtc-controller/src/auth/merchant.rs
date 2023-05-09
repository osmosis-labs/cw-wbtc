use cosmwasm_std::{Addr, Deps, DepsMut, Event, MessageInfo, Response, StdError};
use cw_storage_plus::Map;

use crate::ContractError;

use super::{allow_only, Role};

/// Merchants storage is a map of merchant addresses to empty values
/// This makes it efficient to check if a merchant exists while not storing any data as value
const MERCHANTS: Map<Addr, ()> = Map::new("merchants");

pub fn add_merchant(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Owner], &info.sender, deps.as_ref())?;

    MERCHANTS.save(deps.storage, deps.api.addr_validate(address)?, &())?;

    let event = Event::new("merchant_added").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

pub fn remove_merchant(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Owner], &info.sender, deps.as_ref())?;

    MERCHANTS.remove(deps.storage, deps.api.addr_validate(address)?);

    let event = Event::new("merchant_removed").add_attribute("address", address);
    Ok(Response::new().add_event(event))
}

pub fn is_merchant(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    Ok(MERCHANTS
        .may_load(deps.storage, address.to_owned())?
        .is_some())
}

// TODO: list_merchants

#[cfg(test)]
mod tests {
    use crate::auth::owner;

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn test_manage_merchant() {
        let mut deps = mock_dependencies();
        let owner = "osmo1owner";
        let non_owner = "osmo1nonowner";
        let merchant_address_1 = "osmo1merchant1";
        let merchant_address_2 = "osmo1merchant2";

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();

        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(owner)).unwrap(),
            false
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),
            false
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),
            false
        );

        // add merchant by non owner should fail
        let err = add_merchant(
            deps.as_mut(),
            &mock_info(non_owner, &[]),
            merchant_address_1,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // add merchant 1
        assert_eq!(
            add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant_address_1)
                .unwrap()
                .events,
            vec![Event::new("merchant_added").add_attribute("address", merchant_address_1)]
        );

        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),
            true
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),
            false
        );

        // add merchant 2
        assert_eq!(
            add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant_address_2)
                .unwrap()
                .events,
            vec![Event::new("merchant_added").add_attribute("address", merchant_address_2)]
        );

        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),
            true
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),
            true
        );

        // remove merchant by non_owner should fail
        let err = remove_merchant(
            deps.as_mut(),
            &mock_info(non_owner, &[]),
            merchant_address_1,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // remove merchant 1
        assert_eq!(
            remove_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant_address_1)
                .unwrap()
                .events,
            vec![Event::new("merchant_removed").add_attribute("address", merchant_address_1)]
        );

        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),
            false
        );
        assert_eq!(
            is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),
            true
        );
    }
}

use cosmwasm_std::{Addr, Deps, DepsMut, Event, MessageInfo, Response, StdError};
use cw_storage_plus::Map;

use crate::{
    auth::{allow_only, Role},
    ContractError,
};

// mapping between merchant address to the corresponding custodian BTC deposit address, used in the minting process.
// by using a different deposit address per merchant the custodian can identify which merchant deposited.
const CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT: Map<Addr, String> =
    Map::new("custodian_deposit_address_per_merchant");

pub fn set_custodian_deposit_address(
    deps: DepsMut,
    info: &MessageInfo,
    merchant: &str,
    deposit_address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

    let merchant = deps.api.addr_validate(merchant)?;

    let event = Event::new("custodian_deposit_address_set")
        .add_attribute("sender", info.sender.as_str())
        .add_attribute("merchant", merchant.as_str())
        .add_attribute("deposit_address", deposit_address);

    CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT.save(
        deps.storage,
        merchant,
        &deposit_address.to_string(),
    )?;

    Ok(Response::new().add_event(event))
}

pub fn get_custodian_deposit_address(deps: Deps, merchant: &Addr) -> Result<String, StdError> {
    CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT.load(deps.storage, merchant.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use crate::auth::{custodian, merchant, owner};

    #[test]
    fn test_custodian_deposit_address() {
        let mut deps = mock_dependencies();
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant_1 = "osmo1merchant1";
        let merchant_2 = "osmo1merchant2";
        let deposit_address_1 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let deposit_address_2 = "bc1q35rayrk92pvwamwm4n2hsd3epez2g2tqcqa0fx";

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(&owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(&owner, &[]), merchant_1).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(&owner, &[]), merchant_2).unwrap();

        // no custodian deposit address set yet
        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap_err(),
            StdError::not_found("alloc::string::String")
        );
        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap_err(),
            StdError::not_found("alloc::string::String")
        );

        // non custodian cannot set custodian deposit address
        assert_eq!(
            set_custodian_deposit_address(
                deps.as_mut(),
                &mock_info(&merchant_1, &[]),
                merchant_1,
                deposit_address_1,
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );

        // set custodian deposit address for merchant 1
        set_custodian_deposit_address(
            deps.as_mut(),
            &mock_info(&custodian, &[]),
            merchant_1,
            deposit_address_1,
        )
        .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap(),
            deposit_address_1.to_string()
        );

        // set custodian deposit address for merchant 2
        set_custodian_deposit_address(
            deps.as_mut(),
            &mock_info(&custodian, &[]),
            merchant_2,
            deposit_address_2,
        )
        .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap(),
            deposit_address_2.to_string()
        );
    }
}

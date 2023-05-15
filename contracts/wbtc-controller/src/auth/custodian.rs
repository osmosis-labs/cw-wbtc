use cosmwasm_std::{attr, Addr, Deps, DepsMut, MessageInfo, Response, StdError};
use cw_storage_plus::Item;

use crate::{helpers::method_attrs, ContractError};

use super::{allow_only, Role};

const CUSTODIAN: Item<Addr> = Item::new("custodian");

pub fn set_custodian(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Owner], &info.sender, deps.as_ref())?;

    CUSTODIAN.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let attrs = method_attrs("set_custodian", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

pub fn is_custodian(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    match CUSTODIAN.may_load(deps.storage)? {
        Some(custodian) => Ok(custodian == address),
        None => Ok(false),
    }
}

pub fn get_custodian(deps: Deps) -> Result<Addr, StdError> {
    CUSTODIAN
        .may_load(deps.storage)?
        .ok_or_else(|| StdError::not_found("Custodian"))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use crate::auth::owner::initialize_owner;

    use super::*;

    #[test]
    fn test_manage_custodian() {
        let mut deps = mock_dependencies();
        let owner = "osmo1owner";
        let non_owner = "osmo1nonowner";
        let custodian_address = "osmo1custodian";
        let non_custodian_address = "osmo1noncustodian";

        // setup
        initialize_owner(deps.as_mut(), owner).unwrap();

        // check before set will fail
        assert_eq!(
            is_custodian(deps.as_ref(), &Addr::unchecked(custodian_address)).unwrap(),
            false
        );

        let err = get_custodian(deps.as_ref()).unwrap_err();
        assert_eq!(err, StdError::not_found("Custodian"));

        // set custodian by non owner should fail
        let err = set_custodian(
            deps.as_mut(),
            &mock_info(non_owner, &[]),
            &custodian_address,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // set custodian
        assert_eq!(
            set_custodian(deps.as_mut(), &mock_info(owner, &[]), &custodian_address)
                .unwrap()
                .attributes,
            vec![
                attr("method", "set_custodian"),
                attr("address", custodian_address.clone())
            ]
        );

        // check after set will pass
        assert_eq!(get_custodian(deps.as_ref()).unwrap(), custodian_address);
        assert_eq!(
            is_custodian(deps.as_ref(), &Addr::unchecked(custodian_address)).unwrap(),
            true
        );
        assert_eq!(
            is_custodian(deps.as_ref(), &Addr::unchecked(non_custodian_address)).unwrap(),
            false
        );
    }
}

/// `merchant` module provides functionality to manage merchants
use cosmwasm_std::{
    attr, ensure, Addr, Deps, DepsMut, MessageInfo, Order, Response, StdError, StdResult,
};
use cw_storage_plus::{Bound, Map};

use crate::{
    attrs::action_attrs,
    constants::{DEFAULT_LIMIT, MAX_LIMIT},
    ContractError,
};

use super::{allow_only, Role};

/// Merchants storage is a map of merchant addresses to empty values
/// This makes it efficient to check if a merchant exists while not storing any data as value
const MERCHANTS: Map<Addr, ()> = Map::new("merchants");

/// Add an address as member of merchant.
/// Duplicate addresses will not change the state since it's stored as a map's key.
pub fn add_merchant(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::MemberManager], &info.sender, deps.as_ref())?;

    let validated_address = deps.api.addr_validate(address)?;

    // check for duplicates
    ensure!(
        !is_merchant(deps.as_ref(), &validated_address)?,
        ContractError::DuplicatedMerchant {
            address: validated_address.to_string()
        }
    );

    MERCHANTS.save(deps.storage, validated_address, &())?;

    let attrs = action_attrs("add_merchant", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Remove address from member of merchant.
pub fn remove_merchant(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::MemberManager], &info.sender, deps.as_ref())?;

    MERCHANTS.remove(deps.storage, deps.api.addr_validate(address)?);

    let attrs = action_attrs("remove_merchant", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Check if the given address is a merchant.
pub fn is_merchant(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    Ok(MERCHANTS
        .may_load(deps.storage, address.to_owned())?
        .is_some())
}

/// List merchants with pagination.
pub fn list_merchants(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> Result<Vec<Addr>, StdError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after_bound = start_after
        .map(|addr| deps.api.addr_validate(&addr))
        .transpose()?
        .map(Bound::exclusive);

    let merchants = MERCHANTS
        .keys(deps.storage, start_after_bound, None, Order::Ascending)
        .take(limit)
        .collect::<StdResult<Vec<_>>>()?;

    Ok(merchants)
}

#[cfg(test)]
mod tests {
    use crate::auth::{governor, member_manager};

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn test_manage_merchant() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let non_member_manager = "osmo1nonmembermanager";
        let merchant_address_1 = "osmo1merchant1";
        let merchant_address_2 = "osmo1merchant2";

        // setup
        governor::initialize_governor(deps.as_mut(), governor).unwrap();
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();

        assert!(!is_merchant(deps.as_ref(), &Addr::unchecked(governor)).unwrap(),);
        assert!(!is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),);
        assert!(!is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),);

        // add merchant by non governor should fail
        let err = add_merchant(
            deps.as_mut(),
            &mock_info(non_member_manager, &[]),
            merchant_address_1,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // add merchant 1
        assert_eq!(
            add_merchant(
                deps.as_mut(),
                &mock_info(member_manager, &[]),
                merchant_address_1
            )
            .unwrap()
            .attributes,
            vec![
                attr("action", "add_merchant"),
                attr("address", merchant_address_1)
            ]
        );

        assert!(is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),);
        assert!(!is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),);

        // add merchant 2
        assert_eq!(
            add_merchant(
                deps.as_mut(),
                &mock_info(member_manager, &[]),
                merchant_address_2
            )
            .unwrap()
            .attributes,
            vec![
                attr("action", "add_merchant"),
                attr("address", merchant_address_2)
            ]
        );

        assert!(is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),);
        assert!(is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),);

        // adding merchant 2 again should not change state and return error
        let err = add_merchant(
            deps.as_mut(),
            &mock_info(member_manager, &[]),
            merchant_address_2,
        )
        .unwrap_err();

        assert_eq!(
            err,
            ContractError::DuplicatedMerchant {
                address: merchant_address_2.to_string()
            }
        );

        // remove merchant by non_governor should fail
        let err = remove_merchant(
            deps.as_mut(),
            &mock_info(non_member_manager, &[]),
            merchant_address_1,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // remove merchant 1
        assert_eq!(
            remove_merchant(
                deps.as_mut(),
                &mock_info(member_manager, &[]),
                merchant_address_1
            )
            .unwrap()
            .attributes,
            vec![
                attr("action", "remove_merchant"),
                attr("address", merchant_address_1)
            ]
        );

        assert!(!is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_1)).unwrap(),);
        assert!(is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address_2)).unwrap(),);
    }

    #[test]
    fn test_list_merchants() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";

        // setup
        governor::initialize_governor(deps.as_mut(), governor).unwrap();
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();

        assert_eq!(
            list_merchants(deps.as_ref(), None, None).unwrap(),
            vec![] as Vec<Addr>
        );

        // add 200 merhants
        for i in 1..=200 {
            let merchant_address = format!("osmo1merchant{:0>3}", i);
            add_merchant(
                deps.as_mut(),
                &mock_info(member_manager, &[]),
                &merchant_address,
            )
            .unwrap();
        }

        let first_ten = (1..=10)
            .map(|i| format!("osmo1merchant{:0>3}", i))
            .map(Addr::unchecked)
            .collect::<Vec<Addr>>();

        assert_eq!(
            list_merchants(deps.as_ref(), None, None).unwrap(),
            first_ten
        );

        let first_twenty_one = (1..=21)
            .map(|i| format!("osmo1merchant{:0>3}", i))
            .map(Addr::unchecked)
            .collect::<Vec<Addr>>();

        assert_eq!(
            list_merchants(deps.as_ref(), None, Some(21)).unwrap(),
            first_twenty_one
        );

        let first_hundred = (1..=100)
            .map(|i| format!("osmo1merchant{:0>3}", i))
            .map(Addr::unchecked)
            .collect::<Vec<Addr>>();

        assert_eq!(
            list_merchants(deps.as_ref(), None, Some(999)).unwrap(), // MAX_LIMIT = 100
            first_hundred
        );

        let hundred_one_to_hundred_forty_two = (101..=142)
            .map(|i| format!("osmo1merchant{:0>3}", i))
            .map(Addr::unchecked)
            .collect::<Vec<Addr>>();

        assert_eq!(
            list_merchants(
                deps.as_ref(),
                Some(first_hundred.last().unwrap().to_string()),
                Some(42)
            )
            .unwrap(),
            hundred_one_to_hundred_forty_two
        );
    }
}

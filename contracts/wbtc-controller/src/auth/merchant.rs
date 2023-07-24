/// `merchant` module provides functionality to manage merchants
use cosmwasm_std::{
    attr, ensure, Addr, Deps, DepsMut, MessageInfo, Order, Response, StdError, StdResult,
};
use cw_storage_plus::Bound;

use crate::{
    attrs::action_attrs,
    constants::{DEFAULT_LIMIT, MAX_LIMIT},
    state::MERCHANTS,
    tokenfactory::deposit_address::{
        CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT, MERCHANT_DEPOSIT_ADDRESS,
    },
    ContractError,
};

use super::{allow_only, Role};

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
    mut deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::MemberManager], &info.sender, deps.as_ref())?;

    let address = deps.api.addr_validate(address)?;

    // check if the address is a merchant
    ensure!(
        is_merchant(deps.as_ref(), &address)?,
        ContractError::NotAMerchant {
            address: address.to_string()
        }
    );

    let attrs = action_attrs("remove_merchant", vec![attr("address", address.as_str())]);
    MERCHANTS.remove(deps.storage, address.clone());

    // remove asscoiated deposit addresses
    CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT.set_deposit_address(
        deps.branch(),
        info,
        address.as_str(),
        None,
    )?;

    MERCHANT_DEPOSIT_ADDRESS.set_deposit_address(deps, info, address.as_str(), None)?;

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
    use crate::{
        auth::{custodian, governor, member_manager},
        tokenfactory::deposit_address::{
            get_custodian_deposit_address, get_merchant_deposit_address,
            set_custodian_deposit_address, set_merchant_deposit_address,
        },
    };

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
        let non_merchant_address = "osmo1nonmerchant";

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

        // remove non merchant
        let err = remove_merchant(
            deps.as_mut(),
            &mock_info(member_manager, &[]),
            non_merchant_address,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ContractError::NotAMerchant {
                address: non_merchant_address.to_string()
            }
        );

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

    #[test]
    fn test_cascade_remove_merchant() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian_address = "osmo1custodian";
        let merchant_address = "osmo1merchant";
        let custodian_deposit_address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let merchant_deposit_address = "bc1q35rayrk92pvwamwm4n2hsd3epez2g2tqcqa0fx";

        // setup
        governor::initialize_governor(deps.as_mut(), governor).unwrap();
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();
        custodian::set_custodian(
            deps.as_mut(),
            &mock_info(member_manager, &[]),
            custodian_address,
        )
        .unwrap();

        // add merchant
        add_merchant(
            deps.as_mut(),
            &mock_info(member_manager, &[]),
            merchant_address,
        )
        .unwrap();

        assert!(is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address)).unwrap());

        set_custodian_deposit_address(
            deps.as_mut(),
            &mock_info(custodian_address, &[]),
            merchant_address,
            Some(custodian_deposit_address),
        )
        .unwrap();

        set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant_address, &[]),
            Some(merchant_deposit_address),
        )
        .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_address))
                .unwrap(),
            custodian_deposit_address
        );

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_address))
                .unwrap(),
            merchant_deposit_address
        );

        // remove merchant
        remove_merchant(
            deps.as_mut(),
            &mock_info(member_manager, &[]),
            merchant_address,
        )
        .unwrap();

        assert!(!is_merchant(deps.as_ref(), &Addr::unchecked(merchant_address)).unwrap());

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_address))
                .unwrap_err(),
            StdError::not_found(format!(
                "No custodian deposit address found for `{merchant_address}`"
            ))
        );

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_address))
                .unwrap_err(),
            StdError::not_found(format!(
                "No merchant deposit address found for `{merchant_address}`"
            ))
        );
    }
}

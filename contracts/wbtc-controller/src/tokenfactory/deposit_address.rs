/// `deposit_address` module provides a way to manage deposit addresses for merchants and custodian.
use cosmwasm_std::{attr, ensure, Addr, Attribute, Deps, DepsMut, MessageInfo, Response, StdError};
use cw_storage_plus::Map;

use crate::{
    attrs::action_attrs,
    auth::{allow_only, merchant, Role},
    ContractError,
};

/// `DepositAddressMananger` is a helper struct to manage deposit addresses.
pub struct DepositAddressMananger<'a> {
    /// deposit address storage.
    deposit_address: Map<'a, Addr, String>,

    /// role allowed to set the deposit address.
    setter_role: Role,
}

impl<'a> DepositAddressMananger<'a> {
    pub const fn new(namespace: &'a str, setter_role: Role) -> Self {
        DepositAddressMananger {
            deposit_address: Map::new(namespace),
            setter_role,
        }
    }

    pub fn set_deposit_address(
        &self,
        deps: DepsMut,
        info: &MessageInfo,
        merchant: &str,
        deposit_address: &str,
    ) -> Result<Vec<Attribute>, ContractError> {
        allow_only(&[self.setter_role], &info.sender, deps.as_ref())?;

        let merchant = deps.api.addr_validate(merchant)?;

        let attrs = vec![
            attr("sender", info.sender.as_str()),
            attr("merchant", merchant.as_str()),
            attr("deposit_address", deposit_address),
        ];

        self.deposit_address
            .save(deps.storage, merchant, &deposit_address.to_string())?;

        Ok(attrs)
    }

    pub fn get_deposit_address(
        &self,
        deps: Deps,
        merchant: &Addr,
    ) -> Result<Option<String>, StdError> {
        self.deposit_address
            .may_load(deps.storage, merchant.clone())
    }
}

/// Mapping between merchant address to the corresponding custodian BTC deposit address, used in the minting process.
/// by using a different deposit address per merchant the custodian can identify which merchant deposited.
/// Only custodian can set this addresses.
const CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT: DepositAddressMananger =
    DepositAddressMananger::new("custodian_deposit_address_per_merchant", Role::Custodian);

pub fn set_custodian_deposit_address(
    deps: DepsMut,
    info: &MessageInfo,
    merchant: &str,
    deposit_address: &str,
) -> Result<Response, ContractError> {
    // ensure that the merchant to be associated with the deposit address really has a merchant role.
    // since `set_deposit_address` only checks if sender is custodian.
    ensure!(
        merchant::is_merchant(deps.as_ref(), &deps.api.addr_validate(merchant)?)?,
        ContractError::DepositAddressAssociatedByNonMerchant {
            address: merchant.to_string(),
        }
    );

    Ok(Response::new().add_attributes(action_attrs(
        "set_custodian_deposit_address",
        CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT.set_deposit_address(
            deps,
            info,
            merchant,
            deposit_address,
        )?,
    )))
}

pub fn get_custodian_deposit_address(deps: Deps, merchant: &Addr) -> Result<String, StdError> {
    CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT
        .get_deposit_address(deps, merchant)?
        .ok_or_else(|| {
            StdError::not_found(format!(
                "No custodian deposit address found for `{merchant}`"
            ))
        })
}

/// mapping between merchant to the its deposit address where the asset should be moved to, used in the burning process.
const MERCHANT_DEPOSIT_ADDRESS: DepositAddressMananger =
    DepositAddressMananger::new("merchant_deposit_address", Role::Merchant);

pub fn set_merchant_deposit_address(
    deps: DepsMut,
    info: &MessageInfo,
    deposit_address: &str,
) -> Result<Response, ContractError> {
    // no need to ensure that the merchant to be associated with the deposit address really has a merchant role.
    // since it sets to the sender address, which is already checked to be a merchant in `set_deposit_address`.

    Ok(Response::new().add_attributes(action_attrs(
        "set_merchant_deposit_address",
        MERCHANT_DEPOSIT_ADDRESS.set_deposit_address(
            deps,
            info,
            info.sender.as_ref(),
            deposit_address,
        )?,
    )))
}

pub fn get_merchant_deposit_address(deps: Deps, merchant: &Addr) -> Result<String, StdError> {
    MERCHANT_DEPOSIT_ADDRESS
        .get_deposit_address(deps, merchant)?
        .ok_or_else(|| {
            StdError::not_found(format!(
                "No merchant deposit address found for `{merchant}`"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use crate::auth::{custodian, governor, member_manager, merchant};

    #[test]
    fn test_custodian_deposit_address_per_merchant() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant_1 = "osmo1merchant1";
        let merchant_2 = "osmo1merchant2";
        let non_merchant = "osmo1nonmerchant";
        let deposit_address_1 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let deposit_address_2 = "bc1q35rayrk92pvwamwm4n2hsd3epez2g2tqcqa0fx";

        // setup
        governor::initialize_governor(deps.as_mut(), governor).unwrap();
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(member_manager, &[]), custodian)
            .unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant_1).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant_2).unwrap();

        // no custodian deposit address set yet
        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap_err(),
            StdError::not_found(format!(
                "No custodian deposit address found for `{merchant_1}`"
            ))
        );
        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap_err(),
            StdError::not_found(format!(
                "No custodian deposit address found for `{merchant_2}`"
            ))
        );

        // non custodian cannot set custodian deposit address
        assert_eq!(
            set_custodian_deposit_address(
                deps.as_mut(),
                &mock_info(merchant_1, &[]),
                merchant_1,
                deposit_address_1,
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );

        // set custodian deposit address for non merchant should fail
        assert_eq!(
            set_custodian_deposit_address(
                deps.as_mut(),
                &mock_info(custodian, &[]),
                non_merchant,
                deposit_address_1,
            )
            .unwrap_err(),
            ContractError::DepositAddressAssociatedByNonMerchant {
                address: non_merchant.to_string()
            }
        );

        // set custodian deposit address for merchant 1
        set_custodian_deposit_address(
            deps.as_mut(),
            &mock_info(custodian, &[]),
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
            &mock_info(custodian, &[]),
            merchant_2,
            deposit_address_2,
        )
        .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap(),
            deposit_address_2.to_string()
        );
    }
    #[test]
    fn test_merchant_deposit_address() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant_1 = "osmo1merchant1";
        let merchant_2 = "osmo1merchant2";
        let deposit_address_1 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let deposit_address_2 = "bc1q35rayrk92pvwamwm4n2hsd3epez2g2tqcqa0fx";

        // setup
        governor::initialize_governor(deps.as_mut(), governor).unwrap();
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(member_manager, &[]), custodian)
            .unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant_1).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant_2).unwrap();

        // no merchant deposit address set yet
        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap_err(),
            StdError::not_found(format!(
                "No merchant deposit address found for `{merchant_1}`"
            ))
        );
        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap_err(),
            StdError::not_found(format!(
                "No merchant deposit address found for `{merchant_2}`"
            ))
        );

        // non-merchant cannot set merchant deposit address
        assert_eq!(
            set_merchant_deposit_address(
                deps.as_mut(),
                &mock_info(governor, &[]),
                deposit_address_1,
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );
        assert_eq!(
            set_merchant_deposit_address(
                deps.as_mut(),
                &mock_info(custodian, &[]),
                deposit_address_1,
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );
        assert_eq!(
            set_merchant_deposit_address(
                deps.as_mut(),
                &mock_info("anyone", &[]),
                deposit_address_1,
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );

        // set merchant deposit address for merchant 1
        set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant_1, &[]),
            deposit_address_1,
        )
        .unwrap();

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap(),
            deposit_address_1.to_string()
        );

        // set merchant deposit address for merchant 2
        set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant_2, &[]),
            deposit_address_2,
        )
        .unwrap();

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap(),
            deposit_address_2.to_string()
        );
    }
}

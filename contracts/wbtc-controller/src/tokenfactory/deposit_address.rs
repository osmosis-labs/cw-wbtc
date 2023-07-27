/// `deposit_address` module provides a way to manage deposit addresses for merchants and custodian.
use cosmwasm_std::{attr, ensure, Addr, Attribute, Deps, DepsMut, MessageInfo, Response, StdError};
use cw_storage_plus::Map;

use crate::{
    attrs::action_attrs,
    auth::{allow_only, merchant, Role},
    state::deposit_address::{CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT, MERCHANT_DEPOSIT_ADDRESS},
    ContractError,
};

/// Deposit address tracker keeps track of all deposit addresses.
/// It's used to ensure that a deposit address is not associated with more than one merchant
/// and has single purpose.
pub struct DepositAddresseTracker<'a> {
    tracker: Map<'a, String, ()>,
}

impl<'a> DepositAddresseTracker<'a> {
    pub const fn new(namespace: &'a str) -> Self {
        DepositAddresseTracker {
            tracker: Map::new(namespace),
        }
    }

    pub fn track_associated(&self, deps: DepsMut, address: String) -> Result<(), ContractError> {
        self.tracker
            .save(deps.storage, address, &())
            .map_err(ContractError::from)
    }

    pub fn is_associated(&self, deps: Deps, address: String) -> Result<bool, StdError> {
        Ok(self.tracker.may_load(deps.storage, address)?.is_some())
    }

    pub fn track_disassociated(&self, deps: DepsMut, address: String) {
        self.tracker.remove(deps.storage, address)
    }
}

/// `DepositAddressManager` is a helper struct to manage deposit addresses.
pub struct DepositAddressManager<'a> {
    /// deposit address storage.
    deposit_address: Map<'a, Addr, String>,

    /// deposit address tracker.
    deposit_address_tracker: &'a DepositAddresseTracker<'a>,
}

impl<'a> DepositAddressManager<'a> {
    pub const fn new(
        namespace: &'a str,
        deposit_address_tracker: &'a DepositAddresseTracker,
    ) -> Self {
        DepositAddressManager {
            deposit_address: Map::new(namespace),
            deposit_address_tracker,
        }
    }

    pub fn set_deposit_address(
        &self,
        mut deps: DepsMut,
        info: &MessageInfo,
        merchant: &str,
        deposit_address: Option<&str>,
    ) -> Result<Vec<Attribute>, ContractError> {
        let merchant = deps.api.addr_validate(merchant)?;

        let attrs = vec![
            attr("sender", info.sender.as_str()),
            attr("merchant", merchant.as_str()),
        ];

        match deposit_address {
            // set deposit address if it's not None
            Some(deposit_address) => {
                // ensure that the deposit address is not associated as any kind of deposit address
                ensure!(
                    !self
                        .deposit_address_tracker
                        .is_associated(deps.as_ref(), deposit_address.to_string())?,
                    ContractError::DepositAddressAlreadyAssociated {
                        address: deposit_address.to_string()
                    }
                );

                self.deposit_address
                    .save(deps.storage, merchant, &deposit_address.to_string())?;

                // track if deposit address is associated and should not be used again
                // except already deassociated
                self.deposit_address_tracker
                    .track_associated(deps, deposit_address.to_string())?;

                // add deposit address to the attributes
                Ok(attrs
                    .into_iter()
                    .chain(vec![attr("deposit_address", deposit_address)])
                    .collect())
            }

            // remove deposit address if it's set to None
            None => {
                // deassociate deposit address from tracker if it's associated
                let maybe_deposit_address = self
                    .deposit_address
                    .may_load(deps.storage, merchant.clone())?;

                if let Some(deposit_address) = maybe_deposit_address {
                    self.deposit_address_tracker
                        .track_disassociated(deps.branch(), deposit_address);
                };

                self.deposit_address.remove(deps.storage, merchant);
                Ok(attrs)
            }
        }
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

pub fn set_custodian_deposit_address(
    deps: DepsMut,
    info: &MessageInfo,
    merchant: &str,
    deposit_address: Option<&str>,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

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

pub fn set_merchant_deposit_address(
    deps: DepsMut,
    info: &MessageInfo,
    deposit_address: Option<&str>,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;

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
                Some(deposit_address_1),
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
                Some(deposit_address_1),
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
            Some(deposit_address_1),
        )
        .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap(),
            deposit_address_1.to_string()
        );

        // set duplicated custodian deposit address for merchant 2 should fail
        assert_eq!(
            set_custodian_deposit_address(
                deps.as_mut(),
                &mock_info(custodian, &[]),
                merchant_2,
                Some(deposit_address_1),
            )
            .unwrap_err(),
            ContractError::DepositAddressAlreadyAssociated {
                address: deposit_address_1.to_string()
            }
        );

        // set custodian deposit address for merchant 2
        set_custodian_deposit_address(
            deps.as_mut(),
            &mock_info(custodian, &[]),
            merchant_2,
            Some(deposit_address_2),
        )
        .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap(),
            deposit_address_2.to_string()
        );

        // remove custodian deposit address for merchant 1
        set_custodian_deposit_address(deps.as_mut(), &mock_info(custodian, &[]), merchant_1, None)
            .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap_err(),
            StdError::not_found(format!(
                "No custodian deposit address found for `{merchant_1}`"
            ))
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
                Some(deposit_address_1),
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );
        assert_eq!(
            set_merchant_deposit_address(
                deps.as_mut(),
                &mock_info(custodian, &[]),
                Some(deposit_address_1),
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );
        assert_eq!(
            set_merchant_deposit_address(
                deps.as_mut(),
                &mock_info("anyone", &[]),
                Some(deposit_address_1),
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );

        // set merchant deposit address for merchant 1
        set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant_1, &[]),
            Some(deposit_address_1),
        )
        .unwrap();

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap(),
            deposit_address_1.to_string()
        );

        // set duplicated merchant deposit address for merchant 2 should fail
        assert_eq!(
            set_merchant_deposit_address(
                deps.as_mut(),
                &mock_info(merchant_2, &[]),
                Some(deposit_address_1),
            )
            .unwrap_err(),
            ContractError::DepositAddressAlreadyAssociated {
                address: deposit_address_1.to_string()
            }
        );

        // set merchant deposit address for merchant 2
        set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant_2, &[]),
            Some(deposit_address_2),
        )
        .unwrap();

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap(),
            deposit_address_2.to_string()
        );

        // remove merchant deposit address for merchant 1
        set_merchant_deposit_address(deps.as_mut(), &mock_info(merchant_1, &[]), None).unwrap();

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_1)).unwrap_err(),
            StdError::not_found(format!(
                "No merchant deposit address found for `{merchant_1}`"
            ))
        );
    }

    #[test]
    fn test_cross_deposit_address_association() {
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

        // set merchant deposit address for merchant 1
        set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant_1, &[]),
            Some(deposit_address_1),
        )
        .unwrap();

        // set merchant 1's merchant deposit address as custodian deposit address for merchant 2 should fail
        assert_eq!(
            set_custodian_deposit_address(
                deps.as_mut(),
                &mock_info(custodian, &[]),
                merchant_2,
                Some(deposit_address_1),
            )
            .unwrap_err(),
            ContractError::DepositAddressAlreadyAssociated {
                address: deposit_address_1.to_string()
            }
        );

        // remove merchant 1's merchant deposit address
        set_merchant_deposit_address(deps.as_mut(), &mock_info(merchant_1, &[]), None).unwrap();

        // set old merchant 1's merchant deposit address as custodian deposit address for merchant 2 should succeed
        set_custodian_deposit_address(
            deps.as_mut(),
            &mock_info(custodian, &[]),
            merchant_2,
            Some(deposit_address_1),
        )
        .unwrap();

        assert_eq!(
            get_custodian_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap(),
            deposit_address_1.to_string()
        );

        // set custodian deposit address for merchant 1
        set_custodian_deposit_address(
            deps.as_mut(),
            &mock_info(custodian, &[]),
            merchant_1,
            Some(deposit_address_2),
        )
        .unwrap();

        // set merchant 1's custodian deposit address as merchant deposit address for merchant 2 should fail
        assert_eq!(
            set_merchant_deposit_address(
                deps.as_mut(),
                &mock_info(merchant_2, &[]),
                Some(deposit_address_2),
            )
            .unwrap_err(),
            ContractError::DepositAddressAlreadyAssociated {
                address: deposit_address_2.to_string()
            }
        );

        // remove custodian deposit address for merchant 1
        set_custodian_deposit_address(deps.as_mut(), &mock_info(custodian, &[]), merchant_1, None)
            .unwrap();

        // set old custodian deposit address for merchant 1 as merchant deposit address for merchant 2 should succeed
        set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant_2, &[]),
            Some(deposit_address_2),
        )
        .unwrap();

        assert_eq!(
            get_merchant_deposit_address(deps.as_ref(), &Addr::unchecked(merchant_2)).unwrap(),
            deposit_address_2.to_string()
        );
    }

    #[test]
    fn test_setting_deposit_address_to_none_should_not_cause_error() {
        let mut deps = mock_dependencies();
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant_1 = "osmo1merchant1";
        let merchant_2 = "osmo1merchant2";

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

        // set merchant deposit address for merchant 1 to None
        set_merchant_deposit_address(deps.as_mut(), &mock_info(merchant_1, &[]), None).unwrap();

        // set custodian deposit address for merchant 2 to None
        set_custodian_deposit_address(deps.as_mut(), &mock_info(custodian, &[]), merchant_2, None)
            .unwrap();
    }
}

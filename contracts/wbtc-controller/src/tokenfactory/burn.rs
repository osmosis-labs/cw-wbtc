/// `burn` module provides functionalities to manage burn requests and operations.
use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    attr, ensure, Attribute, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    Uint128,
};
use cw_storage_plus::Item;
use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgBurn;

use crate::{
    attrs::action_attrs,
    auth::{allow_only, Role},
    ContractError,
};

use super::{
    deposit_address,
    request::{Request, RequestManager, RequestWithHash, Status},
    token,
};

/// Burn request status.
#[cw_serde]
pub enum BurnRequestStatus {
    /// The burn request has been executed and pending for tx_id confirmation. This is the initial status.
    Pending,
    /// The burn request has been confirmed by the custodian.
    Confirmed,
}

pub type BurnRequest = Request<BurnRequestStatus>;
pub type BurnRequestWithHash = RequestWithHash<BurnRequestStatus>;

/// `Display` implementation for `BurnRequestStatus`. This is used for serializing the status.
impl Display for BurnRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BurnRequestStatus::Pending => write!(f, "Pending"),
            BurnRequestStatus::Confirmed => write!(f, "Confirmed"),
        }
    }
}

/// `Status` implementation for `BurnRequestStatus`.
/// Ensuring that:
/// - `Executed` is the initial status.
/// - `Executed` is the only updatable status.
impl Status for BurnRequestStatus {
    fn initial() -> Self {
        Self::Pending
    }

    fn is_updatable(&self) -> bool {
        self == &Self::initial()
    }
}

/// Burn request manager.
fn burn_requests<'a>() -> RequestManager<'a, BurnRequestStatus> {
    RequestManager::new(
        "burn_requests",
        "burn_requests__nonce",
        "burn_requests__status_and_nonce",
        "burn_nonce",
    )
}

const MIN_BURN_AMOUNT: Item<Uint128> = Item::new("min_burn_amount");

/// Burn the requested amount of tokens.
/// Only the merchant can burn tokens.
/// This will be executed immediately and created an `Executed` burn request.
/// The custodian will later transfer the burn amount
/// from custodian deposit address to merchant deposit address and confirm the burn request.
pub fn burn(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;

    // ensure the requested amount is greater than the min burn amount
    let min_burn_amount = get_min_burn_amount(deps.as_ref())?;
    ensure!(
        amount >= min_burn_amount,
        ContractError::BurnAmountTooSmall {
            requested_burn_amount: amount,
            min_burn_amount
        }
    );

    let deposit_address =
        deposit_address::get_merchant_deposit_address(deps.as_ref(), &info.sender)?;

    // record burn request
    let (request_hash, request) = burn_requests().issue(
        deps.branch(),
        info.sender.clone(),
        amount,
        // tx_id will later be confirmed by the custodian
        None,
        deposit_address,
        env.block.time,
    )?;

    // construct burn message
    let denom = token::get_token_denom(deps.storage)?;
    let token_to_burn = Coin::new(request.amount.u128(), denom);

    // burn the requested amount of tokens from sender, which can only be the merchant
    let burn_msg: CosmosMsg = MsgBurn {
        sender: env.contract.address.to_string(),
        amount: Some(token_to_burn.into()),
        burn_from_address: info.sender.to_string(),
    }
    .into();

    // construct attributes
    let mut attrs = action_attrs("burn", <Vec<Attribute>>::from(&request.data()));
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_message(burn_msg).add_attributes(attrs))
}

/// Confirm the burn request. Only the custodian can confirm the burn request.
/// This will be called after the custodian has transferred the burn amount
/// from custodian deposit address to merchant deposit address.
/// And confirm that with `tx_id`.
pub fn confirm_burn_request(
    mut deps: DepsMut,

    info: MessageInfo,
    request_hash: String,
    tx_id: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

    burn_requests().check_and_update_request_status(
        deps.branch(),
        request_hash.as_str(),
        BurnRequestStatus::Confirmed,
        |_| Ok(()),
    )?;

    let request = burn_requests().confirm_tx(deps, request_hash.as_str(), tx_id)?;

    let mut attrs = action_attrs(
        "confirm_burn_request",
        <Vec<Attribute>>::from(&request.data()),
    );
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
}

pub fn get_burn_request_by_nonce(deps: Deps, nonce: &Uint128) -> StdResult<(String, BurnRequest)> {
    burn_requests().get_request_by_nonce(deps, nonce)
}

pub fn get_burn_request_by_hash(deps: Deps, request_hash: &str) -> StdResult<BurnRequest> {
    burn_requests().get_request(deps, request_hash)
}

pub fn get_burn_request_count(deps: Deps) -> StdResult<Uint128> {
    burn_requests().get_request_count(deps)
}

/// Set the minimum burn amount. Only the custodian can set the minimum burn amount.
pub fn set_min_burn_amount(
    deps: DepsMut,
    info: &MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

    MIN_BURN_AMOUNT.save(deps.storage, &amount)?;

    let attrs = action_attrs("set_min_burn_amount", vec![attr("amount", amount)]);
    Ok(Response::new().add_attributes(attrs))
}

pub fn get_min_burn_amount(deps: Deps) -> StdResult<Uint128> {
    Ok(MIN_BURN_AMOUNT.may_load(deps.storage)?.unwrap_or_default())
}

pub fn list_burn_requests(
    deps: Deps,
    limit: Option<u32>,
    start_after_nonce: Option<Uint128>,
    status: Option<BurnRequestStatus>,
) -> StdResult<Vec<BurnRequestWithHash>> {
    burn_requests().list_requests(deps, limit, start_after_nonce, status)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{
        attr,
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, Attribute, BlockInfo, Coin, DepsMut, Env, MessageInfo, SubMsg, Timestamp,
        TransactionInfo, Uint128,
    };
    use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgBurn;

    use crate::{
        auth::{custodian, governor, member_manager, merchant},
        tokenfactory::{
            burn::{burn_requests, confirm_burn_request, set_min_burn_amount, BurnRequestStatus},
            deposit_address,
            request::RequestData,
            token,
        },
        ContractError,
    };

    use super::burn;

    #[test]
    fn test_burn() {
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";

        let deposit_address = "bc1depositaddress";
        let contract_addr =
            Addr::unchecked("osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9");
        let mut deps = mock_dependencies();

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
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant).unwrap();

        deposit_address::set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant, &[]),
            deposit_address,
        )
        .unwrap();

        token::set_token_denom(
            deps.as_mut().storage,
            &format!("factory/{}/wbtc", contract_addr),
        )
        .unwrap();

        let amount = Uint128::new(100_000_000);
        let denom = token::get_token_denom(deps.as_ref().storage).unwrap();
        let token_to_burn = Coin::new(amount.u128(), denom);

        let timestamp = Timestamp::from_seconds(1689069540);

        let env = Env {
            block: BlockInfo {
                height: 1,
                time: timestamp,
                chain_id: "osmosis-1".to_string(),
            },
            transaction: Some(TransactionInfo { index: 1 }),
            contract: cosmwasm_std::ContractInfo {
                address: contract_addr.clone(),
            },
        };

        let burn_fixture = |deps: DepsMut, info: MessageInfo| burn(deps, env.clone(), info, amount);

        // burn request count = 0
        assert_eq!(
            burn_requests().get_request_count(deps.as_ref()).unwrap(),
            Uint128::zero()
        );

        // burn success
        let res = burn_fixture(deps.as_mut(), mock_info(merchant, &[])).unwrap();

        // sends burn msg
        assert_eq!(
            res.messages,
            vec![SubMsg::new(MsgBurn {
                sender: contract_addr.to_string(),
                amount: Some(token_to_burn.into()),
                burn_from_address: merchant.to_string(),
            })]
        );

        // create new burn request
        let request_hash = res
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        let request = burn_requests()
            .get_request(deps.as_ref(), request_hash.as_str())
            .unwrap();

        assert_eq!(request.status, BurnRequestStatus::Pending);

        assert_eq!(
            request.data(),
            RequestData {
                requester: Addr::unchecked(merchant),
                amount,
                tx_id: None,
                deposit_address: deposit_address.to_string(),
                nonce: Uint128::zero(),
                timestamp
            }
        );

        // burn request count = 1
        assert_eq!(
            burn_requests().get_request_count(deps.as_ref()).unwrap(),
            Uint128::one()
        );

        // burn fail with unauthorized if not merchant
        assert_eq!(
            burn_fixture(deps.as_mut(), mock_info(governor, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            burn_fixture(deps.as_mut(), mock_info(custodian, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );
    }

    #[test]
    fn test_confirm_burn() {
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";

        let deposit_address = "bc1depositaddress";
        let contract_addr =
            Addr::unchecked("osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9");
        let mut deps = mock_dependencies();

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
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant).unwrap();

        deposit_address::set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant, &[]),
            deposit_address,
        )
        .unwrap();

        token::set_token_denom(
            deps.as_mut().storage,
            &format!("factory/{}/wbtc", contract_addr),
        )
        .unwrap();

        let amount = Uint128::new(100_000_000);

        let env = Env {
            block: BlockInfo {
                height: 1,
                time: Timestamp::from_seconds(1689069540),
                chain_id: "osmosis-1".to_string(),
            },
            transaction: Some(TransactionInfo { index: 1 }),
            contract: cosmwasm_std::ContractInfo {
                address: contract_addr,
            },
        };

        let res = burn(deps.as_mut(), env, mock_info(merchant, &[]), amount).unwrap();

        let request_hash = res
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        let request_before = burn_requests()
            .get_request(deps.as_ref(), request_hash.as_str())
            .unwrap();

        assert_eq!(request_before.status, BurnRequestStatus::Pending);
        assert_eq!(request_before.tx_id, None);

        let res = confirm_burn_request(
            deps.as_mut(),
            mock_info(custodian, &[]),
            request_hash.clone(),
            "btc_tx_id".to_string(),
        )
        .unwrap();

        let request_after = burn_requests()
            .get_request(deps.as_ref(), request_hash.as_str())
            .unwrap();

        assert_eq!(
            res.attributes
                .into_iter()
                .skip(1) // remove "method"
                .rev()
                .skip(1) // remove ""
                .rev()
                .collect::<Vec<_>>(),
            <Vec<Attribute>>::from(&request_after.clone().data())
        );

        assert_eq!(request_after.status, BurnRequestStatus::Confirmed);
        assert_eq!(request_after.tx_id, Some("btc_tx_id".to_string()));
    }

    #[test]
    fn test_min_burn_amount() {
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";

        let deposit_address = "bc1depositaddress";
        let contract_addr =
            Addr::unchecked("osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9");
        let mut deps = mock_dependencies();

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
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant).unwrap();

        deposit_address::set_merchant_deposit_address(
            deps.as_mut(),
            &mock_info(merchant, &[]),
            deposit_address,
        )
        .unwrap();

        token::set_token_denom(
            deps.as_mut().storage,
            &format!("factory/{}/wbtc", contract_addr),
        )
        .unwrap();

        // burn small amount
        let requested_burn_amount = Uint128::new(1);
        let min_burn_amount = Uint128::new(100);

        // if nothing is set, min burn amount is 0
        assert!(burn(
            deps.as_mut(),
            mock_env(),
            mock_info(merchant, &[]),
            requested_burn_amount
        )
        .is_ok());

        // set min burn amount
        // only custodian can set
        assert_eq!(
            set_min_burn_amount(deps.as_mut(), &mock_info(governor, &[]), min_burn_amount)
                .unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            set_min_burn_amount(deps.as_mut(), &mock_info(custodian, &[]), min_burn_amount)
                .unwrap()
                .attributes,
            vec![attr("action", "set_min_burn_amount"), attr("amount", "100"),]
        );

        assert_eq!(
            burn(
                deps.as_mut(),
                mock_env(),
                mock_info(merchant, &[]),
                requested_burn_amount
            )
            .unwrap_err(),
            ContractError::BurnAmountTooSmall {
                requested_burn_amount,
                min_burn_amount,
            }
        );

        // burn at least min burn amount should succeed
        assert!(burn(
            deps.as_mut(),
            mock_env(),
            mock_info(merchant, &[]),
            min_burn_amount
        )
        .is_ok());

        // burn more than min burn amount should succeed
        assert!(burn(
            deps.as_mut(),
            mock_env(),
            mock_info(merchant, &[]),
            min_burn_amount + Uint128::new(1)
        )
        .is_ok());

        // burn less than min burn amount should fail
        assert_eq!(
            burn(
                deps.as_mut(),
                mock_env(),
                mock_info(merchant, &[]),
                min_burn_amount - Uint128::new(1)
            )
            .unwrap_err(),
            ContractError::BurnAmountTooSmall {
                requested_burn_amount: min_burn_amount - Uint128::new(1),
                min_burn_amount,
            }
        );
    }
}

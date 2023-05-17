use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    attr, ensure, Attribute, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    Uint128,
};
use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgBurn;

use crate::{
    auth::{allow_only, Role},
    helpers::action_attrs,
    ContractError,
};

use super::{
    deposit_address,
    request::{Request, RequestData, RequestManager, RequestWithHash, Status, TxId},
    token,
};

/// Burn request status.
#[cw_serde]
pub enum BurnRequestStatus {
    /// The burn request has been executed. This is the initial status.
    Executed,
    /// The burn request has been confirmed by the custodian.
    Confirmed,
}

pub type BurnRequest = Request<BurnRequestStatus>;
pub type BurnRequestWithHash = RequestWithHash<BurnRequestStatus>;

/// `Display` implementation for `BurnRequestStatus`. This is used for serializing the status.
impl Display for BurnRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BurnRequestStatus::Executed => write!(f, "Executed"),
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
        Self::Executed
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

    let deposit_address =
        deposit_address::get_merchant_deposit_address(deps.as_ref(), &info.sender)?;

    // record burn request
    let (request_hash, request) = burn_requests().issue(
        deps.branch(),
        info.sender,
        amount,
        // tx_id will later be confirmed by the custodian
        TxId::Pending,
        deposit_address,
        env.block,
        env.transaction,
        env.contract.clone(),
    )?;

    // construct attributes
    let mut attrs = action_attrs("burn", <Vec<Attribute>>::from(&request.data));
    attrs.extend(vec![attr("request_hash", request_hash)]);

    // construct burn message
    let RequestData { amount, .. } = request.data;
    let denom = token::get_token_denom(deps.storage)?;
    let token_to_burn = Coin::new(amount.u128(), denom);
    let token_to_burn_vec = vec![token_to_burn.clone()];

    // ensure that funds sent from msg sender matches the amount requested
    ensure!(
        info.funds == token_to_burn_vec,
        ContractError::MismatchedFunds {
            expected: token_to_burn_vec,
            actual: info.funds,
        }
    );

    // burn the requested amount of tokens
    let burn_msg: CosmosMsg = MsgBurn {
        sender: env.contract.address.to_string(),
        amount: Some(token_to_burn.into()),
    }
    .into();

    Ok(Response::new().add_message(burn_msg).add_attributes(attrs))
}

/// Confirm the burn request. Only the custodian can confirm the burn request.
/// This will be called after the custodian has transferred the burn amount
/// from custodian deposit address to merchant deposit address.
/// And confirm that with `tx_id`.
pub fn confirm_burn_request(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    request_hash: String,
    tx_id: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

    let request = burn_requests().check_and_update_request_status(
        deps.branch(),
        request_hash.as_str(),
        BurnRequestStatus::Confirmed,
        |request| {
            // ensure contract address matched request's contract address
            ensure!(
                request.data.contract.address == env.contract.address,
                ContractError::Std(cosmwasm_std::StdError::generic_err(
                    "unreachable: contract address mismatch"
                ))
            );

            Ok(())
        },
    )?;

    burn_requests().confirm_tx(deps, request_hash.as_str(), tx_id)?;

    let mut attrs = action_attrs(
        "confirm_burn_request",
        <Vec<Attribute>>::from(&request.data),
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
        testing::{mock_dependencies, mock_info},
        Addr, BlockInfo, Coin, DepsMut, Env, MessageInfo, SubMsg, Timestamp, TransactionInfo,
        Uint128,
    };
    use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgBurn;

    use crate::{
        auth::{custodian, merchant, owner},
        tokenfactory::{
            burn::{burn_requests, confirm_burn_request, BurnRequestStatus},
            deposit_address,
            request::{RequestData, TxId},
            token,
        },
        ContractError,
    };

    use super::burn;

    #[test]
    fn test_burn() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";

        let deposit_address = "bc1depositaddress";
        let contract_addr =
            Addr::unchecked("osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9");
        let mut deps = mock_dependencies();

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

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
        let token_to_burn = Coin::new(amount.u128(), denom.clone());

        let env = Env {
            block: BlockInfo {
                height: 1,
                time: Timestamp::from_seconds(1689069540),
                chain_id: "osmosis-1".to_string(),
            },
            transaction: Some(TransactionInfo { index: 1 }),
            contract: cosmwasm_std::ContractInfo {
                address: contract_addr.clone(),
            },
        };

        let burn_fixture = |deps: DepsMut, info: MessageInfo| burn(deps, env.clone(), info, amount);

        // burn success
        let res =
            burn_fixture(deps.as_mut(), mock_info(merchant, &[token_to_burn.clone()])).unwrap();

        // sends burn msg
        assert_eq!(
            res.messages,
            vec![SubMsg::new(MsgBurn {
                sender: contract_addr.to_string(),
                amount: Some(token_to_burn.clone().into())
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

        assert_eq!(request.status, BurnRequestStatus::Executed);

        assert_eq!(
            request.data,
            RequestData {
                requester: Addr::unchecked(merchant),
                amount,
                tx_id: TxId::Pending,
                deposit_address: deposit_address.to_string(),
                block: env.block.clone(),
                transaction: env.transaction.clone(),
                contract: env.contract.clone(),
                nonce: Uint128::zero(),
            }
        );

        // burn fail with unauthorized if not merchant
        assert_eq!(
            burn_fixture(deps.as_mut(), mock_info(owner, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            burn_fixture(deps.as_mut(), mock_info(custodian, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );

        // burn fail if sent funds don't match with burn amount
        assert_eq!(
            burn_fixture(deps.as_mut(), mock_info(merchant, &[])).unwrap_err(),
            ContractError::MismatchedFunds {
                expected: vec![token_to_burn.clone()],
                actual: vec![],
            }
        );

        assert_eq!(
            burn_fixture(
                deps.as_mut(),
                mock_info(merchant, &[Coin::new(999, denom.clone())])
            )
            .unwrap_err(),
            ContractError::MismatchedFunds {
                expected: vec![token_to_burn.clone()],
                actual: vec![Coin::new(999, denom.clone())],
            }
        );

        assert_eq!(
            burn_fixture(
                deps.as_mut(),
                mock_info(merchant, &[Coin::new(9999999999999, denom.clone())])
            )
            .unwrap_err(),
            ContractError::MismatchedFunds {
                expected: vec![token_to_burn.clone()],
                actual: vec![Coin::new(9999999999999, denom)],
            }
        );

        assert_eq!(
            burn_fixture(
                deps.as_mut(),
                mock_info(merchant, &[token_to_burn.clone(), Coin::new(1000, "uosmo")])
            )
            .unwrap_err(),
            ContractError::MismatchedFunds {
                expected: vec![token_to_burn.clone()],
                actual: vec![token_to_burn.clone(), Coin::new(1000, "uosmo")],
            }
        );
    }

    #[test]
    fn test_confirm_burn() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";

        let deposit_address = "bc1depositaddress";
        let contract_addr =
            Addr::unchecked("osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9");
        let mut deps = mock_dependencies();

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

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
        let token_to_burn = Coin::new(amount.u128(), denom.clone());

        let env = Env {
            block: BlockInfo {
                height: 1,
                time: Timestamp::from_seconds(1689069540),
                chain_id: "osmosis-1".to_string(),
            },
            transaction: Some(TransactionInfo { index: 1 }),
            contract: cosmwasm_std::ContractInfo {
                address: contract_addr.clone(),
            },
        };

        let res = burn(
            deps.as_mut(),
            env.clone(),
            mock_info(merchant, &[token_to_burn.clone()]),
            amount,
        )
        .unwrap();

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

        assert_eq!(request_before.status, BurnRequestStatus::Executed);
        assert_eq!(request_before.data.tx_id, TxId::Pending);

        confirm_burn_request(
            deps.as_mut(),
            env,
            mock_info(custodian, &[]),
            request_hash.clone(),
            "btc_tx_id".to_string(),
        )
        .unwrap();

        let request_after = burn_requests()
            .get_request(deps.as_ref(), request_hash.as_str())
            .unwrap();

        assert_eq!(request_after.status, BurnRequestStatus::Confirmed);
        assert_eq!(
            request_after.data.tx_id,
            TxId::Confirmed("btc_tx_id".to_string())
        );
    }
}

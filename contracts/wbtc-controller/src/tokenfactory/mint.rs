/// `mint` module provides functionalities to manage mint requests and operations.
use std::fmt::Display;

use crate::{
    auth::{allow_only, Role},
    helpers::action_attrs,
    tokenfactory::request::RequestData,
    ContractError,
};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    attr, ensure, Addr, Attribute, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    Uint128,
};
use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgMint;

use super::{
    request::{Request, RequestManager, RequestWithHash, Status, TxId},
    token,
};

/// Mint request status.
#[cw_serde]
pub enum MintRequestStatus {
    /// Initial status, waiting for approval.
    Pending,

    /// Approved status, it can be assumed that the mint request is processed.
    /// This status can no longer be updated.
    Approved,

    /// Cancelled status. This status can no longer be updated.
    Cancelled,

    /// Rejected status, This status can no longer be updated.
    Rejected,
}

pub type MintRequest = Request<MintRequestStatus>;
pub type MintRequestWithHash = RequestWithHash<MintRequestStatus>;

/// `Display` implementation for `MintRequestStatus`. This is mainly used for attribute serialization.
impl Display for MintRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintRequestStatus::Pending => write!(f, "Pending"),
            MintRequestStatus::Approved => write!(f, "Approved"),
            MintRequestStatus::Cancelled => write!(f, "Cancelled"),
            MintRequestStatus::Rejected => write!(f, "Rejected"),
        }
    }
}

/// `Status` implementation for `MintRequestStatus`.
/// Ensuring that:
/// - `MintRequestStatus` is only initialized as `Pending` status.
/// - `MintRequestStatus` is only updatable when it is in `Pending` status.
impl Status for MintRequestStatus {
    fn initial() -> Self {
        Self::Pending
    }

    fn is_updatable(&self) -> bool {
        self == &Self::initial()
    }
}

/// Mint request storage.
fn mint_requests<'a>() -> RequestManager<'a, MintRequestStatus> {
    RequestManager::new(
        "mint_requests",
        "mint_requests__nonce",
        "mint_requests__status_and_nonce",
        "mint_nonce",
    )
}

/// Issue a mint request. This can only be done by the merchant.
/// This will create a new mint request with `Pending` status.
/// The mint request can be approved or rejected by the custodian.
/// The mint request can be cancelled by the merchant.
pub fn issue_mint_request(
    deps: DepsMut,
    info: MessageInfo,
    env: Env,
    amount: Uint128,
    tx_id: String,
    deposit_address: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;

    let (request_hash, request) = mint_requests().issue(
        deps,
        info.sender,
        amount,
        TxId::Confirmed(tx_id),
        deposit_address,
        env.block,
        env.transaction,
        env.contract,
    )?;

    let mut attrs = action_attrs("issue_mint_request", <Vec<Attribute>>::from(&request.data));
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
}

/// Cancel a mint request. This can only be done by the merchant.
/// This will update the mint request status to `Cancelled`.
pub fn cancel_mint_request(
    deps: DepsMut,
    info: MessageInfo,
    contract_address: Addr,
    request_hash: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;
    // update request status to `Cancelled`
    let request = mint_requests().check_and_update_request_status(
        deps,
        &request_hash,
        MintRequestStatus::Cancelled,
        |request| {
            // ensure sender is the requester
            ensure!(
                request.data.requester == info.sender,
                ContractError::Unauthorized {}
            );

            // ensure contract address matched request's contract address
            ensure!(
                request.data.contract.address == contract_address,
                ContractError::Std(cosmwasm_std::StdError::generic_err(
                    "unreachable: contract address mismatch"
                ))
            );

            Ok(())
        },
    )?;

    // construct event attributes
    let mut attrs = action_attrs("cancel_mint_request", <Vec<Attribute>>::from(&request.data));
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
}

/// Approve a mint request. This can only be done by the custodian after custodian has validated the request.
/// This will update the mint request status to `Approved` and mint the requested amount of tokens to the merchant address.
pub fn approve_mint_request(
    mut deps: DepsMut,
    info: MessageInfo,
    contract_address: Addr,
    request_hash: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

    let request_data = mint_requests()
        .check_and_update_request_status(
            deps.branch(),
            &request_hash,
            MintRequestStatus::Approved,
            |request| {
                ensure!(
                    request.data.contract.address == contract_address,
                    ContractError::Std(cosmwasm_std::StdError::generic_err(
                        "unreachable: contract address mismatch"
                    ))
                );

                Ok(())
            },
        )?
        .data;

    // construct event attributes
    let mut attrs = action_attrs("cancel_mint_request", <Vec<Attribute>>::from(&request_data));
    attrs.extend(vec![attr("request_hash", request_hash)]);

    let RequestData {
        requester, amount, ..
    } = request_data;

    let denom = token::get_token_denom(deps.storage)?;

    let token_to_mint = Coin::new(amount.u128(), denom);
    let mint_to_requester_msg = MsgMint {
        sender: contract_address.to_string(),
        amount: Some(token_to_mint.into()),
        mint_to_address: requester.to_string(),
    };

    Ok(Response::new()
        .add_message(mint_to_requester_msg)
        .add_attributes(attrs))
}

/// Reject a mint request. This can only be done by the custodian after custodian has validated the request.
pub fn reject_mint_request(
    deps: DepsMut,
    info: MessageInfo,
    contract_address: Addr,
    request_hash: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;
    let request_data = mint_requests()
        .check_and_update_request_status(
            deps,
            &request_hash,
            MintRequestStatus::Rejected,
            |request| {
                ensure!(
                    request.data.contract.address == contract_address,
                    ContractError::Std(cosmwasm_std::StdError::generic_err(
                        "unreachable: contract address mismatch"
                    ))
                );

                Ok(())
            },
        )?
        .data;

    let mut attrs = action_attrs("reject_mint_request", <Vec<Attribute>>::from(&request_data));
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
}

pub fn get_mint_request_by_nonce(deps: Deps, nonce: &Uint128) -> StdResult<(String, MintRequest)> {
    mint_requests().get_request_by_nonce(deps, nonce)
}

pub fn get_mint_request_by_hash(deps: Deps, request_hash: &str) -> StdResult<MintRequest> {
    mint_requests().get_request(deps, request_hash)
}

pub fn get_mint_request_count(deps: Deps) -> StdResult<Uint128> {
    mint_requests().get_request_count(deps)
}

pub fn list_mint_requests(
    deps: Deps,
    limit: Option<u32>,
    start_after_nonce: Option<Uint128>,
    status: Option<MintRequestStatus>,
) -> StdResult<Vec<MintRequestWithHash>> {
    mint_requests().list_requests(deps, limit, start_after_nonce, status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, BlockInfo, Coin, DepsMut, Env, Response, StdError, SubMsg, Timestamp,
        TransactionInfo, Uint128,
    };
    use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgMint;

    use crate::{
        auth::{custodian, merchant, owner},
        contract,
        helpers::test_helpers::setup_contract,
        ContractError,
    };

    #[test]
    fn test_issue_mint_request() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let mut deps = mock_dependencies();

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

        let issue_mint_request_fixture = |deps: DepsMut, sender: &str| {
            issue_mint_request(
                deps,
                mock_info(sender, &[]),
                Env {
                    block: BlockInfo {
                        height: 1,
                        time: Timestamp::from_seconds(1689069540),
                        chain_id: "osmosis-1".to_string(),
                    },
                    transaction: Some(TransactionInfo { index: 1 }),
                    contract: cosmwasm_std::ContractInfo {
                        address: Addr::unchecked(
                            "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9",
                        ),
                    },
                },
                Uint128::new(100_000_000),
                "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf".to_string(),
                "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun".to_string(),
            )
        };

        // add mint request fail with unauthorized if not merchant
        assert_eq!(
            issue_mint_request_fixture(deps.as_mut(), owner).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            issue_mint_request_fixture(deps.as_mut(), custodian).unwrap_err(),
            ContractError::Unauthorized {}
        );

        let hash_on_nonce_0 = "cC2AqyP3sgYXmlq+QfOZ+VWucw9HVj/tw2CkqPE6h9E=";

        assert_eq!(
            issue_mint_request_fixture(deps.as_mut(), merchant).unwrap(),
            Response::new()
                .add_attribute("action", "issue_mint_request")
                .add_attribute("requester", merchant)
                .add_attribute("amount", "100000000")
                .add_attribute(
                    "tx_id",
                    "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf"
                )
                .add_attribute(
                    "deposit_address",
                    "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun"
                )
                .add_attribute("block_height", "1")
                .add_attribute("timestamp", "1689069540000000000")
                .add_attribute("transaction_index", "1")
                .add_attribute("nonce", "0")
                .add_attribute("request_hash", hash_on_nonce_0)
        );

        // mint request should be saved
        let request = mint_requests()
            .get_request(deps.as_ref(), hash_on_nonce_0)
            .unwrap();

        assert_eq!(request.data.nonce, Uint128::new(0));
        assert_eq!(request.status, MintRequestStatus::Pending);
        assert_eq!(request.data.hash().unwrap().to_base64(), hash_on_nonce_0);

        let (request_hash_by_nonce, request_by_nonce) =
            get_mint_request_by_nonce(deps.as_ref(), &Uint128::new(0)).unwrap();

        assert_eq!(request_hash_by_nonce, hash_on_nonce_0);
        assert_eq!(request, request_by_nonce);

        // nonce should be incremented
        assert_eq!(
            mint_requests().get_request_count(deps.as_ref()).unwrap(),
            Uint128::new(1)
        );

        // same request with same sender, even on the same tx must result in different hash
        let hash_on_nonce_1 = issue_mint_request_fixture(deps.as_mut(), merchant)
            .unwrap()
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        assert_ne!(hash_on_nonce_0, hash_on_nonce_1);

        let request = mint_requests()
            .get_request(deps.as_ref(), &hash_on_nonce_1)
            .unwrap();

        let (request_hash_by_nonce, request_by_nonce) =
            get_mint_request_by_nonce(deps.as_ref(), &Uint128::new(1)).unwrap();

        assert_eq!(request_hash_by_nonce, hash_on_nonce_1);
        assert_eq!(request, request_by_nonce);

        // nonce should be incremented
        assert_eq!(
            mint_requests().get_request_count(deps.as_ref()).unwrap(),
            Uint128::new(2)
        );
    }

    #[test]
    fn test_cancel_mint_request() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let contract = "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9";
        let mut deps = mock_dependencies();

        let amount = Uint128::new(100_000_000);

        // setup
        setup_contract(deps.as_mut(), contract, owner, "wbtc").unwrap();

        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

        // add mint request
        let res = issue_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(1689069540),
                    chain_id: "osmosis-1".to_string(),
                },
                transaction: Some(TransactionInfo { index: 1 }),
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(contract),
                },
            },
            amount,
            "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf".to_string(),
            "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun".to_string(),
        )
        .unwrap();

        let request_hash = res
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        // cancel mint request fail with unauthorized if not requester
        let err = cancel_mint_request(
            deps.as_mut(),
            mock_info(owner, &[]),
            Addr::unchecked(contract),
            request_hash.clone(),
        )
        .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // cancel mint request succeed if requester
        cancel_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Addr::unchecked(contract),
            request_hash,
        )
        .unwrap();
    }

    #[test]
    fn test_approve_mint_request() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let contract = "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9";
        let mut deps = mock_dependencies();

        let amount = Uint128::new(100_000_000);

        // setup
        let denom = setup_contract(deps.as_mut(), contract, owner, "wbtc").unwrap();

        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

        // add mint request
        let res = issue_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(1689069540),
                    chain_id: "osmosis-1".to_string(),
                },
                transaction: Some(TransactionInfo { index: 1 }),
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(contract),
                },
            },
            amount,
            "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf".to_string(),
            "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun".to_string(),
        )
        .unwrap();

        let request_hash = res
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        // approve mint request with non existing request hash by custodian should fail
        let err = approve_mint_request(
            deps.as_mut(),
            mock_info(custodian, &[]),
            Addr::unchecked(contract),
            "non-existing-request-hash".to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            StdError::not_found("Request with hash `non-existing-request-hash`".to_string()).into()
        );

        // approve mint request with non existing request hash by merchant should fail
        let err = approve_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Addr::unchecked(contract),
            "non-existing-request-hash".to_string(),
        )
        .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // approve mint request with exising request hash by merchant should fail
        let err = approve_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Addr::unchecked(contract),
            request_hash.clone(),
        )
        .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // approve mint request with exising request hash by custodian should succeed
        let res = approve_mint_request(
            deps.as_mut(),
            mock_info(custodian, &[]),
            Addr::unchecked(contract),
            request_hash.clone(),
        )
        .unwrap();

        // and should mint new token to merchant
        assert_eq!(
            res.messages,
            vec![SubMsg::new(MsgMint {
                sender: contract.to_string(),
                amount: Some(Coin::new(amount.u128(), denom).into()),
                mint_to_address: merchant.to_string(),
            }),]
        );

        // check mint request status
        let request = mint_requests()
            .get_request(deps.as_ref(), &request_hash)
            .unwrap();

        assert_eq!(request.status, MintRequestStatus::Approved);
    }

    #[test]
    fn test_reject_mint_request() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let contract = "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9";
        let mut deps = mock_dependencies();

        let denom = "factory/osmo1owner/wbtc";
        let amount = Uint128::new(100_000_000);

        // setup
        contract::instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info(owner, &[]),
            crate::msg::InstantiateMsg {
                owner: owner.to_string(),
                subdenom: denom.to_string(),
            },
        )
        .unwrap();

        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

        // add mint request
        let res = issue_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(1689069540),
                    chain_id: "osmosis-1".to_string(),
                },
                transaction: Some(TransactionInfo { index: 1 }),
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(contract),
                },
            },
            amount,
            "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf".to_string(),
            "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun".to_string(),
        )
        .unwrap();

        let request_hash = res
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        // reject mint request with non existing request hash by custodian should fail
        let err = reject_mint_request(
            deps.as_mut(),
            mock_info(custodian, &[]),
            Addr::unchecked(contract),
            "non-existing-request-hash".to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            StdError::not_found("Request with hash `non-existing-request-hash`".to_string()).into()
        );

        // reject mint request with non existing request hash by merchant should fail
        let err = reject_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Addr::unchecked(contract),
            "non-existing-request-hash".to_string(),
        )
        .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // reject mint request with exising request hash by merchant should fail
        let err = reject_mint_request(
            deps.as_mut(),
            mock_info(merchant, &[]),
            Addr::unchecked(contract),
            request_hash.clone(),
        )
        .unwrap_err();

        assert_eq!(err, ContractError::Unauthorized {});

        // reject mint request with exising request hash by custodian should succeed
        let _res = reject_mint_request(
            deps.as_mut(),
            mock_info(custodian, &[]),
            Addr::unchecked(contract),
            request_hash.clone(),
        )
        .unwrap();

        // check mint request status
        let request = mint_requests()
            .get_request(deps.as_ref(), &request_hash)
            .unwrap();

        assert_eq!(request.status, MintRequestStatus::Rejected);
    }
}

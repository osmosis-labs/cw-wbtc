use crate::{
    auth::{allow_only, Role},
    tokenfactory::request::{RequestInfo, RequestStatus},
    tokenfactory::token::TOKEN_DENOM,
    ContractError,
};
use cosmwasm_std::{
    attr, ensure, Addr, BankMsg, Coin, CosmosMsg, DepsMut, Env, Event, MessageInfo, Response,
    Uint128,
};
use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgMint;

use super::request::RequestManager;

const MINT_REQUESTS: RequestManager = RequestManager::new("mint_requests", "mint_nonce");

pub fn issue_mint_request(
    mut deps: DepsMut,
    info: MessageInfo,
    env: Env,
    amount: Uint128,
    tx_id: String,
    deposit_address: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;
    let event = Event::new("mint_request_issued")
        .add_attribute("requester", info.sender.as_str())
        .add_attribute("amount", amount)
        .add_attribute("tx_id", tx_id.as_str())
        .add_attribute("deposit_address", deposit_address.as_str())
        .add_attribute("block_height", env.block.height.to_string())
        .add_attribute("timestamp", env.block.time.nanos().to_string())
        .add_attribute(
            "transaction_index",
            env.transaction
                .as_ref()
                .map(|t| t.index.to_string())
                .unwrap_or_default(),
        );

    let (request_hash, request) = MINT_REQUESTS.issue_request(
        &mut deps,
        info.sender,
        amount,
        tx_id,
        deposit_address,
        env.block,
        env.transaction,
        env.contract,
    )?;

    // derived attributes
    let event = event
        .add_attribute("nonce", request.info.nonce.to_string())
        .add_attribute("request_hash", request_hash);

    Ok(Response::new().add_event(event))
}

pub fn approve_mint_request(
    mut deps: DepsMut,
    info: MessageInfo,
    contract_address: Addr,
    request_hash: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

    let RequestInfo {
        requester,
        amount,
        tx_id,
        deposit_address,
        block,
        transaction,
        nonce,
        contract,
    } = MINT_REQUESTS
        .update_request_status_from_pending(&mut deps, &request_hash, RequestStatus::Approved)?
        .info;

    ensure!(
        contract.address == contract_address,
        ContractError::Std(cosmwasm_std::StdError::generic_err(
            "unreachable: contract address mismatch"
        ))
    );

    let event = Event::new("mint_request_approved")
        .add_attribute("requester", requester.as_str())
        .add_attribute("amount", amount)
        .add_attribute("tx_id", tx_id.as_str())
        .add_attribute("deposit_address", deposit_address.as_str())
        .add_attribute("nonce", nonce)
        .add_attribute("block_height", block.height.to_string())
        .add_attribute("timestamp", block.time.nanos().to_string())
        .add_attribute(
            "transaction_index",
            transaction
                .as_ref()
                .map(|t| t.index.to_string())
                .unwrap_or_default(),
        );

    let denom = TOKEN_DENOM.load(deps.storage)?;

    let token_to_mint = Coin::new(amount.u128(), denom);
    let mint_to_requester_msgs = vec![
        MsgMint {
            sender: contract_address.to_string(),
            amount: Some(token_to_mint.clone().into()),
        }
        .into(),
        CosmosMsg::Bank(BankMsg::Send {
            to_address: requester.to_string(),
            amount: vec![token_to_mint],
        }),
    ];

    Ok(Response::new()
        .add_messages(mint_to_requester_msgs)
        .add_event(event))
}

// TODO: test with add and confirm, add and reject, add and cancel
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, BankMsg, BlockInfo, Coin, DepsMut, Env, Event, Response, StdError, SubMsg, Timestamp,
        TransactionInfo, Uint128,
    };
    use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgMint;

    use crate::{
        auth::{custodian, merchant, owner},
        contract,
        tokenfactory::request::RequestStatus,
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

        let hash_on_nonce_0 = "5u8TbLWA7MKMZa6ZpGXTCLbomCnAl0Bj8JxIlLgVjpg=";

        assert_eq!(
            issue_mint_request_fixture(deps.as_mut(), merchant).unwrap(),
            Response::new().add_event(
                Event::new("mint_request_issued")
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
            )
        );

        // mint request should be saved
        let request = MINT_REQUESTS
            .get_request(deps.as_ref(), hash_on_nonce_0)
            .unwrap();

        assert_eq!(request.info.nonce, Uint128::new(0));
        assert_eq!(request.status, RequestStatus::Pending);
        assert_eq!(request.hash().unwrap().to_base64(), hash_on_nonce_0);

        // nonce should be incremented
        assert_eq!(
            MINT_REQUESTS.current_nonce(deps.as_ref()).unwrap(),
            Uint128::new(1)
        );

        // same request with same sender, even on the same tx must result in different hash
        let hash_on_nonce_1 = issue_mint_request_fixture(deps.as_mut(), merchant)
            .unwrap()
            .events[0]
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        assert_ne!(hash_on_nonce_0, hash_on_nonce_1);

        // nonce should be incremented
        assert_eq!(
            MINT_REQUESTS.current_nonce(deps.as_ref()).unwrap(),
            Uint128::new(2)
        );
    }

    #[test]
    fn test_approve_mint_request() {
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
                denom: denom.to_string(),
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

        let request_hash = res.events[0]
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
            StdError::not_found("wbtc_controller::tokenfactory::request::Request").into()
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
            vec![
                SubMsg::new(MsgMint {
                    sender: contract.to_string(),
                    amount: Some(Coin::new(amount.u128(), denom).into())
                }),
                SubMsg::new(BankMsg::Send {
                    to_address: merchant.to_string(), // requester
                    amount: vec![Coin::new(amount.u128(), denom).into()]
                })
            ]
        );

        // check mint request status
        let request = MINT_REQUESTS
            .get_request(deps.as_ref(), &request_hash)
            .unwrap();

        assert_eq!(request.status, RequestStatus::Approved);
    }
}
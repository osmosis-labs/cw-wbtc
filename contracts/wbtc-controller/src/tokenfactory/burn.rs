use cosmwasm_std::{
    attr, ensure, Attribute, Coin, CosmosMsg, DepsMut, Env, MessageInfo, Response, Uint128,
};
use osmosis_std::types::osmosis::tokenfactory::v1beta1::MsgBurn;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{allow_only, Role},
    helpers::method_attrs,
    ContractError,
};

use super::{
    deposit_address,
    request::{RequestData, RequestManager, Status, TxId},
    token,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum BurnRequestStatus {
    Executed,
    Confirmed,
}

impl Status for BurnRequestStatus {
    fn initial() -> Self {
        Self::Executed
    }

    fn is_updatable(&self) -> bool {
        self == &Self::initial()
    }
}

fn burn_requests<'a>() -> RequestManager<'a, BurnRequestStatus> {
    RequestManager::new("burn_requests", "burn_requests__nonce", "burn_nonce")
}

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
    let mut attrs = method_attrs("burn", <Vec<Attribute>>::from(&request.data));
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

    let mut attrs = method_attrs(
        "confirm_burn_request",
        <Vec<Attribute>>::from(&request.data),
    );
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
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

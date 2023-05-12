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

const BURN_REQUESTS: RequestManager<BurnRequestStatus> =
    RequestManager::new("burn_requests", "burn_nonce");

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
    let (request_hash, request) = BURN_REQUESTS.issue(
        &mut deps,
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

    let request = BURN_REQUESTS.check_and_update_request_status(
        &mut deps,
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

    BURN_REQUESTS.confirm_tx(deps, request_hash.as_str(), tx_id)?;

    let mut attrs = method_attrs(
        "confirm_burn_request",
        <Vec<Attribute>>::from(&request.data),
    );
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
}

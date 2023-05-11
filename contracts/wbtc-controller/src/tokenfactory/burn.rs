use cosmwasm_std::{attr, ensure, Attribute, DepsMut, Env, MessageInfo, Response, Uint128};

use crate::{
    auth::{allow_only, Role},
    helpers::method_attrs,
    ContractError,
};

use super::{
    deposit_address,
    request::{RequestManager, RequestStatus, TxId},
};

const BURN_REQUESTS: RequestManager = RequestManager::new("burn_requests", "burn_nonce");

pub fn burn(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;

    let deposit_address =
        deposit_address::get_merchant_deposit_address(deps.as_ref(), &info.sender)?;

    // set tx_id to empty string, this will be set when the request is confirmed
    let tx_id = String::default();

    let (request_hash, request) = BURN_REQUESTS.issue(
        &mut deps,
        info.sender,
        amount,
        TxId::Confirmed(tx_id),
        deposit_address,
        env.block,
        env.transaction,
        env.contract,
    )?;

    let mut attrs = method_attrs("burn", <Vec<Attribute>>::from(&request.info));
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
}

pub fn confirm_burn_request(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    request_hash: String,
    tx_id: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Custodian], &info.sender, deps.as_ref())?;

    let request = BURN_REQUESTS.update_request_status_from_pending(
        &mut deps,
        request_hash.as_str(),
        RequestStatus::Approved,
        |request| {
            // ensure contract address matched request's contract address
            ensure!(
                request.info.contract.address == env.contract.address,
                ContractError::Std(cosmwasm_std::StdError::generic_err(
                    "unreachable: contract address mismatch"
                ))
            );

            Ok(())
        },
    )?;

    BURN_REQUESTS.confirm_tx_id(deps, request_hash.as_str(), tx_id)?;

    let mut attrs = method_attrs(
        "confirm_burn_request",
        <Vec<Attribute>>::from(&request.info),
    );
    attrs.extend(vec![attr("request_hash", request_hash)]);

    Ok(Response::new().add_attributes(attrs))
}

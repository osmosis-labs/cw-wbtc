use crate::{
    request::{Request, RequestStatus},
    ContractError,
};
use cosmwasm_std::{DepsMut, Env, Event, MessageInfo, Response, StdResult, Uint128};
use cw_storage_plus::{Item, Map};

const MINT_REQUESTS: Map<String, Request> = Map::new("mint_requests");
const MINT_NONCE: Item<Uint128> = Item::new("mint_nonce");

pub fn add_mint_request(
    mut deps: DepsMut,
    info: MessageInfo,
    env: Env,
    amount: Uint128,
    tx_id: String,
    deposit_address: String,
) -> Result<Response, ContractError> {
    let nonce = MINT_NONCE.may_load(deps.storage)?.unwrap_or_default();
    let event = Event::new("mint_request_added")
        .add_attribute("sender", info.sender.as_str())
        .add_attribute("amount", amount)
        .add_attribute("tx_id", tx_id.as_str())
        .add_attribute("deposit_address", deposit_address.as_str())
        .add_attribute("nonce", nonce)
        .add_attribute("block_height", env.block.height.to_string())
        .add_attribute("timestamp", env.block.time.to_string())
        .add_attribute(
            "transaction_index",
            env.transaction
                .as_ref()
                .map(|t| t.index.to_string())
                .unwrap_or_default(),
        );

    let request = Request {
        requester: info.sender,
        amount,
        tx_id,
        deposit_address,
        block: env.block,
        transaction: env.transaction,
        contract: env.contract,
        nonce,
        status: RequestStatus::Pending,
    };

    let request_hash = update_mint_request(&mut deps, &request)?;
    let event = event.add_attribute("request_hash", request_hash);

    increase_nonce(&mut deps)?;
    Ok(Response::new().add_event(event))
}

fn update_mint_request(deps: &mut DepsMut, request: &Request) -> StdResult<String> {
    let request_hash = request.hash()?.to_base64();
    MINT_REQUESTS.save(deps.storage, request_hash.clone(), &request)?;

    Ok(request_hash)
}

fn increase_nonce(deps: &mut DepsMut) -> StdResult<Uint128> {
    MINT_NONCE.update(deps.storage, |nonce| Ok(nonce + Uint128::new(1)))
}

// TODO: test with add and confirm, add and reject, add and cancel

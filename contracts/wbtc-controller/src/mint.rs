use crate::ContractError;
use cosmwasm_std::{
    to_binary, Addr, Binary, BlockInfo, ContractInfo, DepsMut, Env, Event, MessageInfo, Response,
    StdError, TransactionInfo, Uint128,
};
use cw_storage_plus::{Item, Map};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Serialize, Deserialize)]
pub enum RequestStatus {
    Pending,
    Completed,
    Cancelled,
    Rejected,
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub requester: Addr,
    pub amount: Uint128,
    pub deposit_address: String,
    pub block: BlockInfo,
    pub transaction: Option<TransactionInfo>,
    pub contract: ContractInfo,
    pub nonce: Uint128,
    pub status: RequestStatus,
}

const MINT_REQUESTS: Map<String, Request> = Map::new("mint_requests");
const NONCE: Item<Uint128> = Item::new("nonce");

pub fn add_mint_request(
    deps: DepsMut,
    info: MessageInfo,
    env: Env,
    amount: Uint128,
    deposit_address: &str,
) -> Result<Response, ContractError> {
    // get nonce
    let nonce = NONCE.may_load(deps.storage)?.unwrap_or_default();

    let request = Request {
        requester: info.sender.clone(),
        amount,
        deposit_address: deposit_address.to_string(),
        block: env.block.clone(),
        transaction: env.transaction.clone(),
        contract: env.contract,
        nonce,
        status: RequestStatus::Pending,
    };

    let request_hash = hash_request(&request)?;
    MINT_REQUESTS.save(deps.storage, request_hash.clone(), &request)?;

    // update nonce
    let next = nonce + Uint128::new(1);
    NONCE.save(deps.storage, &next)?;

    let event = Event::new("add_mint_request")
        .add_attribute("sender", info.sender.to_string())
        .add_attribute("amount", amount)
        .add_attribute("deposit_address", deposit_address)
        .add_attribute("nonce", nonce)
        .add_attribute("block_height", env.block.height.to_string())
        .add_attribute("timestamp", env.block.time.to_string())
        .add_attribute(
            "transaction_index",
            env.transaction
                .map(|t| t.index.to_string())
                .unwrap_or_default(),
        )
        .add_attribute("request_hash", request_hash);

    Ok(Response::new().add_event(event))
}

fn hash_request(request: &Request) -> Result<String, StdError> {
    let mut hasher = Keccak256::new();
    hasher.update(to_binary(&request)?.to_vec());
    Ok(Binary::from(hasher.finalize().to_vec()).to_base64())
}

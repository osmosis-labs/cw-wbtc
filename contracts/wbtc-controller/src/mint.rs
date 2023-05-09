use crate::ContractError;
use cosmwasm_std::{
    to_binary, Addr, Binary, BlockInfo, ContractInfo, DepsMut, Env, Event, MessageInfo, Response,
    StdError, StdResult, TransactionInfo, Uint128,
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
    pub tx_id: String,
    pub deposit_address: String,
    pub block: BlockInfo,
    pub transaction: Option<TransactionInfo>,
    pub contract: ContractInfo,
    pub nonce: Uint128,
    pub status: RequestStatus,
}

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
    let request_hash = hash_request(&request)?;
    MINT_REQUESTS.save(deps.storage, request_hash.clone(), &request)?;

    Ok(request_hash)
}

fn increase_nonce(deps: &mut DepsMut) -> StdResult<Uint128> {
    MINT_NONCE.update(deps.storage, |nonce| Ok(nonce + Uint128::new(1)))
}

fn hash_request(request: &Request) -> Result<String, StdError> {
    let mut hasher = Keccak256::new();
    hasher.update(to_binary(&request)?.to_vec());
    Ok(Binary::from(hasher.finalize().to_vec()).to_base64())
}

// TODO: test with add and confirm, add and reject, add and cancel

#[cfg(test)]
mod tests {
    use cosmwasm_std::Timestamp;

    use super::*;

    #[test]
    fn test_hash_request() {
        let request = Request {
            requester: Addr::unchecked("osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks"),
            amount: Uint128::new(100),
            tx_id: "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf".to_string(),
            deposit_address: "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun".to_string(),
            block: BlockInfo {
                height: 1,
                time: Timestamp::from_nanos(1683617645768),
                chain_id: "osmosis-1".to_string(),
            },
            transaction: Some(TransactionInfo { index: 1 }),
            contract: ContractInfo {
                address: Addr::unchecked(
                    "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9",
                ),
            },
            nonce: Uint128::new(3),
            status: RequestStatus::Pending,
        };

        let struct_hash = hash_request(&request).unwrap();

        let request_string = r#"{
           "requester": "osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks",
           "amount": "100",
           "tx_id": "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf",
           "deposit_address": "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun",
           "block": {
               "height": 1,
               "time": "1683617645768",
               "chain_id": "osmosis-1"
           },
           "transaction": {
               "index": 1
           },
           "contract": {
               "address": "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9"
           },
           "nonce": "3",
           "status": "Pending"
       }"#;

        // strip all spaces & newlines
        let request_string = request_string.replace(" ", "").replace("\n", "");

        let mut hasher = Keccak256::new();
        hasher.update(request_string.as_bytes());
        let string_hash = Binary::from(hasher.finalize().to_vec()).to_base64();

        assert_eq!(struct_hash, string_hash);
    }
}

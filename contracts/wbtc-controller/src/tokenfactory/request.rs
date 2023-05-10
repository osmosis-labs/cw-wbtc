#[cfg(test)]
use cosmwasm_std::Deps;
use cosmwasm_std::{
    ensure, to_binary, Addr, Binary, BlockInfo, ContractInfo, DepsMut, StdResult, TransactionInfo,
    Uint128,
};

use cw_storage_plus::Map;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::ContractError;

use super::nonce::Nonce;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Cancelled,
    Rejected,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestInfo {
    pub requester: Addr,
    pub amount: Uint128,
    pub tx_id: String,
    pub deposit_address: String,
    pub block: BlockInfo,
    pub transaction: Option<TransactionInfo>,
    pub contract: ContractInfo,
    pub nonce: Uint128,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub info: RequestInfo,
    pub status: RequestStatus,
}

impl Request {
    pub fn hash(&self) -> StdResult<Binary> {
        let mut hasher = Keccak256::new();
        hasher.update(to_binary(&self.info)?.to_vec());
        Ok(Binary::from(hasher.finalize().to_vec()))
    }
}

pub struct RequestManager<'a> {
    requests: Map<'a, String, Request>,
    nonce: Nonce<'a>,
}

impl<'a> RequestManager<'a> {
    pub const fn new(requests_namespace: &'a str, nonce_namespaces: &'a str) -> Self {
        Self {
            requests: Map::new(requests_namespace),
            nonce: Nonce::new(nonce_namespaces),
        }
    }

    pub fn add_request(
        &self,
        deps: &mut DepsMut,
        requester: Addr,
        amount: Uint128,
        tx_id: String,
        deposit_address: String,
        block: BlockInfo,
        transaction: Option<TransactionInfo>,
        contract: ContractInfo,
    ) -> Result<(String, Request), ContractError> {
        let nonce = self.nonce.next(deps)?;
        let request = Request {
            info: RequestInfo {
                requester,
                amount,
                tx_id,
                deposit_address,
                block,
                transaction,
                contract,
                nonce,
            },
            status: RequestStatus::Pending,
        };
        let request_hash = request.hash()?.to_base64();
        self.requests
            .save(deps.storage, request_hash.clone(), &request)?;
        Ok((request_hash, request))
    }

    pub fn approve_request(
        &self,
        deps: &mut DepsMut,
        request_hash: &str,
    ) -> Result<Request, ContractError> {
        self.update_pending_request_status(deps, request_hash, RequestStatus::Approved)
    }

    fn update_pending_request_status(
        &self,
        deps: &mut DepsMut,
        request_hash: &str,
        status: RequestStatus,
    ) -> Result<Request, ContractError> {
        let mut request = self.requests.load(deps.storage, request_hash.to_string())?;
        ensure!(
            request.status == RequestStatus::Pending,
            ContractError::PendingRequestExpected {
                request_hash: request_hash.to_string()
            }
        );

        request.status = status;

        self.requests
            .save(deps.storage, request_hash.to_string(), &request)?;

        Ok(request)
    }

    #[cfg(test)]
    pub fn current_nonce(&self, deps: Deps) -> StdResult<Uint128> {
        self.nonce.current(deps)
    }

    #[cfg(test)]
    pub fn get_request(&self, deps: Deps, request_hash: &str) -> StdResult<Request> {
        self.requests.load(deps.storage, request_hash.to_string())
    }
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::Timestamp;

    use super::*;

    #[test]
    fn test_hash_request() {
        let request = Request {
            info: RequestInfo {
                requester: Addr::unchecked("osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks"),
                amount: Uint128::new(100),
                tx_id: "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf"
                    .to_string(),
                deposit_address: "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun".to_string(),
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(1689069540),
                    chain_id: "osmosis-1".to_string(),
                },
                transaction: Some(TransactionInfo { index: 1 }),
                contract: ContractInfo {
                    address: Addr::unchecked(
                        "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9",
                    ),
                },
                nonce: Uint128::new(3),
            },
            status: RequestStatus::Pending,
        };

        let struct_hash = request.hash().unwrap();

        let request_string = r#"{
            "requester": "osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks",
            "amount": "100",
            "tx_id": "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf",
            "deposit_address": "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun",
            "block": {
                "height": 1,
                "time": "1689069540000000000",
                "chain_id": "osmosis-1"
            },
            "transaction": {
                "index": 1
            },
            "contract": {
                "address": "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9"
            },
            "nonce": "3"
        }"#;

        // strip all spaces & newlines
        let request_string = request_string.replace(" ", "").replace("\n", "");

        let mut hasher = Keccak256::new();
        hasher.update(request_string.as_bytes());
        let string_hash = Binary::from(hasher.finalize().to_vec());

        assert_eq!(struct_hash, string_hash);
    }
}

#[cfg(test)]
use cosmwasm_std::Deps;
use cosmwasm_std::{
    attr, ensure, to_binary, Addr, Attribute, Binary, BlockInfo, ContractInfo, DepsMut, StdResult,
    TransactionInfo, Uint128,
};

use cw_storage_plus::Map;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::ContractError;

use super::nonce::Nonce;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum RequestStatus {
    Pending,
    Approved,
    Cancelled,
    Rejected,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

// impl From<RequestInfo> for Vec<Attributes>
impl From<&RequestInfo> for Vec<Attribute> {
    fn from(info: &RequestInfo) -> Self {
        let RequestInfo {
            requester,
            amount,
            tx_id,
            deposit_address,
            block,
            transaction,
            nonce,
            // don't include contract info in attributes since it's already exists as `_contract_address` by default
            contract: _,
        } = info;
        vec![
            attr("requester", requester.as_str()),
            attr("amount", amount.to_string()),
            attr("tx_id", tx_id.as_str()),
            attr("deposit_address", deposit_address.as_str()),
            attr("block_height", block.height.to_string()),
            attr("timestamp", block.time.nanos().to_string()),
            attr(
                "transaction_index",
                transaction
                    .as_ref()
                    .map(|t| t.index.to_string())
                    .unwrap_or("none".to_string()),
            ),
            attr("nonce", nonce.to_string()),
        ]
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

    /// Issue a new request and return pair of `(request_hash, request)`
    /// with request status set to `Pending`
    pub fn issue_request(
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

    /// Update status of a pending request to other status.
    /// For all status of the request, only `Pending` status can be updated
    pub fn update_request_status_from_pending(
        &self,
        deps: &mut DepsMut,
        request_hash: &str,
        status: RequestStatus,
        precondition: impl Fn(&Request) -> Result<(), ContractError>,
    ) -> Result<Request, ContractError> {
        let mut request = self.requests.load(deps.storage, request_hash.to_string())?;

        // ensure precondition before updating the request
        precondition(&request)?;

        // Ensure that the request is in pending status
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
    /// Get request by request hash
    /// Only used for testing
    pub fn get_request(&self, deps: Deps, request_hash: &str) -> StdResult<Request> {
        self.requests.load(deps.storage, request_hash.to_string())
    }

    #[cfg(test)]
    /// Current nonce that will be used for the next request
    /// Only used for testing
    pub fn current_nonce(&self, deps: Deps) -> StdResult<Uint128> {
        self.nonce.current(deps)
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

#[cfg(test)]
use cosmwasm_std::Deps;
use cosmwasm_std::{
    attr, ensure, to_binary, Addr, Attribute, Binary, BlockInfo, ContractInfo, DepsMut, StdResult,
    TransactionInfo, Uint128,
};

use cw_storage_plus::Map;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::ContractError;

use super::nonce::Nonce;

pub trait Status: PartialEq + Eq {
    fn initial() -> Self;
    fn is_updatable(&self) -> bool;
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TxId {
    Pending,
    Confirmed(String),
}

impl std::fmt::Display for TxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxId::Pending => write!(f, "<pending>"),
            TxId::Confirmed(tx_id) => write!(f, "{}", tx_id),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestData {
    pub requester: Addr,
    pub amount: Uint128,
    pub tx_id: TxId,
    pub deposit_address: String,
    pub block: BlockInfo,
    pub transaction: Option<TransactionInfo>,
    pub contract: ContractInfo,
    pub nonce: Uint128,
}

impl RequestData {
    pub fn hash(&self) -> StdResult<Binary> {
        let mut hasher = Keccak256::new();
        hasher.update(to_binary(&self)?.to_vec());
        Ok(Binary::from(hasher.finalize().to_vec()))
    }
}

impl From<&RequestData> for Vec<Attribute> {
    fn from(data: &RequestData) -> Self {
        let RequestData {
            requester,
            amount,
            tx_id,
            deposit_address,
            block,
            transaction,
            nonce,
            // don't include contract info in attributes since it's already exists as `_contract_address` by default
            contract: _,
        } = data;
        vec![
            attr("requester", requester.as_str()),
            attr("amount", amount.to_string()),
            attr("tx_id", tx_id.to_string()),
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
pub struct Request<S> {
    pub data: RequestData,
    pub status: S,
}

pub struct RequestManager<'a, S> {
    requests: Map<'a, String, Request<S>>,
    nonce: Nonce<'a>,
}

impl<'a, S> RequestManager<'a, S>
where
    S: Status + Serialize + DeserializeOwned + PartialEq + Clone,
{
    pub const fn new(requests_namespace: &'a str, nonce_namespaces: &'a str) -> Self {
        Self {
            requests: Map::new(requests_namespace),
            nonce: Nonce::new(nonce_namespaces),
        }
    }

    /// Issue a new request and return pair of `(request_hash, request)`
    /// with request status set to `Pending`
    pub fn issue(
        &self,
        deps: &mut DepsMut,
        requester: Addr,
        amount: Uint128,
        tx_id: TxId,
        deposit_address: String,
        block: BlockInfo,
        transaction: Option<TransactionInfo>,
        contract: ContractInfo,
    ) -> Result<(String, Request<S>), ContractError> {
        let nonce = self.nonce.next(deps)?;
        let request = Request {
            data: RequestData {
                requester,
                amount,
                tx_id,
                deposit_address,
                block,
                transaction,
                contract,
                nonce,
            },
            status: S::initial(),
        };
        let request_hash = request.data.hash()?.to_base64();
        self.requests
            .save(deps.storage, request_hash.clone(), &request)?;
        Ok((request_hash, request))
    }

    /// Update status of a request.
    /// Only request with updatable status can be updated.
    pub fn check_and_update_request_status(
        &self,
        deps: &mut DepsMut,
        request_hash: &str,
        status: S,
        precondition: impl Fn(&Request<S>) -> Result<(), ContractError>,
    ) -> Result<Request<S>, ContractError> {
        let mut request = self.requests.load(deps.storage, request_hash.to_string())?;

        // ensure precondition before updating the request
        precondition(&request)?;

        // Ensure that the request is in initial status
        ensure!(
            request.status.is_updatable(),
            ContractError::UpdatableStatusExpected {
                request_hash: request_hash.to_string()
            }
        );

        request.status = status;

        self.requests
            .save(deps.storage, request_hash.to_string(), &request)?;

        Ok(request)
    }

    /// Confirm tx_id of a request
    /// Since tx_id can be unavialable when the request is issued (burn request), it needs to be updated later
    pub fn confirm_tx(
        &self,
        deps: DepsMut,
        request_hash: &str,
        tx_id: String,
    ) -> StdResult<Request<S>> {
        let mut request = self.requests.load(deps.storage, request_hash.to_string())?;

        request.data.tx_id = TxId::Confirmed(tx_id);
        self.requests
            .save(deps.storage, request_hash.to_string(), &request)?;

        Ok(request)
    }

    #[cfg(test)]
    /// Get request by request hash
    /// Only used for testing
    pub fn get_request(&self, deps: Deps, request_hash: &str) -> StdResult<Request<S>> {
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

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
    pub enum TestRequestStatus {
        Pending,
        Approved,
        Cancelled,
        Rejected,
    }

    impl Status for TestRequestStatus {
        fn initial() -> Self {
            Self::Pending
        }

        fn is_updatable(&self) -> bool {
            self == &Self::initial()
        }
    }

    #[test]
    fn test_hash_request() {
        let request = Request {
            data: RequestData {
                requester: Addr::unchecked("osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks"),
                amount: Uint128::new(100),
                tx_id: TxId::Confirmed(
                    "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf".to_string(),
                ),
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
            status: TestRequestStatus::Pending,
        };

        let struct_hash = request.data.hash().unwrap();

        let request_string = r#"{
            "requester": "osmo1cyyzpxplxdzkeea7kwsydadg87357qnahakaks",
            "amount": "100",
            "tx_id": {
                "confirmed": "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf"
            },
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

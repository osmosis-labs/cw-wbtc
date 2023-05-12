use std::fmt::Display;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{
    attr, ensure, to_binary, Addr, Attribute, Binary, BlockInfo, ContractInfo, Deps, DepsMut,
    Order, StdError, StdResult, TransactionInfo, Uint128,
};

use cw_storage_plus::{Bound, Index, IndexList, IndexedMap, MultiIndex};
use serde::{de::DeserializeOwned, Serialize};
use sha3::{Digest, Keccak256};

use crate::{
    constants::{DEFAULT_LIMIT, MAX_LIMIT},
    ContractError,
};

use super::nonce::Nonce;

pub trait Status:
    Clone + Serialize + DeserializeOwned + PartialEq + std::fmt::Debug + Display
{
    fn initial() -> Self;
    fn is_updatable(&self) -> bool;
}

#[cw_serde]
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

#[cw_serde]
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

#[cw_serde]
pub struct Request<S> {
    pub data: RequestData,
    pub status: S,
}

#[cw_serde]
pub struct RequestWithHash<S> {
    pub request_hash: String,
    pub request: Request<S>,
}

pub struct RequestIndexes<'a, S> {
    pub nonce: MultiIndex<'a, Vec<u8>, Request<S>, String>,
    pub status_and_nonce: MultiIndex<'a, (String, Vec<u8>), Request<S>, String>,
}

impl<'a, S: Status> IndexList<Request<S>> for RequestIndexes<'a, S> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Request<S>>> + '_> {
        let v: Vec<&dyn Index<Request<S>>> = vec![&self.nonce, &self.status_and_nonce];
        Box::new(v.into_iter())
    }
}

pub struct RequestManager<'a, S: Status> {
    requests: IndexedMap<'a, String, Request<S>, RequestIndexes<'a, S>>,
    nonce: Nonce<'a>,
}

impl<'a, S: Status> RequestManager<'a, S> {
    pub fn new(
        requests_namespace: &'a str,
        requests_nonce_idx_namespace: &'a str,
        requests_status_and_nonce_idx_namespace: &'a str,
        nonce_namespace: &'a str,
    ) -> Self {
        let indexes = RequestIndexes {
            nonce: MultiIndex::new(
                |_pk: &[u8], req: &Request<S>| req.data.nonce.to_be_bytes().to_vec(),
                requests_namespace,
                requests_nonce_idx_namespace,
            ),
            status_and_nonce: MultiIndex::new(
                |_pk: &[u8], req: &Request<S>| {
                    (
                        req.status.to_string(),
                        req.data.nonce.to_be_bytes().to_vec(),
                    )
                },
                requests_namespace,
                requests_status_and_nonce_idx_namespace,
            ),
        };
        Self {
            requests: IndexedMap::new(requests_namespace, indexes),
            nonce: Nonce::new(nonce_namespace),
        }
    }

    /// Issue a new request and return pair of `(request_hash, request)`
    /// with request status set to `Pending`
    pub fn issue(
        &self,
        mut deps: DepsMut,
        requester: Addr,
        amount: Uint128,
        tx_id: TxId,
        deposit_address: String,
        block: BlockInfo,
        transaction: Option<TransactionInfo>,
        contract: ContractInfo,
    ) -> Result<(String, Request<S>), ContractError> {
        let nonce = self.nonce.get_then_increase(deps.branch())?;
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
        deps: DepsMut,
        request_hash: &str,
        status: S,
        precondition: impl Fn(&Request<S>) -> Result<(), ContractError>,
    ) -> Result<Request<S>, ContractError> {
        let mut request = self.requests.load(deps.storage, request_hash.to_string())?;

        // ensure precondition before updating the request
        precondition(&request)?;

        // Ensure that the request is updatable
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

    pub fn get_request_by_nonce(
        &self,
        deps: Deps,
        nonce: &Uint128,
    ) -> StdResult<(String, Request<S>)> {
        self.requests
            .idx
            .nonce
            .prefix(nonce.to_be_bytes().to_vec())
            .range(deps.storage, None, None, Order::Ascending)
            .into_iter()
            .next()
            .ok_or(StdError::not_found(format!("Request with nonce: {nonce}")))?
    }

    pub fn get_request(&self, deps: Deps, request_hash: &str) -> StdResult<Request<S>> {
        self.requests.load(deps.storage, request_hash.to_string())
    }

    /// Get numbers of requests
    pub fn get_request_count(&self, deps: Deps) -> StdResult<Uint128> {
        // since nonce is being increment on each request issued, it can be used to count the number of requests
        self.nonce.get(deps)
    }

    pub fn list_requests(
        &self,
        deps: Deps,
        limit: Option<u32>,
        start_after_nonce: Option<Uint128>,
        status: Option<S>,
    ) -> StdResult<Vec<RequestWithHash<S>>> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start_after_bound = start_after_nonce.map(|nonce| (nonce.to_be_bytes().to_vec()));

        match status {
            Some(status) => self
                .requests
                .idx
                .status_and_nonce
                .sub_prefix(status.to_string())
                .range(
                    deps.storage,
                    start_after_bound
                        .map(|nonce| (nonce, String::default()))
                        .map(Bound::exclusive),
                    None,
                    Order::Ascending,
                )
                .map(|v| {
                    let (request_hash, request) = v?;

                    Ok(RequestWithHash {
                        request_hash,
                        request,
                    })
                })
                .take(limit)
                .collect(),
            None => self
                .requests
                .idx
                .nonce
                .range(
                    deps.storage,
                    start_after_bound
                        .map(|nonce| (nonce, String::default()))
                        .map(Bound::exclusive),
                    None,
                    Order::Ascending,
                )
                .map(|v| {
                    let (request_hash, request) = v?;

                    Ok(RequestWithHash {
                        request_hash,
                        request,
                    })
                })
                .take(limit)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::{testing::mock_dependencies, Timestamp};

    use super::*;

    #[cw_serde]
    pub enum TestRequestStatus {
        Pending,
        Approved,
        Cancelled,
        Rejected,
    }

    impl Display for TestRequestStatus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                TestRequestStatus::Pending => write!(f, "Pending"),
                TestRequestStatus::Approved => write!(f, "Approved"),
                TestRequestStatus::Cancelled => write!(f, "Cancelled"),
                TestRequestStatus::Rejected => write!(f, "Rejected"),
            }
        }
    }

    impl Status for TestRequestStatus {
        fn initial() -> Self {
            Self::Pending
        }

        fn is_updatable(&self) -> bool {
            self == &Self::initial()
        }
    }

    fn test_requests<'a>() -> RequestManager<'a, TestRequestStatus> {
        RequestManager::new(
            "test_requests",
            "test_requests__nonce",
            "test_requests__status_and_nonce",
            "test_nonce",
        )
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

    #[test]
    fn test_list_requests() {
        let mut deps = mock_dependencies();

        let base_request_data = RequestData {
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
        };

        let mut requests: Vec<RequestWithHash<TestRequestStatus>> = Vec::new();
        for i in 0..200 {
            let mut status = TestRequestStatus::Pending;
            if i % 2 == 0 {
                status = TestRequestStatus::Approved;
            } else if i % 3 == 0 {
                status = TestRequestStatus::Cancelled;
            } else if i % 5 == 0 {
                status = TestRequestStatus::Rejected;
            }

            let request = Request {
                data: RequestData {
                    nonce: Uint128::new(i),
                    ..base_request_data.clone()
                },
                status,
            };
            let request_hash = request.data.hash().unwrap().to_base64();
            requests.push(RequestWithHash {
                request_hash: request_hash.clone(),
                request: request.clone(),
            });
            test_requests()
                .requests
                .save(deps.as_mut().storage, request_hash, &request)
                .unwrap();
        }

        // with out status filter
        assert_eq!(
            test_requests()
                .list_requests(deps.as_ref(), None, None, None)
                .unwrap(),
            requests[0..DEFAULT_LIMIT as usize].to_vec()
        );

        assert_eq!(
            test_requests()
                .list_requests(deps.as_ref(), Some(21), None, None)
                .unwrap(),
            requests[0..21]
        );

        assert_eq!(
            test_requests()
                .list_requests(deps.as_ref(), Some(999), None, None)
                .unwrap(),
            requests[0..MAX_LIMIT as usize]
        );

        assert_eq!(
            test_requests()
                .list_requests(deps.as_ref(), Some(20), Some(Uint128::new(35)), None)
                .unwrap(),
            requests[35..(35 + 20)]
        );

        // with status filter
        assert_eq!(
            test_requests()
                .list_requests(
                    deps.as_ref(),
                    Some(1),
                    None,
                    Some(TestRequestStatus::Approved)
                )
                .unwrap(),
            requests
                .clone()
                .into_iter()
                .filter(|r| r.request.status == TestRequestStatus::Approved)
                .take(1 as usize)
                .collect::<Vec<_>>()
        );

        assert_eq!(
            test_requests()
                .list_requests(deps.as_ref(), None, None, Some(TestRequestStatus::Approved))
                .unwrap(),
            requests
                .clone()
                .into_iter()
                .filter(|r| r.request.status == TestRequestStatus::Approved)
                .take(DEFAULT_LIMIT as usize)
                .collect::<Vec<_>>()
        );

        assert_eq!(
            test_requests()
                .list_requests(
                    deps.as_ref(),
                    None,
                    Some(Uint128::new(15)),
                    Some(TestRequestStatus::Rejected)
                )
                .unwrap(),
            requests
                .clone()
                .into_iter()
                .skip(15)
                .filter(|r| r.request.status == TestRequestStatus::Rejected)
                .take(DEFAULT_LIMIT as usize)
                .collect::<Vec<_>>()
        );

        assert_eq!(
            test_requests()
                .list_requests(
                    deps.as_ref(),
                    Some(999),
                    Some(Uint128::new(88)),
                    Some(TestRequestStatus::Pending)
                )
                .unwrap(),
            requests
                .clone()
                .into_iter()
                .skip(88)
                .filter(|r| r.request.status == TestRequestStatus::Pending)
                .take(MAX_LIMIT as usize)
                .collect::<Vec<_>>()
        );
    }
}

use cosmwasm_std::{
    to_binary, Addr, Binary, BlockInfo, ContractInfo, StdResult, TransactionInfo, Uint128,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Cancelled,
    Rejected,
}

#[derive(Serialize, Deserialize, Debug)]
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

impl Request {
    pub fn hash(&self) -> StdResult<Binary> {
        let mut hasher = Keccak256::new();
        hasher.update(to_binary(self)?.to_vec());
        Ok(Binary::from(hasher.finalize().to_vec()))
    }
}

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
            "nonce": "3",
            "status": "Pending"
        }"#;

        // strip all spaces & newlines
        let request_string = request_string.replace(" ", "").replace("\n", "");

        let mut hasher = Keccak256::new();
        hasher.update(request_string.as_bytes());
        let string_hash = Binary::from(hasher.finalize().to_vec());

        assert_eq!(struct_hash, string_hash);
    }
}

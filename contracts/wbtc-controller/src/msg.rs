use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Timestamp, Uint128, Uint64};

/// Message type for `instantiate` entry_point
#[cw_serde]
pub struct InstantiateMsg {}

/// Message type for `execute` entry_point
#[cw_serde]
pub enum ExecuteMsg {
    SetCustodian {
        address: String,
    },
    AddMerchant {
        address: String,
    },
    RemoveMerchant {
        address: String,
    },
    /// Set custodian BTC deposit address of the specified merchant
    SetCustodianDepositAddress {
        merchant: String,
        deposit_address: String,
    },
    SetMerchantDepositAddress {
        deposit_address: String,
    },
    AddMintRequest {
        amount: Uint128,
        tx_id: String,
        deposit_address: String,
    },
    CancelMintRequest {
        request_hash: String,
    },
    ConfirmMintRequest {
        request_hash: String,
    },
    RejectMintRequest {
        request_hash: String,
    },
    Burn {
        amount: Uint128,
    },
    ConfirmBurnRequest {
        request_hash: String,
        tx_id: String,
    },
    Pause {},
    Unpause {},
}

/// Message type for `migrate` entry_point
#[cw_serde]
pub enum MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetMintRequestResponse)]
    GetMintRequest { nonce: Uint64 },

    #[returns(GetMintRequestsLengthResponse)]
    GetMintRequestsLength {},

    #[returns(GetBurnRequestResponse)]
    GetBurnRequest { nonce: Uint64 },

    #[returns(GetBurnRequestsLengthResponse)]
    GetBurnRequestsLength {},

    #[returns(GetTokenDenomResposne)]
    GetTokenDenom {},

    /// IsMerchant
    #[returns(IsMerchantResponse)]
    IsMerchant { address: String },

    /// IsCustodian
    #[returns(IsCustodianResponse)]
    IsCustodian { address: String },
}

#[cw_serde]
pub struct GetMintRequestResponse {
    pub request_nonce: Uint64,
    pub requester: String,
    pub amount: Uint64,
    pub deposit_address: String,
    pub tx_id: String,
    pub timestamp: Timestamp,
    pub status: String,
    pub request_hash: String,
}

#[cw_serde]
pub struct GetMintRequestsLengthResponse {
    pub length: Uint64,
}

#[cw_serde]
pub struct GetBurnRequestResponse {
    pub request_nonce: Uint64,
    pub requester: String,
    pub amount: Uint128,
    pub deposit_address: String,
    pub tx_id: String,
    pub timestamp: Timestamp,
    pub status: String,
    pub request_hash: String,
}

#[cw_serde]
pub struct GetBurnRequestsLengthResponse {
    pub length: Uint64,
}

#[cw_serde]
pub struct GetTokenDenomResposne {
    pub denom: String,
}

#[cw_serde]
pub struct IsMerchantResponse {
    pub is_merchant: bool,
}

#[cw_serde]
pub struct IsCustodianResponse {
    pub is_custodian: bool,
}

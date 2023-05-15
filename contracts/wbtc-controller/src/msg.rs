use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};
use osmosis_std::types::cosmos::bank::v1beta1::Metadata;

use crate::tokenfactory::{
    burn::{BurnRequest, BurnRequestStatus, BurnRequestWithHash},
    mint::{MintRequest, MintRequestStatus, MintRequestWithHash},
};

/// Message type for `instantiate` entry_point
#[cw_serde]
pub struct InstantiateMsg {
    pub owner: String,

    /// Subdenom of the token that will be created on behalf of this contract
    /// The resulting denom will be tokenfactory denom: "factory/<contract_address>/<subdenom>"
    pub subdenom: String,
}

/// Message type for `execute` entry_point
#[cw_serde]
pub enum ExecuteMsg {
    TransferOwnership {
        new_owner_address: String,
    },
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
    IssueMintRequest {
        amount: Uint128,
        tx_id: String,
        deposit_address: String,
    },
    CancelMintRequest {
        request_hash: String,
    },
    ApproveMintRequest {
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
    SetDenomMetadata {
        metadata: Metadata,
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
    #[returns(GetMintRequestByNonceResponse)]
    GetMintRequestByNonce { nonce: Uint128 },

    #[returns(GetMintRequestByHashResponse)]
    GetMintRequestByHash { request_hash: String },

    #[returns(GetMintRequestsCountResponse)]
    GetMintRequestsCount {},

    #[returns(ListMintRequestsResponse)]
    ListMintRequests {
        limit: Option<u32>,
        start_after_nonce: Option<Uint128>,
        status: Option<MintRequestStatus>,
    },

    #[returns(GetBurnRequestByNonceResponse)]
    GetBurnRequestByNonce { nonce: Uint128 },

    #[returns(GetBurnRequestByHashResponse)]
    GetBurnRequestByHash { request_hash: String },

    #[returns(GetBurnRequestsCountResponse)]
    GetBurnRequestsCount {},

    #[returns(ListBurnRequestsResponse)]
    ListBurnRequests {
        limit: Option<u32>,
        start_after_nonce: Option<Uint128>,
        status: Option<BurnRequestStatus>,
    },

    #[returns(GetTokenDenomResponse)]
    GetTokenDenom {},

    #[returns(IsMerchantResponse)]
    IsMerchant { address: String },

    #[returns(ListMerchantsResponse)]
    ListMerchants {
        limit: Option<u32>,
        start_after: Option<String>,
    },

    #[returns(IsCustodianResponse)]
    IsCustodian { address: String },

    #[returns(GetCustodianResponse)]
    GetCustodian {},

    #[returns(GetOwnerResponse)]
    GetOwner {},

    #[returns(IsOwnerResponse)]
    IsOwner { address: String },

    #[returns(GetCustodianDepositAddressResponse)]
    GetCustodianDepositAddress { merchant: String },

    #[returns(GetMerchantDepositAddressResponse)]
    GetMerchantDepositAddress { merchant: String },
}

#[cw_serde]
pub struct GetMintRequestByNonceResponse {
    pub request_hash: String,
    pub request: MintRequest,
}

#[cw_serde]
pub struct GetMintRequestByHashResponse {
    pub request: MintRequest,
}

#[cw_serde]
pub struct GetMintRequestsCountResponse {
    pub count: Uint128,
}

#[cw_serde]
pub struct ListMintRequestsResponse {
    pub requests: Vec<MintRequestWithHash>,
}

#[cw_serde]
pub struct GetBurnRequestByNonceResponse {
    pub request_hash: String,
    pub request: BurnRequest,
}

#[cw_serde]
pub struct GetBurnRequestByHashResponse {
    pub request: BurnRequest,
}

#[cw_serde]
pub struct GetBurnRequestsCountResponse {
    pub count: Uint128,
}

#[cw_serde]
pub struct ListBurnRequestsResponse {
    pub requests: Vec<BurnRequestWithHash>,
}

#[cw_serde]
pub struct GetTokenDenomResponse {
    pub denom: String,
}

#[cw_serde]
pub struct IsMerchantResponse {
    pub is_merchant: bool,
}

#[cw_serde]
pub struct ListMerchantsResponse {
    pub merchants: Vec<Addr>,
}

#[cw_serde]
pub struct IsCustodianResponse {
    pub is_custodian: bool,
}

#[cw_serde]
pub struct GetCustodianResponse {
    pub address: Addr,
}

#[cw_serde]
pub struct GetOwnerResponse {
    pub address: Addr,
}

#[cw_serde]
pub struct IsOwnerResponse {
    pub is_owner: bool,
}

#[cw_serde]
pub struct GetCustodianDepositAddressResponse {
    pub address: String,
}

#[cw_serde]
pub struct GetMerchantDepositAddressResponse {
    pub address: String,
}

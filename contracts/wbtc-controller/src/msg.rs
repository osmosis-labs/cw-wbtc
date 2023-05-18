use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Coin, Uint128};
use osmosis_std::types::cosmos::bank::v1beta1::Metadata;

use crate::tokenfactory::{
    burn::{BurnRequest, BurnRequestStatus, BurnRequestWithHash},
    mint::{MintRequest, MintRequestStatus, MintRequestWithHash},
};

#[cw_serde]
pub struct InstantiateMsg {
    /// Address of the owner of the contract.
    /// The owner can set the custodian and add/remove merchants.
    /// Ownership can be transferred to another address.
    pub owner: String,

    /// Subdenom of the token that will be created on behalf of this contract
    /// The resulting denom will be tokenfactory denom: "factory/<contract_address>/<subdenom>"
    pub subdenom: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Transfer ownership of the contract to another address.
    TransferOwnership { new_owner_address: String },

    /// Set custodian address.
    SetCustodian { address: String },

    /// Add merchant address.
    AddMerchant { address: String },

    /// Remove merchant address.
    RemoveMerchant { address: String },

    /// Set custodian BTC deposit address of the specified merchant
    SetCustodianDepositAddress {
        merchant: String,
        deposit_address: String,
    },

    /// Set merchant BTC deposit address. Message sender must be a merchant.
    /// This deposit address will be associated with message sender.
    SetMerchantDepositAddress { deposit_address: String },

    /// Issue request to mint tokens.
    /// Only merchants can issue mint requests.
    /// The request needs to be approved by the custodian in order to mint tokens.
    IssueMintRequest {
        amount: Uint128,
        tx_id: String,
        deposit_address: String,
    },

    /// Cancel mint request. Message sender must be the requester.
    CancelMintRequest { request_hash: String },

    /// Approve mint request. Message sender must be the custodian.
    /// The custodian will verify the BTC deposit if it's matched with the requested amount.
    /// If approved, the tokens will be minted to requester address.
    ApproveMintRequest { request_hash: String },

    /// Reject mint request. Message sender must be the custodian.
    RejectMintRequest { request_hash: String },

    /// Burn tokens. Message sender must be merchant.
    /// Funds attached with execute message must match the amount of tokens and denom to be burned.
    /// The tokens will be burned immediately and the BTC will be sent from custodian to the merchant's deposit address.
    Burn { amount: Uint128 },

    /// Only custodian can execute this message.
    /// Once the custodian has sent the BTC to the merchant's deposit address, the custodian can confirm the burn request.
    ConfirmBurnRequest { request_hash: String, tx_id: String },

    /// Set denom metadata. Message sender must be the owner.
    SetDenomMetadata { metadata: Metadata },

    /// Pause contract. Message sender must be the owner.
    Pause {},

    /// Unpause contract. Message sender must be the owner.
    Unpause {},
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Get mint request by nonce.
    #[returns(GetMintRequestByNonceResponse)]
    GetMintRequestByNonce { nonce: Uint128 },

    /// Get mint request by hash.
    #[returns(GetMintRequestByHashResponse)]
    GetMintRequestByHash { request_hash: String },

    /// Count total mint requests.
    #[returns(GetMintRequestsCountResponse)]
    GetMintRequestsCount {},

    /// List mint requests with filter and pagination.
    /// Ordered by nonce.
    #[returns(ListMintRequestsResponse)]
    ListMintRequests {
        /// Maximum number of results to return.
        /// If not specified, default to 10.
        /// Max limit is 100.
        limit: Option<u32>,

        /// Start after the specified nonce.
        start_after_nonce: Option<Uint128>,

        /// Filter by status.
        /// If not specified, default to all statuses.
        status: Option<MintRequestStatus>,
    },

    /// Get burn request by nonce.
    #[returns(GetBurnRequestByNonceResponse)]
    GetBurnRequestByNonce { nonce: Uint128 },

    /// Get burn request by hash.
    #[returns(GetBurnRequestByHashResponse)]
    GetBurnRequestByHash { request_hash: String },

    /// Count total burn requests.
    #[returns(GetBurnRequestsCountResponse)]
    GetBurnRequestsCount {},

    /// List burn requests with filter and pagination.
    /// Ordered by nonce.
    #[returns(ListBurnRequestsResponse)]
    ListBurnRequests {
        /// Maximum number of results to return.
        /// If not specified, default to 10.
        /// Max limit is 100.
        limit: Option<u32>,

        /// Start after the specified nonce.
        start_after_nonce: Option<Uint128>,

        /// Filter by status.
        /// If not specified, default to all statuses.
        status: Option<BurnRequestStatus>,
    },

    /// Get token denom associated with this contract.
    #[returns(GetTokenDenomResponse)]
    GetTokenDenom {},

    /// Check if the specified address is a merchant.
    #[returns(IsMerchantResponse)]
    IsMerchant { address: String },

    /// List merchants with pagination.
    /// Ordered by address.
    #[returns(ListMerchantsResponse)]
    ListMerchants {
        /// Maximum number of results to return.
        /// If not specified, default to 10.
        /// Max limit is 100.
        limit: Option<u32>,

        /// Start after the specified address.
        /// If not specified, default to the first address.
        start_after: Option<String>,
    },

    /// Check if the specified address is a custodian.
    #[returns(IsCustodianResponse)]
    IsCustodian { address: String },

    /// Get custodian address.
    #[returns(GetCustodianResponse)]
    GetCustodian {},

    /// Get owner address.
    #[returns(GetOwnerResponse)]
    GetOwner {},

    /// Check if the specified address is the owner.
    #[returns(IsOwnerResponse)]
    IsOwner { address: String },

    /// Get custodian deposit address of the specified merchant.
    #[returns(GetCustodianDepositAddressResponse)]
    GetCustodianDepositAddress { merchant: String },

    /// Get merchant deposit address of the specified merchant.
    #[returns(GetMerchantDepositAddressResponse)]
    GetMerchantDepositAddress { merchant: String },

    /// Check if token transfers are paused.
    #[returns(IsPausedResponse)]
    IsPaused {},
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

#[cw_serde]
pub struct IsPausedResponse {
    pub is_paused: bool,
}

/// SudoMsg is only exposed for internal Cosmos SDK modules to call.
/// This is showing how we can expose "admin" functionality than can not be called by
/// external users or contracts, but only trusted (native/Go) code in the blockchain
#[cw_serde]
pub enum SudoMsg {
    BlockBeforeSend {
        from: String,
        to: String,
        amount: Coin,
    },
}

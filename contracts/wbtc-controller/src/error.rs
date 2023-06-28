use cosmwasm_std::{StdError, Uint128};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Expect request to have updatable status: request_hash: {request_hash}")]
    UpdatableStatusExpected { request_hash: String },

    #[error(
        "Only merchant can be associated with deposit address but {address} is not a merchant"
    )]
    DepositAddressAssociatedByNonMerchant { address: String },

    #[error("Custodian deposit address not found for merchant {merchant}")]
    CustodianDepositAddressNotFound { merchant: String },

    #[error("Address `{address}` is already added as merchant")]
    DuplicatedMerchant { address: String },

    #[error("Token transfer is paused")]
    TokenTransferPaused {},

    #[error("Burn amount too small: required at least {min_burn_amount}, but got {requested_burn_amount}")]
    BurnAmountTooSmall {
        requested_burn_amount: Uint128,
        min_burn_amount: Uint128,
    },
}

use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Expect request to have status `pending`: request_hash: {request_hash}")]
    PendingRequestExpected { request_hash: String },

    #[error("Custodian deposit address not found for merchant {merchant}")]
    CustodianDepositAddressNotFound { merchant: String },
}

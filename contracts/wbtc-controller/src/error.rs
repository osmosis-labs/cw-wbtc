use cosmwasm_std::{ensure, MessageInfo, StdError, Uint128};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Multiple privileged role for single address is not allowed: `{address}`")]
    AlreadyHasPriviledgedRole { address: String },

    #[error("Expect request to have updatable status: request_hash: {request_hash}")]
    UpdatableStatusExpected { request_hash: String },

    #[error(
        "Only merchant can be associated with deposit address but {address} is not a merchant"
    )]
    DepositAddressAssociatedByNonMerchant { address: String },

    #[error("Deposit address `{address}` is already associated with merchant")]
    DepositAddressAlreadyAssociated { address: String },

    #[error("Custodian deposit address not found for merchant {merchant}")]
    CustodianDepositAddressNotFound { merchant: String },

    #[error("Address `{address}` is not a merchant")]
    NotAMerchant { address: String },

    #[error("Token transfer is paused")]
    TokenTransferPaused {},

    #[error("Burn amount too small: required at least {min_burn_amount}, but got {requested_burn_amount}")]
    BurnAmountTooSmall {
        requested_burn_amount: Uint128,
        min_burn_amount: Uint128,
    },

    #[error("This message does not accept funds")]
    NonPayable {},
}

// ensure that the message sender is the merchant
pub fn non_payable(info: &MessageInfo) -> Result<(), ContractError> {
    ensure!(info.funds.is_empty(), ContractError::NonPayable {});
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{testing::mock_info, Coin};

    #[test]
    fn test_non_payable() {
        let info = mock_info("osmo1xxx", &[]);
        assert!(non_payable(&info).is_ok());

        let info = mock_info("osmo1xxx", &[Coin::new(100, "uosmo")]);
        assert_eq!(
            non_payable(&info).unwrap_err(),
            ContractError::NonPayable {}
        );
    }
}

use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};

use crate::{
    tokenfactory::{deposit_address::DepositAddressManager, RequestManager},
    BurnRequestStatus, MintRequestStatus,
};

pub const CUSTODIAN: Item<Addr> = Item::new("custodian");
pub const GOVERNOR: Item<Addr> = Item::new("governor");
pub const MEMBER_MANAGER: Item<Addr> = Item::new("member_manager");

/// Merchants storage is a map of merchant addresses to empty values
/// This makes it efficient to check if a merchant exists while not storing any data as value
pub const MERCHANTS: Map<Addr, ()> = Map::new("merchants");

/// Token denom storage.
pub const TOKEN_DENOM: Item<String> = Item::new("token_denom");

/// Pause status storage.
pub const IS_PAUSED: Item<bool> = Item::new("is_paused");

/// Mint request storage.
pub fn mint_requests<'a>() -> RequestManager<'a, MintRequestStatus> {
    RequestManager::new(
        "mint_requests",
        "mint_requests__nonce",
        "mint_requests__status_and_nonce",
        "mint_nonce",
    )
}

/// Burn request manager.
pub fn burn_requests<'a>() -> RequestManager<'a, BurnRequestStatus> {
    RequestManager::new(
        "burn_requests",
        "burn_requests__nonce",
        "burn_requests__status_and_nonce",
        "burn_nonce",
    )
}

pub const MIN_BURN_AMOUNT: Item<Uint128> = Item::new("min_burn_amount");

/// Mapping between merchant address to the corresponding custodian BTC deposit address, used in the minting process.
/// by using a different deposit address per merchant the custodian can identify which merchant deposited.
/// Only custodian can set this addresses.
pub const CUSTODIAN_DEPOSIT_ADDRESS_PER_MERCHANT: DepositAddressManager =
    DepositAddressManager::new("custodian_deposit_address_per_merchant");

/// mapping between merchant to the its deposit address where the asset should be moved to, used in the burning process.
pub const MERCHANT_DEPOSIT_ADDRESS: DepositAddressManager =
    DepositAddressManager::new("merchant_deposit_address");

use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

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

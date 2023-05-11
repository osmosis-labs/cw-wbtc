use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::Item;

pub const TOKEN_DENOM: Item<String> = Item::new("token_denom");

pub fn set_token_denom(storage: &mut dyn Storage, token_denom: &String) -> StdResult<()> {
    TOKEN_DENOM.save(storage, token_denom)
}

pub fn get_token_denom(storage: &dyn Storage) -> StdResult<String> {
    TOKEN_DENOM.load(storage)
}

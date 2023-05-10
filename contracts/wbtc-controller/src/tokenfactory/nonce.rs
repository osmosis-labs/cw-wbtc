use cosmwasm_std::{DepsMut, StdResult, Uint128};
use cw_storage_plus::Item;

pub struct Nonce<'a> {
    pub nonce: Item<'a, Uint128>,
}

impl<'a> Nonce<'a> {
    pub const fn new(namespace: &'a str) -> Nonce<'a> {
        Self {
            nonce: Item::new(namespace),
        }
    }

    pub fn next(&self, deps: &mut DepsMut) -> StdResult<Uint128> {
        // load nonce from state
        let nonce = self.nonce.may_load(deps.storage)?.unwrap_or_default();

        // update nonce to be used for next request
        self.nonce.save(deps.storage, &(nonce + Uint128::new(1)))?;

        // return the loaded nonce
        Ok(nonce)
    }
}

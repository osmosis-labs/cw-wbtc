#[cfg(test)]
use cosmwasm_std::Deps;
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

    /// Return current nonce and increment it by 1
    pub fn next(&self, deps: &mut DepsMut) -> StdResult<Uint128> {
        // load nonce from state
        let nonce = self.nonce.may_load(deps.storage)?.unwrap_or_default();

        // update nonce to be used for next request
        self.nonce
            .save(deps.storage, &(nonce.checked_add(Uint128::new(1))?))?;

        // return the loaded nonce
        Ok(nonce)
    }

    #[cfg(test)]
    /// Current nonce that will be used for the next request
    pub fn current(&self, deps: Deps) -> StdResult<Uint128> {
        self.nonce.load(deps.storage)
    }
}

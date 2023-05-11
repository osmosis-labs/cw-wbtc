use cosmwasm_std::{attr, Attribute};

pub fn method_attrs<A: Into<Attribute>>(
    method: &str,
    attrs: impl IntoIterator<Item = A>,
) -> Vec<Attribute> {
    let mut res = vec![attr("method", method)];
    res.extend(attrs.into_iter().map(A::into));

    res
}

#[cfg(test)]
pub mod test_helpers {
    use cosmwasm_std::{
        testing::{mock_env, mock_info},
        Addr, ContractInfo, DepsMut, Env,
    };

    use crate::{
        contract::instantiate, msg::InstantiateMsg, tokenfactory::token::TOKEN_DENOM, ContractError,
    };

    pub fn setup_contract(
        mut deps: DepsMut,
        contract_address: &str,
        owner: &str,
        subdenom: &str,
    ) -> Result<String, ContractError> {
        let info = mock_info(owner, &[]);
        let msg = InstantiateMsg {
            owner: info.sender.to_string(),
            subdenom: subdenom.to_string(),
        };

        let env = Env {
            contract: ContractInfo {
                address: Addr::unchecked(contract_address),
            },
            ..mock_env()
        };

        instantiate(deps.branch(), env, info.clone(), msg)?;

        let new_token_denom = format!("factory/{}/{}", contract_address, subdenom);

        // set token denom
        TOKEN_DENOM.save(deps.storage, &new_token_denom).unwrap();

        Ok(new_token_denom)
    }
}

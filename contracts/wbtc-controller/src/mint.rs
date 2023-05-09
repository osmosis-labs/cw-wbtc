use crate::{
    auth::{allow_only, Role},
    request::{Request, RequestStatus},
    ContractError,
};
use cosmwasm_std::{DepsMut, Env, Event, MessageInfo, Response, StdResult, Uint128};
use cw_storage_plus::{Item, Map};

const MINT_REQUESTS: Map<String, Request> = Map::new("mint_requests");
const MINT_NONCE: Item<Uint128> = Item::new("mint_nonce");

pub fn add_mint_request(
    mut deps: DepsMut,
    info: MessageInfo,
    env: Env,
    amount: Uint128,
    tx_id: String,
    deposit_address: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;

    let nonce = next_nonce(&mut deps)?;
    let event = Event::new("mint_request_added")
        .add_attribute("sender", info.sender.as_str())
        .add_attribute("amount", amount)
        .add_attribute("tx_id", tx_id.as_str())
        .add_attribute("deposit_address", deposit_address.as_str())
        .add_attribute("nonce", nonce)
        .add_attribute("block_height", env.block.height.to_string())
        .add_attribute("timestamp", env.block.time.nanos().to_string())
        .add_attribute(
            "transaction_index",
            env.transaction
                .as_ref()
                .map(|t| t.index.to_string())
                .unwrap_or_default(),
        );

    let request = Request {
        requester: info.sender,
        amount,
        tx_id,
        deposit_address,
        block: env.block,
        transaction: env.transaction,
        contract: env.contract,
        nonce,
        status: RequestStatus::Pending,
    };

    let request_hash = update_mint_request(&mut deps, &request)?;
    let event = event.add_attribute("request_hash", request_hash);

    Ok(Response::new().add_event(event))
}

fn update_mint_request(deps: &mut DepsMut, request: &Request) -> StdResult<String> {
    let request_hash = request.hash()?.to_base64();
    MINT_REQUESTS.save(deps.storage, request_hash.clone(), &request)?;

    Ok(request_hash)
}

fn next_nonce(deps: &mut DepsMut) -> StdResult<Uint128> {
    // load nonce from state
    let nonce = MINT_NONCE.may_load(deps.storage)?.unwrap_or_default();

    // update nonce to be used for next request
    MINT_NONCE.save(deps.storage, &(nonce + Uint128::new(1)))?;

    // return the loaded nonce
    Ok(nonce)
}

// TODO: test with add and confirm, add and reject, add and cancel
#[cfg(test)]
mod tests {
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_info},
        Addr, BlockInfo, Env, Event, Response, Timestamp, TransactionInfo, Uint128,
    };

    use crate::{
        auth::{custodian, merchant, owner},
        mint::add_mint_request,
        ContractError,
    };

    #[test]
    fn test_add_mint_request() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant_1 = "osmo1merchant1";
        let mut deps = mock_dependencies();

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant_1).unwrap();

        let mut add_mint_request_fixture = |sender: &str| {
            add_mint_request(
                deps.as_mut(),
                mock_info(sender, &[]),
                Env {
                    block: BlockInfo {
                        height: 1,
                        time: Timestamp::from_seconds(1689069540),
                        chain_id: "osmosis-1".to_string(),
                    },
                    transaction: Some(TransactionInfo { index: 1 }),
                    contract: cosmwasm_std::ContractInfo {
                        address: Addr::unchecked(
                            "osmo14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sq2r9g9",
                        ),
                    },
                },
                Uint128::new(100_000_000),
                "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf".to_string(),
                "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun".to_string(),
            )
        };

        // add mint request fail with unauthorized if not merchant
        assert_eq!(
            add_mint_request_fixture(owner).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            add_mint_request_fixture(custodian).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            add_mint_request_fixture(merchant_1).unwrap(),
            Response::new().add_event(
                Event::new("mint_request_added")
                    .add_attribute("sender", merchant_1)
                    .add_attribute("amount", "100000000")
                    .add_attribute(
                        "tx_id",
                        "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf"
                    )
                    .add_attribute(
                        "deposit_address",
                        "bc1qzmylp874rg2st6pdlt8yjga3ek9pr96wuzelun"
                    )
                    .add_attribute("nonce", "0")
                    .add_attribute("block_height", "1")
                    .add_attribute("timestamp", "1689069540000000000")
                    .add_attribute("transaction_index", "1")
                    .add_attribute(
                        "request_hash",
                        "S+29PBJLMGmBKBG18A+lUROSno6Mqkwq0BjXK1yhMlU="
                    )
            )
        );
    }
}

use crate::{
    auth::{allow_only, Role},
    nonce::Nonce,
    request::{Request, RequestStatus},
    ContractError,
};
use cosmwasm_std::{DepsMut, Env, Event, MessageInfo, Response, StdResult, Uint128};
use cw_storage_plus::Map;

const MINT_REQUESTS: Map<String, Request> = Map::new("mint_requests");
const MINT_NONCE: Nonce = Nonce::new("mint_nonce");

pub fn add_mint_request(
    mut deps: DepsMut,
    info: MessageInfo,
    env: Env,
    amount: Uint128,
    tx_id: String,
    deposit_address: String,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Merchant], &info.sender, deps.as_ref())?;

    let nonce = MINT_NONCE.next(&mut deps)?;
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

// TODO: test with add and confirm, add and reject, add and cancel
#[cfg(test)]
mod tests {

    use cosmwasm_std::{
        testing::{mock_dependencies, mock_info},
        Addr, BlockInfo, DepsMut, Env, Event, Response, Timestamp, TransactionInfo, Uint128,
    };

    use crate::{
        auth::{custodian, merchant, owner},
        mint::{add_mint_request, MINT_NONCE, MINT_REQUESTS},
        request::RequestStatus,
        ContractError,
    };

    #[test]
    fn test_add_mint_request() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let mut deps = mock_dependencies();

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

        let add_mint_request_fixture = |deps: DepsMut, sender: &str| {
            add_mint_request(
                deps,
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
            add_mint_request_fixture(deps.as_mut(), owner).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            add_mint_request_fixture(deps.as_mut(), custodian).unwrap_err(),
            ContractError::Unauthorized {}
        );

        let hash_on_nonce_0 = "ccD5o4NXxNaqYukHobbmZSf8tYOv1HyzPKG4dT1pGbA=";

        assert_eq!(
            add_mint_request_fixture(deps.as_mut(), merchant).unwrap(),
            Response::new().add_event(
                Event::new("mint_request_added")
                    .add_attribute("sender", merchant)
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
                    .add_attribute("request_hash", hash_on_nonce_0)
            )
        );

        // mint request should be saved
        let request = MINT_REQUESTS
            .load(deps.as_ref().storage, hash_on_nonce_0.to_owned())
            .unwrap();

        assert_eq!(request.nonce, Uint128::new(0));
        assert_eq!(request.status, RequestStatus::Pending);
        assert_eq!(request.hash().unwrap().to_base64(), hash_on_nonce_0);

        // nonce should be incremented
        assert_eq!(
            MINT_NONCE.nonce.load(deps.as_ref().storage).unwrap(),
            Uint128::new(1)
        );

        // same request with same sender, even on the same tx must result in different hash
        let hash_on_nonce_1 = add_mint_request_fixture(deps.as_mut(), merchant)
            .unwrap()
            .events[0]
            .attributes
            .iter()
            .find(|attr| attr.key == "request_hash")
            .unwrap()
            .value
            .clone();

        assert_ne!(hash_on_nonce_0, hash_on_nonce_1);

        // nonce should be incremented
        assert_eq!(
            MINT_NONCE.nonce.load(deps.as_ref().storage).unwrap(),
            Uint128::new(2)
        );
    }
}

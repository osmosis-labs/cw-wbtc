#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdResult,
};
use cw2::set_contract_version;

use crate::auth::{custodian, merchant, owner};
use crate::error::ContractError;
use crate::msg::{
    ExecuteMsg, GetCustodianResponse, InstantiateMsg, IsCustodianResponse, IsMerchantResponse,
    MigrateMsg, QueryMsg,
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:wbtc-controller";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Handling contract instantiation
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Initialize the admin, no auth is required only at contract instantiation
    owner::initialize_owner(deps, msg.owner.as_ref())?;

    // With `Response` type, it is possible to dispatch message to invoke external logic.
    // See: https://github.com/CosmWasm/cosmwasm/blob/main/SEMANTICS.md#dispatching-messages
    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

/// Handling contract migration
/// To make a contract migratable, you need
/// - this entry_point implemented
/// - only contract admin can migrate, so admin has to be set at contract initiation time
/// Handling contract execution
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    match msg {
        // Find matched incoming message variant and execute them with your custom logic.
        //
        // With `Response` type, it is possible to dispatch message to invoke external logic.
        // See: https://github.com/CosmWasm/cosmwasm/blob/main/SEMANTICS.md#dispatching-messages
    }
}

/// Handling contract execution
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::TransferOwnership { new_owner_address } => {
            owner::transfer_ownership(deps, &info, &new_owner_address)
        }
        ExecuteMsg::SetCustodian { address } => custodian::set_custodian(deps, &address),
        ExecuteMsg::SetCustodianDepositAddress {
            merchant: _,
            deposit_address: _,
        } => todo!(),
        ExecuteMsg::AddMerchant { address } => merchant::add_merchant(deps, info, &address),
        ExecuteMsg::RemoveMerchant { address } => merchant::remove_merchant(deps, info, &address),
        ExecuteMsg::SetMerchantDepositAddress { deposit_address: _ } => todo!(),
        ExecuteMsg::AddMintRequest {
            amount: _,
            tx_id: _,
            deposit_address: _,
        } => todo!(),
        ExecuteMsg::CancelMintRequest { request_hash: _ } => todo!(),
        ExecuteMsg::ConfirmMintRequest { request_hash: _ } => todo!(),
        ExecuteMsg::RejectMintRequest { request_hash: _ } => todo!(),
        ExecuteMsg::Burn { amount: _ } => todo!(),
        ExecuteMsg::ConfirmBurnRequest {
            request_hash: _,
            tx_id: _,
        } => todo!(),
        ExecuteMsg::Pause {} => todo!(),
        ExecuteMsg::Unpause {} => todo!(),
    }
}

/// Handling contract query
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMintRequest { nonce: _ } => todo!(),
        QueryMsg::GetMintRequestsLength {} => todo!(),
        QueryMsg::GetBurnRequest { nonce: _ } => todo!(),
        QueryMsg::GetBurnRequestsLength {} => todo!(),
        QueryMsg::GetTokenDenom {} => todo!(),
        QueryMsg::IsMerchant { address } => to_binary(&IsMerchantResponse {
            is_merchant: merchant::is_merchant(deps, &address)?,
        }),
        QueryMsg::IsCustodian { address } => to_binary(&IsCustodianResponse {
            is_custodian: custodian::is_custodian(deps, &address)?,
        }),
        QueryMsg::GetCustodian {} => to_binary(&GetCustodianResponse {
            address: custodian::get_custodian(deps)?.to_string(),
        }),
        QueryMsg::GetOwner {} => to_binary(&owner::get_owner(deps)?.to_string()),
        QueryMsg::IsOwner { address } => {
            to_binary(&owner::is_owner(deps, &deps.api.addr_validate(&address)?)?)
        }
    }
}

/// Handling submessage reply.
/// For more info on submessage and reply, see https://github.com/CosmWasm/cosmwasm/blob/main/SEMANTICS.md#submessages
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, _msg: Reply) -> Result<Response, ContractError> {
    // With `Response` type, it is still possible to dispatch message to invoke external logic.
    // See: https://github.com/CosmWasm/cosmwasm/blob/main/SEMANTICS.md#dispatching-messages

    todo!()
}

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdError, StdResult,
    SubMsg,
};
use cw2::set_contract_version;
use osmosis_std::types::osmosis::tokenfactory::v1beta1::{MsgCreateDenom, MsgCreateDenomResponse};

use crate::auth::{custodian, merchant, owner};
use crate::error::ContractError;
use crate::msg::{
    ExecuteMsg, GetBurnRequestByNonceResponse, GetCustodianDepositAddressResponse,
    GetCustodianResponse, GetMintRequestByNonceResponse, GetOwnerResponse, GetTokenDenomResponse,
    InstantiateMsg, IsCustodianResponse, IsMerchantResponse, IsOwnerResponse, MigrateMsg, QueryMsg,
};
use crate::tokenfactory::burn;
use crate::tokenfactory::mint;
use crate::tokenfactory::{deposit_address, token};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:wbtc-controller";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

const CREATE_DENOM_REPLY_ID: u64 = 1;

/// Handling contract instantiation
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Initialize the admin, no auth is required only at contract instantiation
    owner::initialize_owner(deps, msg.owner.as_ref())?;

    // create denom
    let msg_create_denom = SubMsg::reply_on_success(
        MsgCreateDenom {
            sender: env.contract.address.to_string(),
            subdenom: msg.subdenom,
        },
        CREATE_DENOM_REPLY_ID,
    );

    Ok(Response::new()
        .add_submessage(msg_create_denom)
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
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::TransferOwnership { new_owner_address } => {
            owner::transfer_ownership(deps, &info, &new_owner_address)
        }
        ExecuteMsg::SetCustodian { address } => custodian::set_custodian(deps, &info, &address),
        ExecuteMsg::SetCustodianDepositAddress {
            merchant,
            deposit_address,
        } => deposit_address::set_custodian_deposit_address(
            deps,
            &info,
            merchant.as_str(),
            &deposit_address,
        ),
        ExecuteMsg::AddMerchant { address } => merchant::add_merchant(deps, &info, &address),
        ExecuteMsg::RemoveMerchant { address } => merchant::remove_merchant(deps, &info, &address),
        ExecuteMsg::SetMerchantDepositAddress { deposit_address } => {
            deposit_address::set_merchant_deposit_address(deps, &info, &deposit_address)
        }
        ExecuteMsg::IssueMintRequest {
            amount,
            tx_id,
            deposit_address,
        } => mint::issue_mint_request(deps, info, env, amount, tx_id, deposit_address),
        ExecuteMsg::CancelMintRequest { request_hash } => {
            mint::cancel_mint_request(deps, info, env.contract.address, request_hash)
        }
        ExecuteMsg::ApproveMintRequest { request_hash } => {
            mint::approve_mint_request(deps, info, env.contract.address, request_hash)
        }
        ExecuteMsg::RejectMintRequest { request_hash } => {
            mint::reject_mint_request(deps, info, env.contract.address, request_hash)
        }
        ExecuteMsg::Burn { amount } => burn::burn(deps, env, info, amount),
        ExecuteMsg::ConfirmBurnRequest {
            request_hash,
            tx_id,
        } => burn::confirm_burn_request(deps, env, info, request_hash, tx_id),
        ExecuteMsg::Pause {} => todo!(),
        ExecuteMsg::Unpause {} => todo!(),
    }
}

/// Handling contract query
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMintRequestByNonce { nonce } => {
            let (request_hash, request) = mint::get_mint_request_by_nonce(deps, &nonce)?;
            to_binary(&GetMintRequestByNonceResponse {
                request_hash,
                request,
            })
        }
        QueryMsg::GetMintRequestsLength {} => todo!(),
        QueryMsg::GetBurnRequestByNonce { nonce } => {
            let (request_hash, request) = burn::get_burn_request_by_nonce(deps, &nonce)?;
            to_binary(&GetBurnRequestByNonceResponse {
                request_hash,
                request,
            })
        }
        QueryMsg::GetBurnRequestsLength {} => todo!(),
        QueryMsg::GetTokenDenom {} => to_binary(&GetTokenDenomResponse {
            denom: token::get_token_denom(deps.storage)?,
        }),
        QueryMsg::IsMerchant { address } => to_binary(&IsMerchantResponse {
            is_merchant: merchant::is_merchant(deps, &deps.api.addr_validate(&address)?)?,
        }),
        QueryMsg::IsCustodian { address } => to_binary(&IsCustodianResponse {
            is_custodian: custodian::is_custodian(deps, &deps.api.addr_validate(&address)?)?,
        }),
        QueryMsg::GetCustodian {} => to_binary(&GetCustodianResponse {
            address: custodian::get_custodian(deps)?,
        }),
        QueryMsg::GetOwner {} => to_binary(&GetOwnerResponse {
            address: owner::get_owner(deps)?,
        }),
        QueryMsg::IsOwner { address } => to_binary(&IsOwnerResponse {
            is_owner: owner::is_owner(deps, &deps.api.addr_validate(&address)?)?,
        }),
        QueryMsg::GetCustodianDepositAddress { merchant } => {
            to_binary(&GetCustodianDepositAddressResponse {
                address: deposit_address::get_custodian_deposit_address(
                    deps,
                    &deps.api.addr_validate(&merchant)?,
                )?,
            })
        }
        QueryMsg::GetMerchantDepositAddress { merchant } => {
            to_binary(&deposit_address::get_merchant_deposit_address(
                deps,
                &deps.api.addr_validate(&merchant)?,
            )?)
        }
    }
}

/// Handling submessage reply.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        CREATE_DENOM_REPLY_ID => {
            // register created token denom
            let MsgCreateDenomResponse { new_token_denom } = msg.result.try_into()?;
            token::set_token_denom(deps.storage, &new_token_denom)?;

            Ok(Response::new().add_attribute("new_token_denom", new_token_denom))
        }
        _ => Err(StdError::not_found(format!("No reply handler found for: {:?}", msg)).into()),
    }
}

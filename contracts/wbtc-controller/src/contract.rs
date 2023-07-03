#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    ensure, to_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Reply, Response,
    StdError, StdResult, SubMsg,
};
use cw2::set_contract_version;
use osmosis_std::types::osmosis::tokenfactory::v1beta1::{
    MsgCreateDenom, MsgCreateDenomResponse, MsgSetBeforeSendHook,
};

use crate::auth::{custodian, governor, member_manager, merchant};
use crate::error::{non_payable, ContractError};
use crate::msg::{
    ExecuteMsg, GetBurnRequestByHashResponse, GetBurnRequestByNonceResponse,
    GetBurnRequestsCountResponse, GetCustodianDepositAddressResponse, GetCustodianResponse,
    GetGovernorResponse, GetMemberManagerResponse, GetMinBurnAmountResponse,
    GetMintRequestByHashResponse, GetMintRequestByNonceResponse, GetMintRequestsCountResponse,
    GetTokenDenomResponse, InstantiateMsg, IsCustodianResponse, IsGovernorResponse,
    IsMemberManagerResponse, IsMerchantResponse, IsPausedResponse, ListBurnRequestsResponse,
    ListMerchantsResponse, ListMintRequestsResponse, QueryMsg, SudoMsg,
};
use crate::tokenfactory::burn;
use crate::tokenfactory::mint;
use crate::tokenfactory::{deposit_address, token};

// version info for migration info
pub const CONTRACT_NAME: &str = "crates.io:wbtc-controller";
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    governor::initialize_governor(deps, msg.governor.as_ref())?;

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
        .add_attribute("action", "instantiate")
        .add_attribute("governor", info.sender))
}

/// Handling contract execution
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    // no execute message requires sending funds, reject all non-zero funds
    non_payable(&info)?;

    match msg {
        // === mint ===
        ExecuteMsg::IssueMintRequest { amount, tx_id } => {
            mint::issue_mint_request(deps, env, info, amount, tx_id)
        }
        ExecuteMsg::CancelMintRequest { request_hash } => {
            mint::cancel_mint_request(deps, info, request_hash)
        }
        ExecuteMsg::ApproveMintRequest { request_hash } => {
            mint::approve_mint_request(deps, info, env.contract.address, request_hash)
        }
        ExecuteMsg::RejectMintRequest { request_hash } => {
            mint::reject_mint_request(deps, info, request_hash)
        }

        // === burn ===
        ExecuteMsg::Burn { amount } => burn::burn(deps, env, info, amount),
        ExecuteMsg::ConfirmBurnRequest {
            request_hash,
            tx_id,
        } => burn::confirm_burn_request(deps, info, request_hash, tx_id),
        ExecuteMsg::SetMinBurnAmount { amount } => burn::set_min_burn_amount(deps, &info, amount),

        // === auth ===
        ExecuteMsg::TransferGovernorship {
            new_governor_address,
        } => governor::transfer_governorship(deps, &info, &new_governor_address),
        ExecuteMsg::SetMemberManager { address } => {
            member_manager::set_member_manager(deps, &info, &address)
        }
        ExecuteMsg::SetCustodian { address } => custodian::set_custodian(deps, &info, &address),
        ExecuteMsg::AddMerchant { address } => merchant::add_merchant(deps, &info, &address),
        ExecuteMsg::RemoveMerchant { address } => merchant::remove_merchant(deps, &info, &address),

        // === deposit address ===
        ExecuteMsg::SetCustodianDepositAddress {
            merchant,
            deposit_address,
        } => deposit_address::set_custodian_deposit_address(
            deps,
            &info,
            merchant.as_str(),
            &deposit_address,
        ),
        ExecuteMsg::SetMerchantDepositAddress { deposit_address } => {
            deposit_address::set_merchant_deposit_address(deps, &info, &deposit_address)
        }

        ExecuteMsg::SetDenomMetadata { metadata } => {
            token::set_denom_metadata(deps.as_ref(), &env, &info, metadata)
        }

        // === pausing ===
        ExecuteMsg::Pause {} => token::pause(deps, &info),
        ExecuteMsg::Unpause {} => token::unpause(deps, &info),
    }
}

/// Handling contract query
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        // === mint ===
        QueryMsg::GetMintRequestByNonce { nonce } => {
            let (request_hash, request) = mint::get_mint_request_by_nonce(deps, &nonce)?;
            to_binary(&GetMintRequestByNonceResponse {
                request_hash,
                request,
            })
        }
        QueryMsg::GetMintRequestByHash { request_hash } => {
            to_binary(&GetMintRequestByHashResponse {
                request: mint::get_mint_request_by_hash(deps, &request_hash)?,
            })
        }
        QueryMsg::GetMintRequestsCount {} => to_binary(&GetMintRequestsCountResponse {
            count: mint::get_mint_request_count(deps)?,
        }),

        QueryMsg::ListMintRequests {
            limit,
            start_after_nonce,
            status,
        } => to_binary(&ListMintRequestsResponse {
            requests: mint::list_mint_requests(deps, limit, start_after_nonce, status)?,
        }),

        // === burn ===
        QueryMsg::GetBurnRequestByNonce { nonce } => {
            let (request_hash, request) = burn::get_burn_request_by_nonce(deps, &nonce)?;
            to_binary(&GetBurnRequestByNonceResponse {
                request_hash,
                request,
            })
        }
        QueryMsg::GetBurnRequestByHash { request_hash } => {
            to_binary(&GetBurnRequestByHashResponse {
                request: burn::get_burn_request_by_hash(deps, &request_hash)?,
            })
        }
        QueryMsg::GetBurnRequestsCount {} => to_binary(&GetBurnRequestsCountResponse {
            count: burn::get_burn_request_count(deps)?,
        }),

        QueryMsg::ListBurnRequests {
            limit,
            start_after_nonce,
            status,
        } => to_binary(&ListBurnRequestsResponse {
            requests: burn::list_burn_requests(deps, limit, start_after_nonce, status)?,
        }),

        QueryMsg::GetMinBurnAmount {} => to_binary(&GetMinBurnAmountResponse {
            amount: burn::get_min_burn_amount(deps)?,
        }),

        // === token ===
        QueryMsg::GetTokenDenom {} => to_binary(&GetTokenDenomResponse {
            denom: token::get_token_denom(deps.storage)?,
        }),

        // === auth ===
        QueryMsg::IsMerchant { address } => to_binary(&IsMerchantResponse {
            is_merchant: merchant::is_merchant(deps, &deps.api.addr_validate(&address)?)?,
        }),
        QueryMsg::ListMerchants { limit, start_after } => to_binary(&ListMerchantsResponse {
            merchants: merchant::list_merchants(deps, start_after, limit)?,
        }),
        QueryMsg::IsMemberManager { address } => to_binary(&IsMemberManagerResponse {
            is_member_manager: member_manager::is_member_manager(
                deps,
                &deps.api.addr_validate(&address)?,
            )?,
        }),
        QueryMsg::GetMemberManager {} => to_binary(&GetMemberManagerResponse {
            address: member_manager::get_member_manager(deps)?,
        }),
        QueryMsg::IsCustodian { address } => to_binary(&IsCustodianResponse {
            is_custodian: custodian::is_custodian(deps, &deps.api.addr_validate(&address)?)?,
        }),
        QueryMsg::GetCustodian {} => to_binary(&GetCustodianResponse {
            address: custodian::get_custodian(deps)?,
        }),
        QueryMsg::GetGovernor {} => to_binary(&GetGovernorResponse {
            address: governor::get_governor(deps)?,
        }),
        QueryMsg::IsGovernor { address } => to_binary(&IsGovernorResponse {
            is_governor: governor::is_governor(deps, &deps.api.addr_validate(&address)?)?,
        }),

        // == deposit address ==
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

        // == pausing ==
        QueryMsg::IsPaused {} => to_binary(&IsPausedResponse {
            is_paused: token::is_paused(deps)?,
        }),
    }
}

/// Handling submessage reply.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        CREATE_DENOM_REPLY_ID => {
            // register created token denom
            let MsgCreateDenomResponse { new_token_denom } = msg.result.try_into()?;
            token::set_token_denom(deps.storage, &new_token_denom)?;

            // set beforesend listener to this contract
            // this will trigger sudo endpoint before any bank send
            // which makes token transfer pause possible
            let msg_set_beforesend_hook: CosmosMsg = MsgSetBeforeSendHook {
                sender: env.contract.address.to_string(),
                denom: new_token_denom.clone(),
                cosmwasm_address: env.contract.address.to_string(),
            }
            .into();

            Ok(Response::new()
                .add_attribute("new_token_denom", new_token_denom)
                .add_message(msg_set_beforesend_hook))
        }
        _ => Err(StdError::not_found(format!("No reply handler found for: {:?}", msg)).into()),
    }
}

/// Handling contract sudo call.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, _env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    match msg {
        // Hook for bank send (aka. token transfer), this is called before the token is sent if this contract is registered with MsgSetBeforeSendHook
        SudoMsg::BlockBeforeSend { .. } => {
            // ensure that token transfer is not paused
            let token_transfer_is_not_paused = !token::is_paused(deps.as_ref())?;
            ensure!(
                token_transfer_is_not_paused,
                ContractError::TokenTransferPaused {}
            );

            Ok(Response::new().add_attribute("hook", "block_before_send"))
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Coin,
    };

    use super::*;

    #[test]
    fn execute_reject_all_non_zero_funds() {
        // sample messages
        let msgs = vec![
            ExecuteMsg::Burn {
                amount: 1000u128.into(),
            },
            ExecuteMsg::Pause {},
            ExecuteMsg::SetMinBurnAmount {
                amount: 10000u128.into(),
            },
            ExecuteMsg::IssueMintRequest {
                amount: 10000u128.into(),
                tx_id: "tx_id".to_string(),
            },
        ];

        for msg in msgs {
            let mut deps = mock_dependencies();
            let err = execute(
                deps.as_mut(),
                mock_env(),
                mock_info("sender", &[Coin::new(1, "uosmo")]),
                msg,
            )
            .unwrap_err();
            assert_eq!(err, ContractError::NonPayable {});
        }
    }
}

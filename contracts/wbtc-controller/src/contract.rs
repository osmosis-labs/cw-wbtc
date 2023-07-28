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
    GetGovernorCandidateResponse, GetGovernorResponse, GetMemberManagerResponse,
    GetMerchantDepositAddressResponse, GetMinBurnAmountResponse, GetMintRequestByHashResponse,
    GetMintRequestByNonceResponse, GetMintRequestsCountResponse, GetTokenDenomResponse,
    InstantiateMsg, IsCustodianResponse, IsGovernorCandidateResponse, IsGovernorResponse,
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
    _info: MessageInfo,
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
        .add_attribute("governor", msg.governor))
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
        ExecuteMsg::ClaimGovernorship {} => governor::claim_governorship(deps, info),
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
            deposit_address.as_deref(),
        ),
        ExecuteMsg::SetMerchantDepositAddress { deposit_address } => {
            deposit_address::set_merchant_deposit_address(deps, &info, deposit_address.as_deref())
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
        QueryMsg::GetGovernorCandidate {} => to_binary(&GetGovernorCandidateResponse {
            address: governor::get_governor_candidate(deps)?,
        }),
        QueryMsg::IsGovernor { address } => to_binary(&IsGovernorResponse {
            is_governor: governor::is_governor(deps, &deps.api.addr_validate(&address)?)?,
        }),
        QueryMsg::IsGovernorCandidate { address } => to_binary(&IsGovernorCandidateResponse {
            is_governor_candidate: governor::is_governor_candidate(
                deps,
                &deps.api.addr_validate(&address)?,
            )?,
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
            to_binary(&GetMerchantDepositAddressResponse {
                address: deposit_address::get_merchant_deposit_address(
                    deps,
                    &deps.api.addr_validate(&merchant)?,
                )?,
            })
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
        attr, from_binary,
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, Coin, SubMsgResponse, SubMsgResult,
    };

    use crate::msg::{GetMerchantDepositAddressResponse, IsGovernorCandidateResponse};

    use super::*;

    #[test]
    fn instantiate_attrs() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            governor: "osmo1governor".to_string(),
            subdenom: "subdenom".to_string(),
        };

        let info = mock_info("creator", &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // check attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "instantiate"),
                attr("governor", "osmo1governor"),
            ]
        );
    }

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

    #[test]
    fn smoke_test() {
        let mut deps = mock_dependencies();
        let instantiator = "osmo1instantiator";
        let governor = "osmo1governor";
        let new_governor = "osmo1newgovernor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info(instantiator, &[]),
            InstantiateMsg {
                governor: String::from(governor),
                subdenom: String::from("wbtc"),
            },
        )
        .unwrap();

        let token_denom = format!("factory/{}/wbtc", mock_env().contract.address);

        reply(
            deps.as_mut(),
            mock_env(),
            Reply {
                id: CREATE_DENOM_REPLY_ID,
                result: SubMsgResult::Ok(SubMsgResponse {
                    events: vec![],
                    data: Some(
                        MsgCreateDenomResponse {
                            new_token_denom: token_denom.clone(),
                        }
                        .into(),
                    ),
                }),
            },
        )
        .unwrap();

        // check token denom
        assert_eq!(
            from_binary::<GetTokenDenomResponse>(
                &query(deps.as_ref(), mock_env(), QueryMsg::GetTokenDenom {}).unwrap()
            )
            .unwrap(),
            GetTokenDenomResponse {
                denom: token_denom.clone()
            }
        );

        // no reply hanlder for this id
        reply(
            deps.as_mut(),
            mock_env(),
            Reply {
                id: 999999999999999,
                result: SubMsgResult::Ok(SubMsgResponse {
                    events: vec![],
                    data: Some(
                        MsgCreateDenomResponse {
                            new_token_denom: token_denom,
                        }
                        .into(),
                    ),
                }),
            },
        )
        .unwrap_err();

        // set member manager
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(governor, &[]),
            ExecuteMsg::SetMemberManager {
                address: member_manager.to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            from_binary::<GetMemberManagerResponse>(
                &query(deps.as_ref(), mock_env(), QueryMsg::GetMemberManager {}).unwrap()
            )
            .unwrap(),
            GetMemberManagerResponse {
                address: Addr::unchecked(member_manager)
            }
        );

        assert_eq!(
            from_binary::<IsMemberManagerResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsMemberManager {
                        address: member_manager.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            IsMemberManagerResponse {
                is_member_manager: true
            }
        );

        // set custodian
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(member_manager, &[]),
            ExecuteMsg::SetCustodian {
                address: custodian.to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            from_binary::<GetCustodianResponse>(
                &query(deps.as_ref(), mock_env(), QueryMsg::GetCustodian {}).unwrap()
            )
            .unwrap(),
            GetCustodianResponse {
                address: Addr::unchecked(custodian)
            }
        );

        assert_eq!(
            from_binary::<IsCustodianResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsCustodian {
                        address: custodian.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            IsCustodianResponse { is_custodian: true }
        );

        // add merchant
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(member_manager, &[]),
            ExecuteMsg::AddMerchant {
                address: merchant.to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            from_binary::<ListMerchantsResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::ListMerchants {
                        limit: None,
                        start_after: None
                    }
                )
                .unwrap()
            )
            .unwrap(),
            ListMerchantsResponse {
                merchants: vec![Addr::unchecked(merchant)]
            }
        );

        assert_eq!(
            from_binary::<IsMerchantResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsMerchant {
                        address: merchant.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            IsMerchantResponse { is_merchant: true }
        );

        // remove merchant
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(member_manager, &[]),
            ExecuteMsg::RemoveMerchant {
                address: merchant.to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            from_binary::<ListMerchantsResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::ListMerchants {
                        limit: None,
                        start_after: None
                    }
                )
                .unwrap()
            )
            .unwrap(),
            ListMerchantsResponse { merchants: vec![] }
        );

        assert_eq!(
            from_binary::<IsMerchantResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsMerchant {
                        address: merchant.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            IsMerchantResponse { is_merchant: false }
        );

        // re-add merchant back for later tests
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(member_manager, &[]),
            ExecuteMsg::AddMerchant {
                address: merchant.to_string(),
            },
        )
        .unwrap();

        // set merchant deposit address
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(merchant, &[]),
            ExecuteMsg::SetMerchantDepositAddress {
                deposit_address: Some("merchant_deposit_address".to_string()),
            },
        )
        .unwrap();

        assert_eq!(
            from_binary::<GetMerchantDepositAddressResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::GetMerchantDepositAddress {
                        merchant: merchant.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            GetMerchantDepositAddressResponse {
                address: "merchant_deposit_address".to_string()
            }
        );

        // set custodian deposit address
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(custodian, &[]),
            ExecuteMsg::SetCustodianDepositAddress {
                merchant: merchant.to_string(),
                deposit_address: Some("custodian_deposit_address".to_string()),
            },
        )
        .unwrap();

        assert_eq!(
            from_binary::<GetCustodianDepositAddressResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::GetCustodianDepositAddress {
                        merchant: merchant.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            GetCustodianDepositAddressResponse {
                address: "custodian_deposit_address".to_string()
            }
        );

        // transfer governorship
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(governor, &[]),
            ExecuteMsg::TransferGovernorship {
                new_governor_address: new_governor.to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            from_binary::<GetGovernorResponse>(
                &query(deps.as_ref(), mock_env(), QueryMsg::GetGovernor {}).unwrap()
            )
            .unwrap(),
            GetGovernorResponse {
                address: Addr::unchecked(governor)
            }
        );

        assert_eq!(
            from_binary::<IsGovernorResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsGovernor {
                        address: governor.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            IsGovernorResponse { is_governor: true }
        );

        assert_eq!(
            from_binary::<GetGovernorCandidateResponse>(
                &query(deps.as_ref(), mock_env(), QueryMsg::GetGovernorCandidate {}).unwrap()
            )
            .unwrap(),
            GetGovernorCandidateResponse {
                address: Some(Addr::unchecked(new_governor))
            }
        );

        // is governor candidate
        assert_eq!(
            from_binary::<IsGovernorCandidateResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsGovernorCandidate {
                        address: new_governor.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            IsGovernorCandidateResponse {
                is_governor_candidate: true
            }
        );

        // claim governorship
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(new_governor, &[]),
            ExecuteMsg::ClaimGovernorship {},
        )
        .unwrap();

        assert_eq!(
            from_binary::<GetGovernorResponse>(
                &query(deps.as_ref(), mock_env(), QueryMsg::GetGovernor {}).unwrap()
            )
            .unwrap(),
            GetGovernorResponse {
                address: Addr::unchecked(new_governor)
            }
        );

        assert_eq!(
            from_binary::<IsGovernorResponse>(
                &query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::IsGovernor {
                        address: new_governor.to_string()
                    }
                )
                .unwrap()
            )
            .unwrap(),
            IsGovernorResponse { is_governor: true }
        );

        assert_eq!(
            from_binary::<GetGovernorCandidateResponse>(
                &query(deps.as_ref(), mock_env(), QueryMsg::GetGovernorCandidate {}).unwrap()
            )
            .unwrap(),
            GetGovernorCandidateResponse { address: None }
        );
    }
}

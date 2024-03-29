/// `token` module provides the functionality to manage the token denom and it's metadata.
use cosmwasm_std::{
    attr, Attribute, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Storage,
};
use osmosis_std::types::{
    cosmos::bank::v1beta1::Metadata, osmosis::tokenfactory::v1beta1::MsgSetDenomMetadata,
};

use crate::{
    attrs::action_attrs,
    auth::{allow_only, Role},
    state::token::{IS_PAUSED, TOKEN_DENOM},
    ContractError,
};

/// Set the token denom.
/// This can only be set once in the instantiation of the contract.
pub fn set_token_denom(storage: &mut dyn Storage, token_denom: &String) -> StdResult<()> {
    TOKEN_DENOM.save(storage, token_denom)
}

/// Get the token denom.
pub fn get_token_denom(storage: &dyn Storage) -> StdResult<String> {
    TOKEN_DENOM.load(storage)
}

/// Set denom metadata.
/// Only the governor can set the denom metadata.
pub fn set_denom_metadata(
    deps: Deps,
    env: &Env,
    info: &MessageInfo,
    metadata: Metadata,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Governor], &info.sender, deps)?;

    let attrs = action_attrs(
        "set_denom_metadata",
        vec![
            attr("description", &metadata.description),
            attr("base", &metadata.base),
            attr("display", &metadata.display),
            attr("name", &metadata.name),
            attr("symbol", &metadata.symbol),
        ],
    );

    let msg_set_denom_metadata = MsgSetDenomMetadata {
        sender: env.contract.address.to_string(),
        metadata: Some(metadata),
    };
    Ok(Response::new()
        .add_attributes(attrs)
        .add_message(msg_set_denom_metadata))
}

/// Set the pause status.
pub fn pause(deps: DepsMut, info: &MessageInfo) -> Result<Response, ContractError> {
    allow_only(&[Role::Governor], &info.sender, deps.as_ref())?;

    IS_PAUSED.save(deps.storage, &true)?;

    let attrs = action_attrs("pause", vec![] as Vec<Attribute>);

    Ok(Response::new().add_attributes(attrs))
}

/// Unset the pause status.
pub fn unpause(deps: DepsMut, info: &MessageInfo) -> Result<Response, ContractError> {
    allow_only(&[Role::Governor], &info.sender, deps.as_ref())?;

    IS_PAUSED.save(deps.storage, &false)?;

    let attrs = action_attrs("unpause", vec![] as Vec<Attribute>);

    Ok(Response::new().add_attributes(attrs))
}

/// Check if the contract is paused.
pub fn is_paused(deps: Deps) -> StdResult<bool> {
    Ok(IS_PAUSED.may_load(deps.storage)?.unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        SubMsg,
    };
    use osmosis_std::types::cosmos::bank::v1beta1::Metadata;

    use crate::{
        auth::{custodian, governor, member_manager, merchant},
        ContractError,
    };

    #[test]
    fn test_only_governor_can_set_denom_metadata() {
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let mut deps = mock_dependencies();

        // setup
        governor::initialize_governor(deps.as_mut(), governor).unwrap();
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(member_manager, &[]), custodian)
            .unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant).unwrap();

        let metadata = Metadata {
            description: "description".to_string(),
            base: "base".to_string(),
            display: "display".to_string(),
            name: "name".to_string(),
            symbol: "symbol".to_string(),
            denom_units: vec![],
        };

        assert_eq!(
            set_denom_metadata(
                deps.as_ref(),
                &mock_env(),
                &mock_info(custodian, &[]),
                metadata.clone()
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            set_denom_metadata(
                deps.as_ref(),
                &mock_env(),
                &mock_info(merchant, &[]),
                metadata.clone()
            )
            .unwrap_err(),
            ContractError::Unauthorized {}
        );

        let msgs = set_denom_metadata(
            deps.as_ref(),
            &mock_env(),
            &mock_info(governor, &[]),
            metadata.clone(),
        )
        .unwrap()
        .messages;

        assert_eq!(
            msgs,
            vec![SubMsg::new(MsgSetDenomMetadata {
                sender: mock_env().contract.address.to_string(),
                metadata: Some(metadata)
            })]
        );
    }

    #[test]
    fn test_only_governor_can_pause_and_unpause() {
        let governor = "osmo1governor";
        let member_manager = "osmo1membermanager";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let mut deps = mock_dependencies();

        // setup
        governor::initialize_governor(deps.as_mut(), governor).unwrap();
        member_manager::set_member_manager(
            deps.as_mut(),
            &mock_info(governor, &[]),
            member_manager,
        )
        .unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(member_manager, &[]), custodian)
            .unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(member_manager, &[]), merchant).unwrap();

        // default status is not paused
        assert!(!is_paused(deps.as_ref()).unwrap());

        assert_eq!(
            pause(deps.as_mut(), &mock_info(custodian, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            pause(deps.as_mut(), &mock_info(merchant, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            pause(deps.as_mut(), &mock_info(governor, &[])).unwrap(),
            Response::new().add_attributes(vec![attr("action", "pause")])
        );

        // status is paused
        assert!(is_paused(deps.as_ref()).unwrap());

        assert_eq!(
            unpause(deps.as_mut(), &mock_info(custodian, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            unpause(deps.as_mut(), &mock_info(merchant, &[])).unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            unpause(deps.as_mut(), &mock_info(governor, &[])).unwrap(),
            Response::new().add_attributes(vec![attr("action", "unpause")])
        );

        // status is not paused
        assert!(!is_paused(deps.as_ref()).unwrap());
    }
}

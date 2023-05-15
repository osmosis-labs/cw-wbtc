use cosmwasm_std::{attr, Deps, MessageInfo, Response, StdResult, Storage};
use cw_storage_plus::Item;
use osmosis_std::types::{
    cosmos::bank::v1beta1::Metadata, osmosis::tokenfactory::v1beta1::MsgSetDenomMetadata,
};

use crate::{
    auth::{allow_only, Role},
    helpers::method_attrs,
    ContractError,
};

const TOKEN_DENOM: Item<String> = Item::new("token_denom");

pub fn set_token_denom(storage: &mut dyn Storage, token_denom: &String) -> StdResult<()> {
    TOKEN_DENOM.save(storage, token_denom)
}

pub fn get_token_denom(storage: &dyn Storage) -> StdResult<String> {
    TOKEN_DENOM.load(storage)
}

pub fn set_denom_metadata(
    deps: Deps,
    info: &MessageInfo,
    metadata: Metadata,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Owner], &info.sender, deps)?;

    let attrs = method_attrs(
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
        sender: info.sender.to_string(),
        metadata: Some(metadata),
    };
    Ok(Response::new()
        .add_attributes(attrs)
        .add_message(msg_set_denom_metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_info},
        SubMsg,
    };
    use osmosis_std::types::cosmos::bank::v1beta1::Metadata;

    use crate::{
        auth::{custodian, merchant, owner},
        ContractError,
    };

    #[test]
    fn test_only_owner_can_set_denom_metadata() {
        let owner = "osmo1owner";
        let custodian = "osmo1custodian";
        let merchant = "osmo1merchant";
        let mut deps = mock_dependencies();

        // setup
        owner::initialize_owner(deps.as_mut(), owner).unwrap();
        custodian::set_custodian(deps.as_mut(), &mock_info(owner, &[]), custodian).unwrap();
        merchant::add_merchant(deps.as_mut(), &mock_info(owner, &[]), merchant).unwrap();

        let metadata = Metadata {
            description: "description".to_string(),
            base: "base".to_string(),
            display: "display".to_string(),
            name: "name".to_string(),
            symbol: "symbol".to_string(),
            denom_units: vec![],
        };

        assert_eq!(
            set_denom_metadata(deps.as_ref(), &mock_info(custodian, &[]), metadata.clone())
                .unwrap_err(),
            ContractError::Unauthorized {}
        );

        assert_eq!(
            set_denom_metadata(deps.as_ref(), &mock_info(merchant, &[]), metadata.clone())
                .unwrap_err(),
            ContractError::Unauthorized {}
        );

        let msgs = set_denom_metadata(deps.as_ref(), &mock_info(owner, &[]), metadata.clone())
            .unwrap()
            .messages;

        assert_eq!(
            msgs,
            vec![SubMsg::new(MsgSetDenomMetadata {
                sender: owner.to_string(),
                metadata: Some(metadata)
            })]
        );
    }
}

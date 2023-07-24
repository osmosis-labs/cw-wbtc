/// `governor` module provides governor management functionality.
use cosmwasm_std::{attr, Addr, Deps, DepsMut, MessageInfo, Response, StdError};

use crate::{attrs::action_attrs, state::auth::GOVERNOR, ContractError};

use super::{allow_only, Role};

/// Initialize the governor, can only be called once at contract instantiation
pub fn initialize_governor(deps: DepsMut, address: &str) -> Result<(), ContractError> {
    GOVERNOR
        .save(deps.storage, &deps.api.addr_validate(address)?)
        .map_err(Into::into)
}

/// Transfer the governorship to another address, only the governor can call this
pub fn transfer_governorship(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Governor], &info.sender, deps.as_ref())?;

    GOVERNOR.save(deps.storage, &deps.api.addr_validate(address)?)?;

    let attrs = action_attrs("transfer_governorship", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Check if the given address is the governor
pub fn is_governor(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    match GOVERNOR.may_load(deps.storage)? {
        Some(governor) => Ok(address == governor),
        None => Ok(false),
    }
}

/// Get the governor address
pub fn get_governor(deps: Deps) -> Result<Addr, StdError> {
    GOVERNOR
        .may_load(deps.storage)?
        .ok_or(StdError::not_found("Governor"))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    use super::*;

    #[test]
    fn test_manage_governor() {
        let mut deps = mock_dependencies();
        let governor_address = "osmo1governor";
        let non_governor_address = "osmo1nongovernor";
        let new_governor_address = "osmo1newgovernor";

        // check before set will fail

        assert!(!is_governor(deps.as_ref(), &Addr::unchecked(governor_address)).unwrap(),);

        let err = get_governor(deps.as_ref()).unwrap_err();
        assert_eq!(err, StdError::not_found("Governor"));

        // initialize governor
        initialize_governor(deps.as_mut(), governor_address).unwrap();

        // check after set will pass
        assert_eq!(get_governor(deps.as_ref()).unwrap(), governor_address);
        assert!(is_governor(deps.as_ref(), &Addr::unchecked(governor_address)).unwrap(),);
        assert!(!is_governor(deps.as_ref(), &Addr::unchecked(non_governor_address)).unwrap(),);

        // transfer governor right should fail if not called by governor
        let err = transfer_governorship(
            deps.as_mut(),
            &mock_info(new_governor_address, &[]),
            non_governor_address,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        assert_eq!(get_governor(deps.as_ref()).unwrap(), governor_address);
        assert!(is_governor(deps.as_ref(), &Addr::unchecked(governor_address)).unwrap(),);
        assert!(!is_governor(deps.as_ref(), &Addr::unchecked(non_governor_address)).unwrap(),);

        // transfer governor right should pass if called by governor
        assert_eq!(
            transfer_governorship(
                deps.as_mut(),
                &mock_info(governor_address, &[]),
                new_governor_address,
            )
            .unwrap()
            .attributes,
            vec![
                attr("action", "transfer_governorship"),
                attr("address", new_governor_address)
            ]
        );

        assert_eq!(get_governor(deps.as_ref()).unwrap(), new_governor_address);
        assert!(!is_governor(deps.as_ref(), &Addr::unchecked(governor_address)).unwrap(),);
        assert!(!is_governor(deps.as_ref(), &Addr::unchecked(non_governor_address)).unwrap(),);
        assert!(is_governor(deps.as_ref(), &Addr::unchecked(new_governor_address)).unwrap(),);
    }
}

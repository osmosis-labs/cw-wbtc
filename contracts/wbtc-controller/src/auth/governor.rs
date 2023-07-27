use cosmwasm_schema::cw_serde;
/// `governor` module provides governor management functionality.
use cosmwasm_std::{attr, ensure, Addr, Deps, DepsMut, MessageInfo, Response, StdError};

use crate::{attrs::action_attrs, state::auth::GOVERNOR, ContractError};

use super::{allow_only, has_no_priviledged_role, Role};

#[cw_serde]
pub enum GovernorState {
    Claimed(Addr),
    Transferring { current: Addr, candidate: Addr },
}

impl GovernorState {
    fn claimed(address: Addr) -> Self {
        Self::Claimed(address)
    }

    fn transferring(current: Addr, target: Addr) -> Self {
        Self::Transferring {
            current,
            candidate: target,
        }
    }

    fn current(self) -> Addr {
        match self {
            Self::Claimed(address) => address,
            Self::Transferring { current, .. } => current,
        }
    }

    fn candidate(self) -> Option<Addr> {
        match self {
            Self::Claimed(_) => None,
            Self::Transferring { candidate, .. } => Some(candidate),
        }
    }
}

/// Initialize the governor, can only be called once at contract instantiation
pub fn initialize_governor(deps: DepsMut, address: &str) -> Result<(), ContractError> {
    let address = deps.api.addr_validate(address)?;
    has_no_priviledged_role(deps.as_ref(), &address)?;
    GOVERNOR
        .save(deps.storage, &GovernorState::claimed(address))
        .map_err(Into::into)
}

/// Transfer the governorship to another address, only the governor can call this
pub fn transfer_governorship(
    deps: DepsMut,
    info: &MessageInfo,
    address: &str,
) -> Result<Response, ContractError> {
    allow_only(&[Role::Governor], &info.sender, deps.as_ref())?;

    let validated_address = deps.api.addr_validate(address)?;
    has_no_priviledged_role(deps.as_ref(), &validated_address)?;

    let current = get_governor(deps.as_ref())?;
    GOVERNOR.save(
        deps.storage,
        &GovernorState::transferring(current, validated_address),
    )?;

    let attrs = action_attrs("transfer_governorship", vec![attr("address", address)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Claim the governorship, only the target governor can call this
pub fn claim_governorship(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
    let governor = GOVERNOR.load(deps.storage)?;
    let candidate = governor.candidate().ok_or(ContractError::Unauthorized {})?;

    ensure!(info.sender != candidate, ContractError::Unauthorized {});
    has_no_priviledged_role(deps.as_ref(), &candidate)?;

    GOVERNOR.save(deps.storage, &GovernorState::claimed(info.sender))?;

    let attrs = action_attrs("claim_governorship", vec![attr("address", candidate)]);
    Ok(Response::new().add_attributes(attrs))
}

/// Check if the given address is the governor
pub fn is_governor(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    Ok(GOVERNOR
        .may_load(deps.storage)?
        .map(|governor| governor.current() == *address)
        .unwrap_or(false))
}

/// Check if the given address is the governor candidate
pub fn is_governor_candidate(deps: Deps, address: &Addr) -> Result<bool, StdError> {
    let candidate = GOVERNOR
        .may_load(deps.storage)?
        .and_then(|governor| governor.candidate());

    Ok(candidate.as_ref() == Some(address))
}

/// Get the governor address
pub fn get_governor(deps: Deps) -> Result<Addr, StdError> {
    GOVERNOR
        .may_load(deps.storage)?
        .map(|governor| governor.current())
        .ok_or(StdError::not_found("Governor"))
}

// Get the governor candidate address
pub fn get_governor_candidate(deps: Deps) -> Result<Option<Addr>, StdError> {
    Ok(GOVERNOR
        .may_load(deps.storage)?
        .and_then(|governor| governor.candidate()))
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

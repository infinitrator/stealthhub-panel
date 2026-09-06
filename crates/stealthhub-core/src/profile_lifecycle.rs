//! Generic pre-publication validation for protocol profile desired state.
//!
//! Protocol-specific semantics remain in adapters. This module validates only
//! shared identity, secret-reference, runtime-capability, and listener rules.

use std::collections::BTreeSet;

use anyhow::{bail, Result};

use crate::{
    adapter::{CoreRegistry, ProtocolRegistry},
    models::ProtocolProfile,
};

/// Validates a candidate before it is written to desired-state storage.
pub fn validate_profile_candidate(
    candidate: &ProtocolProfile,
    existing: &[ProtocolProfile],
    protocols: &ProtocolRegistry,
    cores: &CoreRegistry,
    secret_names: &BTreeSet<String>,
) -> Result<()> {
    let display_name = candidate.display_name.trim();
    if display_name.is_empty()
        || display_name.len() > 96
        || display_name.chars().any(char::is_control)
    {
        bail!("display name is invalid or too long");
    }
    let adapter = protocols
        .get(&candidate.protocol_id)
        .ok_or_else(|| anyhow::anyhow!("protocol adapter is not installed"))?;
    adapter.validate_config(candidate.schema_version, &candidate.config)?;
    for reference in adapter.secret_references(&candidate.config)? {
        if !secret_names.contains(reference.as_str()) {
            bail!(
                "required secret reference `{}` is missing",
                reference.as_str()
            );
        }
    }

    let required = &adapter.manifest().required_core_capabilities;
    if let Some(preferred) = candidate.preferred_core_id.as_deref() {
        let runtime = cores
            .get(preferred)
            .ok_or_else(|| anyhow::anyhow!("preferred runtime adapter is missing"))?;
        if !required.is_subset(&runtime.manifest().capabilities) {
            bail!("preferred runtime does not provide the required capability");
        }
    } else if !cores
        .manifests()
        .iter()
        .any(|runtime| required.is_subset(&runtime.capabilities))
    {
        bail!("no runtime adapter provides the required capability");
    }
    if candidate.enabled {
        let network = adapter.manifest().listener_network;
        for profile in existing
            .iter()
            .filter(|profile| profile.enabled && profile.name != candidate.name)
        {
            let Some(other) = protocols.get(&profile.protocol_id) else {
                continue;
            };
            if profile.port == candidate.port && other.manifest().listener_network == network {
                bail!(
                    "listener conflict with profile `{}` on {:?}/{}",
                    profile.name,
                    network,
                    candidate.port
                );
            }
        }
        if cores
            .select(required, candidate.preferred_core_id.as_deref())?
            .is_none()
        {
            bail!("no compatible installed runtime is available");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{adapters::protocol_registry, models::ProxyRole};
    use serde_json::json;

    #[test]
    fn missing_adapter_preserves_state_but_blocks_schema_dependent_validation() {
        let candidate = ProtocolProfile {
            name: "future-profile".into(),
            display_name: "Future profile".into(),
            protocol_id: "future-adapter".into(),
            schema_version: 7,
            role: ProxyRole::Manual,
            server: "node.example.test".into(),
            port: 443,
            enabled: false,
            preferred_core_id: None,
            managed_resource_id: None,
            config: json!({"opaque":"preserved"}),
        };
        let error = validate_profile_candidate(
            &candidate,
            &[],
            &protocol_registry().unwrap(),
            &CoreRegistry::default(),
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not installed"));
        assert_eq!(candidate.config["opaque"], "preserved");
    }

    #[test]
    fn known_profiles_reject_missing_secrets_runtime_and_listener_conflicts() {
        let protocols = protocol_registry().unwrap();
        let cores = crate::adapters::core_registry().unwrap();
        let mut candidate = crate::adapters::default_profiles()
            .into_iter()
            .find(|profile| profile.protocol_id == "vless-reality-xhttp")
            .unwrap();
        candidate.name = "candidate".into();
        candidate.display_name = "Candidate".into();
        let adapter = protocols.get(&candidate.protocol_id).unwrap();
        let secrets = adapter
            .secret_references(&candidate.config)
            .unwrap()
            .into_iter()
            .map(|reference| reference.as_str().to_string())
            .collect();
        validate_profile_candidate(&candidate, &[], &protocols, &cores, &secrets).unwrap();

        let mut invalid = candidate.clone();
        invalid.config.as_object_mut().unwrap().remove("path");
        let field_error =
            validate_profile_candidate(&invalid, &[], &protocols, &cores, &secrets).unwrap_err();
        assert!(field_error.to_string().contains("path"));

        let missing =
            validate_profile_candidate(&candidate, &[], &protocols, &cores, &BTreeSet::new())
                .unwrap_err();
        assert!(missing.to_string().contains("secret reference"));

        candidate.enabled = true;
        let mut occupied = candidate.clone();
        occupied.name = "occupied".into();
        let conflict =
            validate_profile_candidate(&candidate, &[occupied], &protocols, &cores, &secrets)
                .unwrap_err();
        assert!(conflict.to_string().contains("listener conflict"));

        candidate.enabled = false;
        candidate.preferred_core_id = Some("missing-runtime".into());
        let runtime =
            validate_profile_candidate(&candidate, &[], &protocols, &cores, &secrets).unwrap_err();
        assert!(runtime.to_string().contains("runtime adapter is missing"));
    }
}

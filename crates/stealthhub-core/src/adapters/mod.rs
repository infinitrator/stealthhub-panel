//! Built-in adapter packages.
//!
//! Concrete protocol names are intentionally confined to this subtree. Generic
//! storage, reconciliation and subscription code consume only registry traits.

mod cores;
mod infrastructure;
mod protocols;
mod tls;

use anyhow::Result;

use crate::adapter::{CoreRegistry, ProtocolRegistry};

pub use infrastructure::desired_resources;
pub use protocols::{default_profiles, legacy_runtime_preference};
pub use tls::{
    privileged_tls_material_readiness, profile_requires_tls, profile_tls_hostname,
    publish_privileged_tls_readiness, tls_material_readiness, TlsMaterialReadiness,
};

/// Builds the trusted protocol registry shipped with this binary.
pub fn protocol_registry() -> Result<ProtocolRegistry> {
    protocols::registry()
}

/// Builds the trusted runtime and infrastructure adapters shipped with this release.
pub fn core_registry() -> Result<CoreRegistry> {
    registry(tls::TlsReadinessMode::Static)
}

/// Builds the trusted runtime registry with authoritative effective-access checks.
///
/// This registry is only for the root reconciliation worker. Interactive and
/// observational processes must use [`core_registry`].
pub fn privileged_core_registry() -> Result<CoreRegistry> {
    registry(tls::TlsReadinessMode::Privileged)
}

fn registry(tls_readiness_mode: tls::TlsReadinessMode) -> Result<CoreRegistry> {
    let mut registry = cores::registry(tls_readiness_mode)?;
    registry.register(std::sync::Arc::new(
        infrastructure::SubscriptionFrontendAdapter::new(),
    ))?;
    registry.register(std::sync::Arc::new(
        infrastructure::NodeReadinessAdapter::new(),
    ))?;
    Ok(registry)
}

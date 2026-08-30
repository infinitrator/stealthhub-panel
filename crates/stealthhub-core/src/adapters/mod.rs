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
    profile_requires_tls, profile_tls_hostname, tls_material_readiness, TlsMaterialReadiness,
};

/// Builds the trusted protocol registry shipped with this binary.
pub fn protocol_registry() -> Result<ProtocolRegistry> {
    protocols::registry()
}

/// Builds the trusted runtime and infrastructure adapters shipped with this release.
pub fn core_registry() -> Result<CoreRegistry> {
    let mut registry = cores::registry()?;
    registry.register(std::sync::Arc::new(
        infrastructure::SubscriptionFrontendAdapter::new(),
    ))?;
    registry.register(std::sync::Arc::new(
        infrastructure::NodeReadinessAdapter::new(),
    ))?;
    Ok(registry)
}

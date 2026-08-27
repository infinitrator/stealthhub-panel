//! Shared Infiproxy domain logic.
//!
//! This crate contains storage, protocol models, routing rules and Mihomo YAML
//! generation. It has no web/UI responsibilities, which keeps the panel and CLI
//! thin wrappers around the same tested core.

pub mod adapter;
pub mod adapters;
pub mod compatibility;
pub mod desired;
pub mod inventory;
pub mod mihomo;
pub mod models;
pub mod module_manifest;
pub mod reconcile;
pub mod rules;
pub mod storage;

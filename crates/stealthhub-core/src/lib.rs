//! Shared Infiproxy domain logic.
//!
//! This crate contains storage, protocol models, routing rules and Mihomo YAML
//! generation. It has no web/UI responsibilities, which keeps the panel and CLI
//! thin wrappers around the same tested core.

pub mod mihomo;
pub mod models;
pub mod rules;
pub mod storage;

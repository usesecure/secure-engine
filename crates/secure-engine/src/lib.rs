//! Deterministic, local-first repository inventory shared by every Secure Engine interface.

mod classify;
mod model;
mod scan;
mod workspace;

pub use model::*;
pub use scan::{CancellationToken, ScanError, scan_repository};

/// Public schema identifier implemented by this engine release.
pub const SCHEMA_VERSION: &str = "secure-json-v1";

/// Engine version embedded in every machine-readable document.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical, committed JSON Schema for the public process contract.
pub const SECURE_JSON_V1_SCHEMA: &str = include_str!("../../../schemas/secure-json-v1.schema.json");

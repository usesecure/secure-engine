//! Deterministic local-first inventory, syntax facts, evidence graph, and rules shared by every interface.

mod cache;
mod classify;
mod graph;
mod model;
mod parser;
mod scan;
mod workspace;

pub use graph::rules;
pub use model::*;
pub use scan::{CancellationToken, ScanError, scan_repository};

/// Finds one deterministic finding in a completed shared-engine report.
#[must_use]
pub fn explain_finding<'a>(report: &'a ScanReport, finding_id: &str) -> Option<&'a Finding> {
    graph::explain(report, finding_id)
}

/// Public schema identifier implemented by this engine release.
pub const SCHEMA_VERSION: &str = "secure-json-v1";

/// Engine version embedded in every machine-readable document.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical, committed JSON Schema for the public process contract.
pub const SECURE_JSON_V1_SCHEMA: &str = include_str!("../../../schemas/secure-json-v1.schema.json");

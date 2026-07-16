use serde::{Deserialize, Serialize};

use crate::{CweReference, RuleTaxonomyProvenance, TaxonomyCoordinates, TaxonomyDescriptor};

/// Frozen neutral taxonomy schema identifier used as the stable taxonomy name.
pub const TAXONOMY_NAME: &str = "secure-bench-taxonomy-v1";
/// Frozen neutral taxonomy semantic version.
pub const TAXONOMY_VERSION: &str = "1.0.0";
/// Public CWE source release recorded by the frozen contract.
pub const TAXONOMY_SOURCE_VERSION: &str = "CWE 4.20";
/// Signed upstream commit that froze the neutral taxonomy contract.
pub const TAXONOMY_SOURCE_COMMIT: &str = "93c0821db065de436a339c15b070e158947ad76c";
/// SHA-256 of the public taxonomy schema artifact.
pub const TAXONOMY_SCHEMA_SHA256: &str =
    "cdecd643d338aa8ae42ec7398c6c4703cb97d60ad355340c98744fc94bcb7d6f";
/// SHA-256 of the frozen public taxonomy artifact.
pub const TAXONOMY_DOCUMENT_SHA256: &str =
    "059fe22d7707cf8d17f2c1621fdae9819787a1958ba2ef0421eca4e4ec858452";
/// SHA-256 of the public neutral-taxonomy methodology.
pub const TAXONOMY_METHODOLOGY_SHA256: &str =
    "eac27e5800be35c5ae77f7804e52ae90462cbda403a5484baa8fab62f02ab562";
/// Canonical internal content hash declared by the frozen taxonomy document.
pub const TAXONOMY_CONTENT_HASH: &str =
    "22852bd7401020b315af11dfa2b60c0b46f78eb19f95079e6400d7b3bea3272c";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuleTaxonomyDefinition {
    pub(crate) rule_id: &'static str,
    pub(crate) category_id: &'static str,
    pub(crate) invariant_id: &'static str,
    pub(crate) cwe_id: &'static str,
    pub(crate) cwe_url: &'static str,
}

pub(crate) const RULE_TAXONOMY: [RuleTaxonomyDefinition; 7] = [
    RuleTaxonomyDefinition {
        rule_id: "SE1001",
        category_id: "secure-bench.category.command-execution",
        invariant_id: "secure-bench.invariant.command-control-data-separation",
        cwe_id: "CWE-78",
        cwe_url: "https://cwe.mitre.org/data/definitions/78.html",
    },
    RuleTaxonomyDefinition {
        rule_id: "SE1002",
        category_id: "secure-bench.category.sql-construction",
        invariant_id: "secure-bench.invariant.sql-control-data-separation",
        cwe_id: "CWE-89",
        cwe_url: "https://cwe.mitre.org/data/definitions/89.html",
    },
    RuleTaxonomyDefinition {
        rule_id: "SE1003",
        category_id: "secure-bench.category.filesystem-boundary",
        invariant_id: "secure-bench.invariant.filesystem-path-confinement",
        cwe_id: "CWE-22",
        cwe_url: "https://cwe.mitre.org/data/definitions/22.html",
    },
    RuleTaxonomyDefinition {
        rule_id: "SE1004",
        category_id: "secure-bench.category.outbound-request-boundary",
        invariant_id: "secure-bench.invariant.outbound-destination-policy",
        cwe_id: "CWE-918",
        cwe_url: "https://cwe.mitre.org/data/definitions/918.html",
    },
    RuleTaxonomyDefinition {
        rule_id: "SE1005",
        category_id: "secure-bench.category.redirect-boundary",
        invariant_id: "secure-bench.invariant.redirect-destination-policy",
        cwe_id: "CWE-601",
        cwe_url: "https://cwe.mitre.org/data/definitions/601.html",
    },
    RuleTaxonomyDefinition {
        rule_id: "SE1006",
        category_id: "secure-bench.category.dynamic-code-execution",
        invariant_id: "secure-bench.invariant.dynamic-code-control-data-separation",
        cwe_id: "CWE-95",
        cwe_url: "https://cwe.mitre.org/data/definitions/95.html",
    },
    RuleTaxonomyDefinition {
        rule_id: "SE1007",
        category_id: "secure-bench.category.authorization-dominance",
        invariant_id: "secure-bench.invariant.authorization-before-sensitive-operation",
        cwe_id: "CWE-862",
        cwe_url: "https://cwe.mitre.org/data/definitions/862.html",
    },
];

pub(crate) fn mapping(rule_id: &str) -> Option<RuleTaxonomyDefinition> {
    RULE_TAXONOMY
        .iter()
        .copied()
        .find(|mapping| mapping.rule_id == rule_id)
}

pub(crate) fn coordinates(rule_id: &str) -> Option<TaxonomyCoordinates> {
    let mapping = mapping(rule_id)?;
    Some(TaxonomyCoordinates {
        taxonomy_version: TAXONOMY_VERSION.into(),
        category_id: mapping.category_id.into(),
        invariant_id: mapping.invariant_id.into(),
    })
}

pub(crate) fn primary_cwe(rule_id: &str) -> Option<CweReference> {
    let mapping = mapping(rule_id)?;
    Some(CweReference {
        id: mapping.cwe_id.into(),
        url: mapping.cwe_url.into(),
    })
}

pub(crate) fn provenance(rule_id: &str) -> Option<RuleTaxonomyProvenance> {
    mapping(rule_id)?;
    Some(RuleTaxonomyProvenance {
        taxonomy_name: TAXONOMY_NAME.into(),
        source_commit: TAXONOMY_SOURCE_COMMIT.into(),
        content_hash: TAXONOMY_CONTENT_HASH.into(),
        mapping_basis: "secure-engine-built-in-rule-family".into(),
    })
}

pub(crate) fn catalog_is_valid(catalog: &[TaxonomyDescriptor]) -> bool {
    catalog.is_empty() || catalog == [taxonomy_descriptor()]
}

pub(crate) fn metadata_matches_catalog(
    catalog: &[TaxonomyDescriptor],
    rule_id: &str,
    coordinates_value: Option<&TaxonomyCoordinates>,
    cwe_value: Option<&CweReference>,
    provenance_value: Option<&RuleTaxonomyProvenance>,
) -> bool {
    if catalog.is_empty() {
        return coordinates_value.is_none() && cwe_value.is_none() && provenance_value.is_none();
    }
    if !catalog_is_valid(catalog) {
        return false;
    }
    match (coordinates_value, cwe_value, provenance_value) {
        (Some(actual_coordinates), Some(actual_cwe), Some(actual_provenance)) => {
            coordinates(rule_id).as_ref() == Some(actual_coordinates)
                && primary_cwe(rule_id).as_ref() == Some(actual_cwe)
                && provenance(rule_id).as_ref() == Some(actual_provenance)
        }
        (None, None, None) => mapping(rule_id).is_none(),
        _ => false,
    }
}

/// Returns the frozen taxonomy descriptor embedded in new deterministic reports.
#[must_use]
pub fn taxonomy_descriptor() -> TaxonomyDescriptor {
    TaxonomyDescriptor {
        taxonomy_name: TAXONOMY_NAME.into(),
        taxonomy_version: TAXONOMY_VERSION.into(),
        source_version: TAXONOMY_SOURCE_VERSION.into(),
        source_commit: TAXONOMY_SOURCE_COMMIT.into(),
        schema_sha256: TAXONOMY_SCHEMA_SHA256.into(),
        taxonomy_sha256: TAXONOMY_DOCUMENT_SHA256.into(),
        methodology_sha256: TAXONOMY_METHODOLOGY_SHA256.into(),
        content_hash: TAXONOMY_CONTENT_HASH.into(),
    }
}

/// One stable rule-to-neutral-taxonomy mapping for programmatic inspection.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TaxonomyMapping {
    /// Existing Secure Engine rule identifier.
    pub rule_id: String,
    /// Exact frozen matching coordinates.
    pub taxonomy: TaxonomyCoordinates,
    /// Primary public CWE association from the frozen contract.
    pub primary_cwe: CweReference,
    /// Auditable rule-to-contract provenance.
    pub taxonomy_provenance: RuleTaxonomyProvenance,
}

/// Returns all seven frozen mappings ordered by Secure Engine rule identifier.
#[must_use]
pub fn taxonomy_mappings() -> Vec<TaxonomyMapping> {
    RULE_TAXONOMY
        .iter()
        .map(|mapping| TaxonomyMapping {
            rule_id: mapping.rule_id.into(),
            taxonomy: TaxonomyCoordinates {
                taxonomy_version: TAXONOMY_VERSION.into(),
                category_id: mapping.category_id.into(),
                invariant_id: mapping.invariant_id.into(),
            },
            primary_cwe: CweReference {
                id: mapping.cwe_id.into(),
                url: mapping.cwe_url.into(),
            },
            taxonomy_provenance: RuleTaxonomyProvenance {
                taxonomy_name: TAXONOMY_NAME.into(),
                source_commit: TAXONOMY_SOURCE_COMMIT.into(),
                content_hash: TAXONOMY_CONTENT_HASH.into(),
                mapping_basis: "secure-engine-built-in-rule-family".into(),
            },
        })
        .collect()
}

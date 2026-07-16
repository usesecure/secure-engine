use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Request passed to the shared scanning API.
#[derive(Clone, Debug)]
pub struct ScanRequest {
    /// Repository directory. This host path is never copied into a report.
    pub repository: PathBuf,
    /// Deterministic scan settings recorded in the report.
    pub configuration: ScanConfiguration,
    /// Runtime-only cache location and one-shot maintenance controls.
    pub cache: CacheControl,
}

impl ScanRequest {
    /// Creates a request with safe Phase 2 inventory, parsing, and cache defaults.
    #[must_use]
    pub fn new(repository: impl Into<PathBuf>) -> Self {
        Self {
            repository: repository.into(),
            configuration: ScanConfiguration::default(),
            cache: CacheControl::default(),
        }
    }
}

/// Runtime-only parse-cache controls. Cache paths are never serialized into reports.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CacheControl {
    /// Optional local cache base directory. The repository-specific directory is derived safely.
    pub directory: Option<PathBuf>,
    /// Atomically retire the selected repository cache before scanning.
    pub clear_before_scan: bool,
}

/// Resource limits and traversal settings that affect inventory output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScanConfiguration {
    /// Whether hidden files excluded by the traversal library are included.
    pub include_hidden: bool,
    /// Maximum number of regular files inspected.
    pub max_files: usize,
    /// Maximum bytes read from any one file.
    pub max_file_bytes: u64,
    /// Whether Git and repository ignore files are honored.
    pub respect_ignore_files: bool,
    /// Repository-relative glob patterns; at least one must match when non-empty.
    pub include_patterns: Vec<String>,
    /// Repository-relative glob patterns that always exclude matching inputs.
    pub exclude_patterns: Vec<String>,
    /// Whether common generated/build directories are traversed.
    pub include_generated: bool,
    /// Whether common vendored dependency directories are traversed.
    pub include_vendor: bool,
    /// Whether nested Git repositories, worktrees, and submodules are traversed.
    pub include_nested_repositories: bool,
    /// Maximum total bytes read across all files.
    pub max_total_bytes: u64,
    /// Optional traversal depth, where the selected repository is depth zero.
    pub max_depth: Option<usize>,
    /// Maximum non-fatal errors retained in the report.
    pub max_errors: usize,
    /// Whether supported JavaScript and TypeScript parse results may use the local cache.
    pub parse_cache_enabled: bool,
    /// Maximum bytes retained in the repository-specific parse cache.
    pub max_cache_bytes: u64,
    /// Maximum parser diagnostics retained across the report.
    pub max_parser_diagnostics: usize,
    /// Maximum normalized facts retained per parsed file.
    pub max_facts_per_file: usize,
    /// Maximum normalized facts retained across the report.
    pub max_total_facts: usize,
}

impl Default for ScanConfiguration {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_files: 100_000,
            max_file_bytes: 4 * 1024 * 1024,
            respect_ignore_files: true,
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            include_generated: false,
            include_vendor: false,
            include_nested_repositories: false,
            max_total_bytes: 512 * 1024 * 1024,
            max_depth: None,
            max_errors: 100,
            parse_cache_enabled: true,
            max_cache_bytes: 256 * 1024 * 1024,
            max_parser_diagnostics: 1_000,
            max_facts_per_file: 10_000,
            max_total_facts: 100_000,
        }
    }
}

/// Top-level versioned repository inventory report.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScanReport {
    /// Contract version; always `secure-json-v1` for this model.
    pub schema_version: String,
    /// Semantic version of the producing engine.
    pub engine_version: String,
    /// Distinguishes this document from doctor output.
    pub document_type: String,
    /// Repository identity with no host-absolute path.
    pub repository: RepositoryIdentity,
    /// Effective configuration.
    pub configuration: ScanConfiguration,
    /// Completion and documented volatile timing data.
    pub scan: ScanMetadata,
    /// Aggregate inventory and resource-limit results added in Phase 1.
    #[serde(default)]
    pub inventory: InventorySummary,
    /// Aggregate Phase 2 parsing and cache measurements.
    #[serde(default)]
    pub parsing: ParsingSummary,
    /// Deterministic normalized syntax facts. These are evidence, not findings.
    #[serde(default)]
    pub facts: Vec<NormalizedFact>,
    /// Bounded recoverable parser diagnostics.
    #[serde(default)]
    pub parser_diagnostics: Vec<ParserDiagnostic>,
    /// Per-parser-mode coverage for supported inputs.
    #[serde(default)]
    pub parser_coverage: Vec<ParserCoverage>,
    /// Regular files that were successfully inventoried.
    pub files: Vec<FileRecord>,
    /// Aggregated detected languages.
    pub languages: Vec<LanguageSummary>,
    /// Detected package/build manifests.
    pub manifests: Vec<ManifestEvidence>,
    /// Framework hints found in manifests.
    pub frameworks: Vec<FrameworkEvidence>,
    /// Conventional executable/application entry points.
    pub entry_points: Vec<EntryPointEvidence>,
    /// Security-relevant repository capabilities, without vulnerability claims.
    pub capabilities: Vec<CapabilityEvidence>,
    /// Trust-boundary evidence suitable for later agent review.
    pub trust_boundaries: Vec<TrustBoundaryEvidence>,
    /// Normalized deterministic findings. Empty during Phase 2 syntax analysis.
    pub findings: Vec<Finding>,
    /// Known limitations of this analysis.
    pub limitations: Vec<Limitation>,
    /// Inputs skipped due to a stable resource or representation reason.
    pub skipped_files: Vec<SkippedFile>,
    /// Aggregate excluded-input reasons that do not reveal excluded paths.
    #[serde(default)]
    pub exclusions: Vec<ExclusionSummary>,
    /// Bounded, non-fatal, path-sanitized scan errors.
    pub errors: Vec<BoundedError>,
    /// Stable digest of the report after volatile scan metadata is excluded.
    pub report_fingerprint: String,
}

/// Repository identity safe to export outside the scanner process.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryIdentity {
    /// Final directory name, not its host path.
    pub name: String,
    /// Detected version-control system.
    pub vcs: Option<String>,
    /// Git object identifier when readable locally.
    pub revision: Option<String>,
    /// `directory`, `git-repository`, or `git-worktree`.
    #[serde(default = "default_repository_kind")]
    pub repository_kind: String,
    /// Stable digest over relative paths and file bytes.
    pub content_fingerprint: String,
    /// Stable digest over the safe identity fields.
    pub identity_fingerprint: String,
}

fn default_repository_kind() -> String {
    "directory".into()
}

/// Scan lifecycle metadata. Timing fields are documented as volatile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanMetadata {
    /// RFC 3339 UTC start time; volatile.
    pub started_at: String,
    /// RFC 3339 UTC finish time; volatile.
    pub finished_at: String,
    /// Wall-clock duration in milliseconds; volatile.
    pub duration_ms: u64,
    /// True only when all report construction completed.
    pub complete: bool,
    /// Number of discovered regular files considered under the limit.
    pub files_discovered: usize,
    /// Number of files successfully inventoried.
    pub files_scanned: usize,
}

/// Aggregate repository inventory counters and limit outcomes.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventorySummary {
    /// Entries yielded by safe traversal after ignore and directory pruning.
    pub entries_seen: usize,
    /// Regular files matching include/exclude selection before the file limit.
    pub candidate_files: usize,
    /// Candidate files retained under the deterministic file limit.
    pub files_selected: usize,
    /// Files successfully read and classified.
    pub files_scanned: usize,
    /// Successfully scanned non-binary files.
    pub text_files: usize,
    /// Successfully scanned binary files.
    pub binary_files: usize,
    /// Included files under recognized generated/build directories.
    pub generated_files: usize,
    /// Included files under recognized vendored dependency directories.
    pub vendor_files: usize,
    /// Total file bytes read and fingerprinted.
    pub bytes_scanned: u64,
    /// Symbolic links observed and not followed.
    pub symlinks_skipped: usize,
    /// Nested repositories or submodules pruned by the safe default.
    pub nested_repositories_skipped: usize,
    /// Whether candidates exceeded `max_files`.
    pub hit_file_limit: bool,
    /// Whether reading stopped at `max_total_bytes`.
    pub hit_total_byte_limit: bool,
}

/// Aggregate Phase 2 parsing and local-cache results.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParsingSummary {
    /// Non-binary JavaScript, JSX, TypeScript, and TSX files selected for parsing.
    pub files_eligible: usize,
    /// Eligible files producing a recoverable syntax tree or valid cache entry.
    pub files_parsed: usize,
    /// Parsed files containing at least one recoverable syntax diagnostic.
    pub files_with_diagnostics: usize,
    /// Total normalized facts retained in the report.
    pub facts_extracted: usize,
    /// Wall-clock parsing and cache time in milliseconds; volatile.
    pub duration_ms: u64,
    /// Whether parse-cache reads and writes were enabled.
    pub cache_enabled: bool,
    /// Valid cache entries reused; volatile.
    pub cache_hits: usize,
    /// Eligible files without a reusable cache entry; volatile.
    pub cache_misses: usize,
    /// Atomic cache entries written; volatile.
    pub cache_writes: usize,
    /// Corrupt or incompatible entries ignored safely; volatile.
    pub cache_entries_ignored: usize,
}

/// Stable parser and extractor provenance attached to facts and diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ParserProvenance {
    /// Secure Engine parser adapter identifier.
    pub parser: String,
    /// Tree-sitter runtime version.
    pub parser_version: String,
    /// Selected grammar and grammar crate version.
    pub grammar: String,
    /// Secure Engine extractor version.
    pub extractor_version: String,
}

/// A normalized relationship from one syntax fact to a stable target name.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FactRelationship {
    /// Relationship kind such as `calls`, `imports`, or `handles`.
    pub kind: String,
    /// Bounded normalized target; never source text beyond the relevant syntax name.
    pub target: String,
}

/// Deterministic syntax evidence produced by a Secure Engine-owned parser adapter.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NormalizedFact {
    /// Stable identifier derived from kind, location, names, relationships, and provenance.
    pub fact_id: String,
    /// Fact category such as `function`, `call`, `http-route`, or `environment-access`.
    pub kind: String,
    /// Exact repository-relative syntax evidence.
    pub location: SourceLocation,
    /// Optional bounded normalized symbol or operation name.
    pub name: Option<String>,
    /// Stable normalized module, call, route, or operation relationships.
    pub relationships: Vec<FactRelationship>,
    /// Parser and extractor provenance.
    pub provenance: ParserProvenance,
    /// Stable evidence fingerprint independent of scan timing and cache state.
    pub fingerprint: String,
}

/// Recoverable parser diagnostic with no source snippet or absolute path.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ParserDiagnostic {
    /// Stable diagnostic identifier.
    pub diagnostic_id: String,
    /// Stable category such as `syntax-error`, `missing-syntax`, or `invalid-utf8`.
    pub code: String,
    /// Sanitized deterministic description.
    pub message: String,
    /// Exact repository-relative location when available.
    pub location: SourceLocation,
    /// Tree-sitter recovery allows other facts from the file to remain useful.
    pub recoverable: bool,
    /// Parser and grammar provenance.
    pub provenance: ParserProvenance,
}

/// Deterministic coverage for one parser mode.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ParserCoverage {
    /// `javascript`, `jsx`, `typescript`, or `tsx`.
    pub parser_mode: String,
    /// Files eligible for this mode.
    pub files_eligible: usize,
    /// Files parsed or restored from a compatible cache entry.
    pub files_parsed: usize,
    /// Files with recoverable parser diagnostics.
    pub files_with_diagnostics: usize,
    /// Facts retained for this mode.
    pub facts_extracted: usize,
}

/// Stable repository-relative location.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceLocation {
    /// Slash-normalized repository-relative path.
    pub path: String,
    /// Exact half-open source span.
    pub span: SourceSpan,
}

/// Half-open source coordinates, all one-based except byte offsets.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceSpan {
    /// Zero-based byte offset of the first byte.
    pub start_byte: u64,
    /// Zero-based byte offset immediately after the evidence.
    pub end_byte: u64,
    /// One-based start line.
    pub start_line: u32,
    /// One-based start column in Unicode scalar values.
    pub start_column: u32,
    /// One-based end line.
    pub end_line: u32,
    /// One-based end column in Unicode scalar values.
    pub end_column: u32,
}

/// One successfully read regular file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileRecord {
    /// Repository-relative path.
    pub path: String,
    /// Coarse deterministic classification such as source or manifest.
    pub kind: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// BLAKE3 digest of file contents.
    pub content_fingerprint: String,
    /// Detected implementation language, when recognized.
    pub language: Option<String>,
    /// `project`, `generated`, or `vendor`.
    #[serde(default = "default_file_origin")]
    pub origin: String,
    /// Whether bounded content inspection classified this file as binary.
    #[serde(default)]
    pub is_binary: bool,
}

fn default_file_origin() -> String {
    "project".into()
}

/// Aggregated language evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LanguageSummary {
    /// Stable language name.
    pub name: String,
    /// Number of matching files.
    pub file_count: usize,
    /// Total matching bytes.
    pub bytes: u64,
}

/// Detected manifest evidence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ManifestEvidence {
    /// Ecosystem/build kind.
    pub kind: String,
    /// Location of the manifest filename.
    pub location: SourceLocation,
    /// Stable evidence fingerprint.
    pub fingerprint: String,
}

/// Framework name observed in a manifest.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FrameworkEvidence {
    /// Stable framework label.
    pub name: String,
    /// Manifest occurrence supporting this classification.
    pub evidence: SourceLocation,
    /// Stable evidence fingerprint.
    pub fingerprint: String,
}

/// Conventional application entry point.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EntryPointEvidence {
    /// Entry-point category.
    pub kind: String,
    /// File evidence.
    pub location: SourceLocation,
    /// Stable evidence fingerprint.
    pub fingerprint: String,
}

/// Security-relevant capability classification.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CapabilityEvidence {
    /// Stable capability identifier.
    pub capability: String,
    /// Why the inventory inferred the capability.
    pub reason: String,
    /// Precise supporting location.
    pub evidence: SourceLocation,
    /// Stable evidence fingerprint.
    pub fingerprint: String,
}

/// Evidence that data/control may cross a system boundary.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TrustBoundaryEvidence {
    /// Stable boundary kind.
    pub kind: String,
    /// Human-readable but deterministic explanation.
    pub description: String,
    /// Precise supporting location.
    pub evidence: SourceLocation,
    /// Stable evidence fingerprint.
    pub fingerprint: String,
}

/// Normalized finding model reserved for future deterministic rules.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Finding {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Stable finding identifier.
    pub finding_id: String,
    /// Short finding title.
    pub title: String,
    /// Category such as authorization or injection.
    pub category: String,
    /// Impact severity, distinct from confidence.
    pub severity: String,
    /// Evidence confidence, distinct from severity.
    pub confidence: String,
    /// Primary source evidence.
    pub evidence: Vec<SourceLocation>,
    /// Security invariant claimed to be violated.
    pub invariant: String,
    /// Preconditions needed for exploitation.
    pub prerequisites: Vec<String>,
    /// Realistic impact statement.
    pub impact: String,
    /// Remediation guidance.
    pub remediation: String,
    /// Deterministic engine verification state.
    pub verification_state: String,
    /// Finding-specific limitations.
    pub limitations: Vec<String>,
    /// Stable deduplication fingerprint.
    pub fingerprint: String,
}

/// Declared analysis limitation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Limitation {
    /// Stable limitation code.
    pub code: String,
    /// Deterministic explanation.
    pub message: String,
}

/// File omitted from content inspection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SkippedFile {
    /// Repository-relative path.
    pub path: String,
    /// Stable reason code.
    pub reason: String,
}

/// Aggregate count for one exclusion reason without revealing excluded names.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExclusionSummary {
    /// Stable reason such as `vendor-directory` or `exclude-pattern`.
    pub reason: String,
    /// Number of roots or inputs pruned for this reason.
    pub count: usize,
}

/// Non-fatal scan error with no host path or source text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedError {
    /// Stable category.
    pub code: String,
    /// Optional repository-relative path.
    pub path: Option<String>,
    /// Sanitized deterministic message.
    pub message: String,
}

/// Typed progress message shared with terminal and native UI projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgressEvent {
    /// Traversal has begun.
    Discovering,
    /// Bounded traversal progress for large repositories.
    DiscoveryProgress {
        /// Entries yielded after safe directory pruning.
        entries_seen: usize,
        /// Matching regular-file candidates seen so far.
        candidate_files: usize,
    },
    /// File inventory progress.
    Inspecting {
        /// Number of files already considered.
        completed: usize,
        /// Total files to consider.
        total: usize,
        /// Current repository-relative path.
        path: String,
    },
    /// Supported-language parsing progress.
    Parsing {
        /// Number of eligible files already parsed or restored from cache.
        completed: usize,
        /// Total eligible files selected for parsing.
        total: usize,
        /// Current repository-relative path.
        path: String,
        /// `javascript`, `jsx`, `typescript`, or `tsx`.
        parser_mode: String,
    },
    /// Report normalization and fingerprints are being finalized.
    Finalizing,
    /// A complete report is available.
    Complete {
        /// Number of successfully scanned files.
        files_scanned: usize,
    },
}

/// Machine-readable environment check for `secure doctor`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DoctorReport {
    /// Contract version.
    pub schema_version: String,
    /// Producing engine version.
    pub engine_version: String,
    /// Distinguishes this document from a scan report.
    pub document_type: String,
    /// Whether all required runtime checks passed.
    pub healthy: bool,
    /// Deterministically ordered checks.
    pub checks: Vec<DoctorCheck>,
}

/// One doctor check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DoctorCheck {
    /// Stable check identifier.
    pub name: String,
    /// Check result.
    pub status: String,
    /// Concise detail with no sensitive path.
    pub detail: String,
}

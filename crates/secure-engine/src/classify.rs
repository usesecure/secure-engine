#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum FileOrigin {
    Project,
    Generated,
    Vendor,
}

impl FileOrigin {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Generated => "generated",
            Self::Vendor => "vendor",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ManifestInfo {
    pub(crate) kind: &'static str,
    pub(crate) is_lockfile: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameworkMatch {
    pub(crate) name: &'static str,
    pub(crate) offset: usize,
    pub(crate) length: usize,
}

pub(crate) fn origin_for_path(path: &str) -> FileOrigin {
    let mut origin = FileOrigin::Project;
    for component in path.split('/') {
        if is_vendor_directory(component) {
            return FileOrigin::Vendor;
        }
        if is_generated_directory(component) {
            origin = FileOrigin::Generated;
        }
    }
    origin
}

pub(crate) fn is_generated_directory(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "target"
            | "dist"
            | "build"
            | "out"
            | "coverage"
            | ".next"
            | ".nuxt"
            | ".svelte-kit"
            | ".turbo"
            | ".cache"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | ".gradle"
    )
}

pub(crate) fn is_vendor_directory(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "node_modules"
            | "vendor"
            | "vendors"
            | "third_party"
            | "third-party"
            | ".venv"
            | "venv"
            | "site-packages"
    )
}

pub(crate) fn detect_language(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.').map(|(_, extension)| extension)?;
    match extension.to_ascii_lowercase().as_str() {
        "c" | "h" => Some("C"),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => Some("C++"),
        "cs" => Some("C#"),
        "dart" => Some("Dart"),
        "ex" | "exs" => Some("Elixir"),
        "erl" | "hrl" => Some("Erlang"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "kt" | "kts" => Some("Kotlin"),
        "lua" => Some("Lua"),
        "php" => Some("PHP"),
        "pl" | "pm" => Some("Perl"),
        "py" | "pyi" => Some("Python"),
        "r" => Some("R"),
        "rb" => Some("Ruby"),
        "rs" => Some("Rust"),
        "scala" | "sc" => Some("Scala"),
        "sh" | "bash" | "zsh" | "fish" => Some("Shell"),
        "swift" => Some("Swift"),
        "ts" | "tsx" | "mts" | "cts" => Some("TypeScript"),
        "vue" => Some("Vue"),
        "svelte" => Some("Svelte"),
        _ => None,
    }
}

pub(crate) fn manifest_info(path: &str) -> Option<ManifestInfo> {
    let name = file_name(path).to_ascii_lowercase();
    let direct = match name.as_str() {
        "cargo.toml" => Some(("cargo", false)),
        "cargo.lock" => Some(("cargo-lock", true)),
        "package.json" => Some(("npm", false)),
        "package-lock.json" | "npm-shrinkwrap.json" => Some(("npm-lock", true)),
        "pnpm-workspace.yaml" => Some(("pnpm-workspace", false)),
        "pnpm-lock.yaml" => Some(("pnpm-lock", true)),
        "yarn.lock" => Some(("yarn-lock", true)),
        "bun.lock" | "bun.lockb" => Some(("bun-lock", true)),
        "deno.json" | "deno.jsonc" => Some(("deno", false)),
        "pyproject.toml" => Some(("python", false)),
        "setup.py" | "setup.cfg" => Some(("python-package", false)),
        "requirements.txt" | "pipfile" => Some(("python-requirements", false)),
        "pipfile.lock" | "poetry.lock" | "uv.lock" => Some(("python-lock", true)),
        "go.mod" => Some(("go-modules", false)),
        "go.sum" => Some(("go-checksums", true)),
        "pom.xml" => Some(("maven", false)),
        "build.gradle" | "build.gradle.kts" | "settings.gradle" | "settings.gradle.kts" => {
            Some(("gradle", false))
        }
        "gemfile" => Some(("bundler", false)),
        "gemfile.lock" => Some(("bundler-lock", true)),
        "composer.json" => Some(("composer", false)),
        "composer.lock" => Some(("composer-lock", true)),
        "package.swift" => Some(("swift-package", false)),
        "package.resolved" => Some(("swift-lock", true)),
        "mix.exs" => Some(("mix", false)),
        "mix.lock" => Some(("mix-lock", true)),
        "pubspec.yaml" => Some(("dart-pub", false)),
        "pubspec.lock" => Some(("dart-pub-lock", true)),
        "directory.build.props" | "directory.packages.props" => Some(("dotnet", false)),
        _ => None,
    };
    if let Some((kind, is_lockfile)) = direct {
        return Some(ManifestInfo { kind, is_lockfile });
    }
    if name.ends_with(".csproj") || name.ends_with(".fsproj") || name.ends_with(".vbproj") {
        return Some(ManifestInfo {
            kind: "dotnet-project",
            is_lockfile: false,
        });
    }
    None
}

pub(crate) fn classify_file(
    path: &str,
    manifest: Option<ManifestInfo>,
    language: Option<&str>,
    binary: bool,
) -> &'static str {
    if binary {
        "binary"
    } else if manifest.is_some_and(|item| item.is_lockfile) {
        "lockfile"
    } else if manifest.is_some() {
        "manifest"
    } else if is_test_path(path) && language.is_some() {
        "test-source"
    } else if language.is_some() {
        "source"
    } else if is_build_automation(path) {
        "build-configuration"
    } else if is_documentation(path) {
        "documentation"
    } else if is_configuration(path) {
        "configuration"
    } else if is_data(path) {
        "data"
    } else {
        "other"
    }
}

pub(crate) fn entry_point_kind(path: &str) -> Option<&'static str> {
    let name = file_name(path).to_ascii_lowercase();
    match name.as_str() {
        "main.rs" | "main.go" | "main.py" | "main.ts" | "main.js" | "main.kt" | "main.java" => {
            Some("main")
        }
        "app.py" | "app.ts" | "app.js" | "app.rb" => Some("application"),
        "server.py" | "server.ts" | "server.js" | "server.rb" => Some("server"),
        "manage.py" => Some("framework-cli"),
        _ => None,
    }
}

pub(crate) fn is_build_automation(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    matches!(file_name(&lower), "dockerfile" | "makefile" | "justfile")
        || lower.starts_with(".github/workflows/")
        || lower == ".gitlab-ci.yml"
        || lower == "azure-pipelines.yml"
        || lower.starts_with(".circleci/")
}

pub(crate) fn framework_matches(content: &[u8]) -> Vec<FrameworkMatch> {
    const SIGNATURES: &[(&str, &[u8])] = &[
        ("Actix Web", b"actix-web"),
        ("ASP.NET Core", b"microsoft.aspnetcore"),
        ("Axum", b"axum"),
        ("Django", b"django"),
        ("Express", b"express"),
        ("FastAPI", b"fastapi"),
        ("Flask", b"flask"),
        ("NestJS", b"@nestjs/core"),
        ("Next.js", b"\"next\""),
        ("Rails", b"rails"),
        ("Rocket", b"rocket"),
        ("Spring Boot", b"spring-boot"),
    ];
    let lowercase = content
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    SIGNATURES
        .iter()
        .filter_map(|(name, needle)| {
            find_bytes(&lowercase, needle).map(|offset| FrameworkMatch {
                name,
                offset,
                length: needle.len(),
            })
        })
        .collect()
}

pub(crate) fn is_binary(content: &[u8]) -> bool {
    let sample = &content[..content.len().min(8 * 1024)];
    if sample.contains(&0) {
        return true;
    }
    let control_count = sample
        .iter()
        .filter(|byte| byte.is_ascii_control() && !matches!(byte, b'\t' | b'\n' | b'\r' | 0x0C))
        .count();
    !sample.is_empty() && control_count.saturating_mul(100) / sample.len() > 10
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower
        .split('/')
        .any(|part| matches!(part, "test" | "tests" | "spec" | "specs"))
        || file_name(&lower).contains(".test.")
        || file_name(&lower).contains(".spec.")
        || file_name(&lower).starts_with("test_")
        || file_name(&lower).ends_with("_test.rs")
        || file_name(&lower).ends_with("_test.go")
}

fn is_documentation(path: &str) -> bool {
    matches!(
        path.rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .as_deref(),
        Some("md" | "mdx" | "rst" | "adoc" | "txt")
    )
}

fn is_configuration(path: &str) -> bool {
    let name = file_name(path).to_ascii_lowercase();
    name.starts_with(".env.")
        || matches!(name.as_str(), ".env" | "editorconfig")
        || matches!(
            path.rsplit_once('.')
                .map(|(_, extension)| extension.to_ascii_lowercase())
                .as_deref(),
            Some("json" | "jsonc" | "toml" | "yaml" | "yml" | "ini" | "conf" | "cfg" | "xml")
        )
}

fn is_data(path: &str) -> bool {
    matches!(
        path.rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .as_deref(),
        Some("csv" | "tsv" | "sql" | "graphql" | "gql")
    )
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_origins_languages_manifests_and_binary_content() {
        assert_eq!(
            origin_for_path("node_modules/pkg/index.js"),
            FileOrigin::Vendor
        );
        assert_eq!(origin_for_path("target/debug/app"), FileOrigin::Generated);
        assert_eq!(detect_language("src/main.rs"), Some("Rust"));
        assert!(manifest_info("Cargo.lock").is_some_and(|item| item.is_lockfile));
        assert_eq!(
            classify_file("tests/api.rs", None, Some("Rust"), false),
            "test-source"
        );
        assert!(is_binary(b"GIF89a\0binary"));
        assert!(!is_binary(b"fn main() { println!(\"hello\"); }\n"));
    }

    #[test]
    fn framework_detection_is_case_insensitive_and_precise() {
        let matches = framework_matches(b"[dependencies]\nAxum = \"0.8\"\n");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "Axum");
        assert_eq!(matches[0].offset, 15);
    }
}

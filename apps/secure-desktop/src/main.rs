#![allow(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui;
use secure_desktop::{
    FindingFilter, FindingSort, InventoryControls, SuppressionFilter, filter_findings,
    spawn_ai_validation_worker, spawn_inventory_worker, spawn_source_preview_worker,
};
use secure_engine::{
    AiAssessment, AiCache, AiPreview, AiProjectConfiguration, Baseline, BaselineComparison,
    CancellationToken, ExportFormat, HistoryEntry, HistoryListing, HistoryStore, HistorySummary,
    ProgressEvent, ScanError, ScanReport, SourcePreview, Suppression, compare_baseline,
    configured_provider, create_baseline, default_ai_cache_directory, default_history_directory,
    preview_finding, read_ai_configuration, write_export, write_json_artifact,
};

fn main() -> eframe::Result {
    let initial_repository = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Secure Engine",
        options,
        Box::new(move |creation_context| {
            Ok(Box::new(SecureApp::new(
                creation_context.egui_ctx.clone(),
                initial_repository,
            )))
        }),
    )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Page {
    #[default]
    Overview,
    Findings,
    Architecture,
    Dependencies,
    History,
    AiValidation,
    Settings,
}

enum AppMessage {
    Progress(ProgressEvent),
    ScanFinished(Box<Result<ScanReport, ScanError>>),
    RepositoryPicked(Option<PathBuf>),
    SourceLoaded(Result<SourcePreview, String>),
    ExportFinished(Result<PathBuf, String>),
    HistoryLoaded(Result<HistoryListing, String>),
    HistoryRecorded(Result<HistorySummary, String>),
    HistoryOpened(Box<Result<(HistoryEntry, Option<PathBuf>), String>>),
    HistoryDeleted(Result<String, String>),
    BaselineCreated(Box<Result<(Baseline, PathBuf), String>>),
    BaselineCompared(Box<Result<BaselineComparison, String>>),
    AiFinished(Box<Result<AiAssessment, String>>),
}

#[allow(clippy::struct_excessive_bools)]
struct SecureApp {
    context: egui::Context,
    sender: Sender<AppMessage>,
    receiver: Receiver<AppMessage>,
    repository_input: String,
    current_repository: Option<PathBuf>,
    recent_projects: Vec<PathBuf>,
    controls: InventoryControls,
    include_patterns_input: String,
    exclude_patterns_input: String,
    max_depth_input: usize,
    cache_directory_input: String,
    status: String,
    stage: String,
    progress: f32,
    report: Option<ScanReport>,
    cancellation: Option<CancellationToken>,
    scanning: bool,
    page: Page,
    finding_filter: FindingFilter,
    finding_sort: FindingSort,
    selected_finding: Option<String>,
    source_preview: Option<SourcePreview>,
    source_loading: bool,
    suppression_reason: String,
    history: Vec<HistorySummary>,
    history_recovered: usize,
    history_retention: usize,
    history_directory: PathBuf,
    baseline: Option<Baseline>,
    comparison: Option<BaselineComparison>,
    text_scale: f32,
    operation_busy: bool,
    ai_enabled: bool,
    ai_config_path: String,
    ai_configuration: Option<AiProjectConfiguration>,
    ai_preview: Option<AiPreview>,
    ai_assessment: Option<AiAssessment>,
    ai_consent: bool,
    ai_busy: bool,
    ai_cancellation: Option<CancellationToken>,
}

impl SecureApp {
    fn new(context: egui::Context, repository_input: String) -> Self {
        let (sender, receiver) = bounded(512);
        let mut app = Self {
            context,
            sender,
            receiver,
            repository_input,
            current_repository: None,
            recent_projects: Vec::new(),
            controls: InventoryControls::default(),
            include_patterns_input: String::new(),
            exclude_patterns_input: String::new(),
            max_depth_input: 0,
            cache_directory_input: String::new(),
            status: "Ready. Choose a local repository.".into(),
            stage: "ready".into(),
            progress: 0.0,
            report: None,
            cancellation: None,
            scanning: false,
            page: Page::Overview,
            finding_filter: FindingFilter::default(),
            finding_sort: FindingSort::default(),
            selected_finding: None,
            source_preview: None,
            source_loading: false,
            suppression_reason: String::new(),
            history: Vec::new(),
            history_recovered: 0,
            history_retention: 50,
            history_directory: default_history_directory(),
            baseline: None,
            comparison: None,
            text_scale: 1.0,
            operation_busy: false,
            ai_enabled: false,
            ai_config_path: String::new(),
            ai_configuration: None,
            ai_preview: None,
            ai_assessment: None,
            ai_consent: false,
            ai_busy: false,
            ai_cancellation: None,
        };
        app.refresh_history();
        app
    }

    fn start_scan(&mut self) {
        if self.scanning || self.repository_input.trim().is_empty() {
            return;
        }
        let repository = PathBuf::from(self.repository_input.trim());
        let mut controls = self.controls.clone();
        controls.include_patterns = parse_patterns(&self.include_patterns_input);
        controls.exclude_patterns = parse_patterns(&self.exclude_patterns_input);
        controls.max_depth = (self.max_depth_input > 0).then_some(self.max_depth_input);
        controls.cache_directory = (!self.cache_directory_input.trim().is_empty())
            .then(|| PathBuf::from(self.cache_directory_input.trim()));
        let request = controls.request(repository.clone());
        self.controls.clear_cache_before_scan = false;
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        self.cancellation = Some(cancellation);
        self.current_repository = Some(repository.clone());
        remember_project(&mut self.recent_projects, repository);
        self.scanning = true;
        self.report = None;
        self.selected_finding = None;
        self.source_preview = None;
        self.comparison = None;
        self.progress = 0.0;
        self.stage = "discovering".into();
        self.status = "Discovering repository files…".into();
        let progress_sender = self.sender.clone();
        let completion_sender = self.sender.clone();
        let repaint_progress = self.context.clone();
        let repaint_complete = self.context.clone();
        let _worker = spawn_inventory_worker(
            request,
            worker_cancellation,
            move |event| {
                let _ignored = progress_sender.try_send(AppMessage::Progress(event));
                repaint_progress.request_repaint();
            },
            move |result| {
                let _ignored = completion_sender.send(AppMessage::ScanFinished(Box::new(result)));
                repaint_complete.request_repaint();
            },
        );
    }

    fn cancel_scan(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
            self.stage = "cancelling".into();
            self.status = "Cancelling…".into();
        }
    }

    fn clear_result(&mut self) {
        if !self.scanning {
            self.report = None;
            self.selected_finding = None;
            self.source_preview = None;
            self.comparison = None;
            self.stage = "ready".into();
            self.status = "Result cleared. Ready to scan.".into();
            self.progress = 0.0;
        }
    }

    fn pick_repository(&mut self) {
        if self.operation_busy || self.scanning {
            return;
        }
        self.operation_busy = true;
        self.status = "Opening repository picker…".into();
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let selected = rfd::FileDialog::new().pick_folder();
            let _ignored = sender.send(AppMessage::RepositoryPicked(selected));
            context.request_repaint();
        });
    }

    fn load_source(&mut self, location: secure_engine::SourceLocation) {
        let Some(repository) = self.current_repository.clone() else {
            self.status = "The original repository is unavailable for source preview.".into();
            return;
        };
        self.source_loading = true;
        self.source_preview = None;
        let sender = self.sender.clone();
        let context = self.context.clone();
        let _worker = spawn_source_preview_worker(
            repository,
            location,
            CancellationToken::new(),
            move |result| {
                let message = result.map_err(|error| error.to_string());
                let _ignored = sender.send(AppMessage::SourceLoaded(message));
                context.request_repaint();
            },
        );
    }

    fn export_report(&mut self, format: ExportFormat) {
        let Some(report) = self.report.clone() else {
            return;
        };
        if self.operation_busy {
            return;
        }
        self.operation_busy = true;
        self.status = "Choosing export destination…".into();
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let (label, extension) = match format {
                ExportFormat::SecureJson => ("Secure JSON", "json"),
                ExportFormat::Sarif => ("SARIF 2.1.0", "sarif"),
            };
            let selected = rfd::FileDialog::new()
                .add_filter(label, &[extension])
                .set_file_name(format!("secure-report.{extension}"))
                .save_file();
            let result = selected.map_or_else(
                || Err("Export cancelled".into()),
                |path| {
                    write_export(&report, format, &path, &CancellationToken::new())
                        .map(|()| path)
                        .map_err(|error| error.to_string())
                },
            );
            let _ignored = sender.send(AppMessage::ExportFinished(result));
            context.request_repaint();
        });
    }

    fn create_baseline_file(&mut self) {
        let Some(report) = self.report.clone() else {
            return;
        };
        if self.operation_busy {
            return;
        }
        self.operation_busy = true;
        self.status = "Choosing baseline destination…".into();
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let result = create_baseline(&report)
                .map_err(|error| error.to_string())
                .and_then(|baseline| {
                    rfd::FileDialog::new()
                        .add_filter("Secure baseline", &["json"])
                        .set_file_name("secure-baseline.json")
                        .save_file()
                        .ok_or_else(|| "Baseline creation cancelled".to_owned())
                        .and_then(|path| {
                            write_json_artifact(&baseline, &path, &CancellationToken::new())
                                .map_err(|error| error.to_string())?;
                            Ok((baseline, path))
                        })
                });
            let _ignored = sender.send(AppMessage::BaselineCreated(Box::new(result)));
            context.request_repaint();
        });
    }

    fn compare_baseline_file(&mut self) {
        let Some(report) = self.report.clone() else {
            return;
        };
        if self.operation_busy {
            return;
        }
        self.operation_busy = true;
        self.status = "Choosing baseline…".into();
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let result = rfd::FileDialog::new()
                .add_filter("Secure baseline", &["json"])
                .pick_file()
                .ok_or_else(|| "Baseline comparison cancelled".to_owned())
                .and_then(|path| read_baseline_file(&path))
                .and_then(|baseline| {
                    compare_baseline(&baseline, &report).map_err(|error| error.to_string())
                });
            let _ignored = sender.send(AppMessage::BaselineCompared(Box::new(result)));
            context.request_repaint();
        });
    }

    fn refresh_history(&mut self) {
        let directory = self.history_directory.clone();
        let retention = self.history_retention;
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let result = HistoryStore::open(directory, retention)
                .and_then(|store| store.list(&CancellationToken::new()))
                .map_err(|error| error.to_string());
            let _ignored = sender.send(AppMessage::HistoryLoaded(result));
            context.request_repaint();
        });
    }

    fn record_history(&self, report: ScanReport, repository: Option<PathBuf>) {
        let directory = self.history_directory.clone();
        let retention = self.history_retention;
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let result = HistoryStore::open(directory, retention)
                .and_then(|store| {
                    store.record(
                        &report,
                        repository.as_deref(),
                        None,
                        &CancellationToken::new(),
                    )
                })
                .map_err(|error| error.to_string());
            let _ignored = sender.send(AppMessage::HistoryRecorded(result));
            context.request_repaint();
        });
    }

    fn open_history(&mut self, scan_id: String) {
        if self.operation_busy {
            return;
        }
        self.operation_busy = true;
        self.status = format!("Opening {scan_id}…");
        let directory = self.history_directory.clone();
        let retention = self.history_retention;
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let result = HistoryStore::open(directory, retention)
                .and_then(|store| {
                    let cancellation = CancellationToken::new();
                    let entry = store.show(&scan_id, &cancellation)?;
                    let repository = store.repository_path(&scan_id, &cancellation)?;
                    Ok((entry, repository))
                })
                .map_err(|error| error.to_string());
            let _ignored = sender.send(AppMessage::HistoryOpened(Box::new(result)));
            context.request_repaint();
        });
    }

    fn compare_history(&mut self, scan_id: String) {
        let Some(current) = self.report.clone() else {
            self.status = "Open or complete a current scan before comparing history.".into();
            return;
        };
        if self.operation_busy {
            return;
        }
        self.operation_busy = true;
        let directory = self.history_directory.clone();
        let retention = self.history_retention;
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let result = HistoryStore::open(directory, retention)
                .and_then(|store| store.show(&scan_id, &CancellationToken::new()))
                .map_err(|error| error.to_string())
                .and_then(|entry| create_baseline(&entry.report).map_err(|error| error.to_string()))
                .and_then(|baseline| {
                    compare_baseline(&baseline, &current).map_err(|error| error.to_string())
                });
            let _ignored = sender.send(AppMessage::BaselineCompared(Box::new(result)));
            context.request_repaint();
        });
    }

    fn delete_history(&mut self, scan_id: String) {
        if self.operation_busy {
            return;
        }
        self.operation_busy = true;
        let directory = self.history_directory.clone();
        let retention = self.history_retention;
        let sender = self.sender.clone();
        let context = self.context.clone();
        thread::spawn(move || {
            let result = HistoryStore::open(directory, retention)
                .and_then(|store| store.delete(&scan_id))
                .map(|()| scan_id)
                .map_err(|error| error.to_string());
            let _ignored = sender.send(AppMessage::HistoryDeleted(result));
            context.request_repaint();
        });
    }

    fn load_ai_configuration(&mut self) {
        if !self.ai_enabled || self.ai_config_path.trim().is_empty() || self.ai_busy {
            return;
        }
        match read_ai_configuration(Path::new(self.ai_config_path.trim())) {
            Ok(configuration) => {
                self.status = format!(
                    "Loaded AI provider {} and model {}; no request has been sent.",
                    configuration.provider, configuration.model
                );
                self.ai_configuration = Some(configuration);
                self.ai_preview = None;
                self.ai_assessment = None;
                self.ai_consent = false;
            }
            Err(error) => {
                self.ai_configuration = None;
                self.status = error.to_string();
            }
        }
    }

    fn prepare_ai_preview(&mut self) {
        if !self.ai_enabled || self.ai_busy {
            return;
        }
        let Some(report) = self.report.as_ref() else {
            self.status = "Complete or reopen a deterministic scan first.".into();
            return;
        };
        let Some(finding_id) = self.selected_finding.as_deref() else {
            self.status = "Select one deterministic finding first.".into();
            return;
        };
        let Some(configuration) = self.ai_configuration.as_ref() else {
            self.status = "Load an explicit enabled project AI configuration first.".into();
            return;
        };
        match preview_finding(report, finding_id, configuration) {
            Ok(preview) => {
                self.status =
                    "Exact redacted payload prepared locally; review it before consent.".into();
                self.ai_preview = Some(preview);
                self.ai_assessment = None;
                self.ai_consent = false;
            }
            Err(error) => self.status = error.to_string(),
        }
    }

    fn start_ai_validation(&mut self) {
        if !self.ai_enabled || !self.ai_consent || self.ai_busy {
            return;
        }
        let (Some(report), Some(preview), Some(configuration)) = (
            self.report.clone(),
            self.ai_preview.clone(),
            self.ai_configuration.clone(),
        ) else {
            self.status =
                "A current report, exact preview, and project configuration are required.".into();
            return;
        };
        let recorded = match configuration
            .recorded_response
            .as_deref()
            .map(read_recorded_ai_response)
            .transpose()
        {
            Ok(recorded) => recorded,
            Err(error) => {
                self.status = error;
                return;
            }
        };
        let provider = match configured_provider(&configuration, recorded) {
            Ok(provider) => provider,
            Err(error) => {
                self.status = error.to_string();
                return;
            }
        };
        let cache = match AiCache::open(default_ai_cache_directory()) {
            Ok(cache) => Some(cache),
            Err(error) => {
                self.status = error.to_string();
                return;
            }
        };
        let cancellation = CancellationToken::new();
        self.ai_cancellation = Some(cancellation.clone());
        self.ai_busy = true;
        self.ai_assessment = None;
        self.status = format!(
            "Validating {} with {} / {}…",
            preview.finding_id, preview.provider, preview.model
        );
        let sender = self.sender.clone();
        let context = self.context.clone();
        let _worker = spawn_ai_validation_worker(
            report,
            preview,
            configuration,
            provider,
            cache,
            cancellation,
            move |result| {
                let _ignored = sender.send(AppMessage::AiFinished(Box::new(
                    result.map_err(|error| error.to_string()),
                )));
                context.request_repaint();
            },
        );
    }

    fn cancel_ai_validation(&mut self) {
        if let Some(cancellation) = &self.ai_cancellation {
            cancellation.cancel();
            self.status = "Cancelling AI validation…".into();
        }
    }

    fn delete_local_ai_data(&mut self) {
        self.ai_preview = None;
        self.ai_assessment = None;
        self.ai_consent = false;
        match AiCache::open(default_ai_cache_directory())
            .and_then(|cache| cache.clear(&CancellationToken::new()))
        {
            Ok(removed) => {
                self.status =
                    format!("Deleted {removed} local AI cache entries and cleared this session.");
            }
            Err(error) => self.status = error.to_string(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_message(&mut self, message: AppMessage) {
        match message {
            AppMessage::Progress(event) => self.apply_progress(event),
            AppMessage::ScanFinished(result) => self.apply_scan_result(*result),
            AppMessage::RepositoryPicked(selected) => {
                self.operation_busy = false;
                if let Some(path) = selected {
                    self.repository_input = path.display().to_string();
                    remember_project(&mut self.recent_projects, path);
                    self.status = "Repository selected. Ready to scan.".into();
                } else {
                    self.status = "Repository selection cancelled.".into();
                }
            }
            AppMessage::SourceLoaded(result) => {
                self.source_loading = false;
                match result {
                    Ok(preview) => {
                        self.status = format!("Loaded safe preview for {}", preview.path);
                        self.source_preview = Some(preview);
                    }
                    Err(error) => self.status = error,
                }
            }
            AppMessage::ExportFinished(result) => {
                self.operation_busy = false;
                self.status = result.map_or_else(
                    |error| error,
                    |path| format!("Exported atomically to {}", path.display()),
                );
            }
            AppMessage::HistoryLoaded(result) => match result {
                Ok(listing) => {
                    self.history = listing.scans;
                    self.history_recovered = listing.corrupt_entries_recovered;
                }
                Err(error) => self.status = error,
            },
            AppMessage::HistoryRecorded(result) => match result {
                Ok(summary) => {
                    self.status = format!("Complete and saved as {}", summary.scan_id);
                    self.refresh_history();
                }
                Err(error) => self.status = format!("Scan complete; history failed: {error}"),
            },
            AppMessage::HistoryOpened(result) => {
                self.operation_busy = false;
                match *result {
                    Ok((entry, repository)) => {
                        self.report = Some(entry.report);
                        self.current_repository.clone_from(&repository);
                        if let Some(repository) = repository {
                            self.repository_input = repository.display().to_string();
                            remember_project(&mut self.recent_projects, repository);
                        }
                        self.selected_finding = None;
                        self.source_preview = None;
                        self.stage = "history".into();
                        self.status = format!("Reopened {}", entry.summary.scan_id);
                        self.page = Page::Overview;
                    }
                    Err(error) => self.status = error,
                }
            }
            AppMessage::HistoryDeleted(result) => {
                self.operation_busy = false;
                self.status =
                    result.map_or_else(|error| error, |scan_id| format!("Deleted {scan_id}"));
                self.refresh_history();
            }
            AppMessage::BaselineCreated(result) => {
                self.operation_busy = false;
                match *result {
                    Ok((baseline, path)) => {
                        self.baseline = Some(baseline);
                        self.status = format!("Baseline saved to {}", path.display());
                    }
                    Err(error) => self.status = error,
                }
            }
            AppMessage::BaselineCompared(result) => {
                self.operation_busy = false;
                match *result {
                    Ok(comparison) => {
                        self.status = format!(
                            "Baseline: {} new, {} changed, {} resolved",
                            comparison.new.len(),
                            comparison.changed.len(),
                            comparison.resolved.len()
                        );
                        self.comparison = Some(comparison);
                    }
                    Err(error) => self.status = error,
                }
            }
            AppMessage::AiFinished(result) => {
                self.ai_busy = false;
                self.ai_cancellation = None;
                self.ai_consent = false;
                match *result {
                    Ok(assessment) => {
                        self.status = "Separate AI assessment completed; deterministic evidence is unchanged.".into();
                        self.ai_assessment = Some(assessment);
                    }
                    Err(error) => self.status = error,
                }
            }
        }
    }

    fn apply_progress(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::Discovering => {
                self.stage = "discovering".into();
                self.status = "Discovering repository files…".into();
            }
            ProgressEvent::DiscoveryProgress {
                entries_seen,
                candidate_files,
            } => {
                self.status =
                    format!("Discovery: {entries_seen} entries, {candidate_files} candidates");
            }
            ProgressEvent::Inspecting {
                completed,
                total,
                path,
            } => {
                self.stage = "inventory".into();
                self.progress = fraction(completed, total);
                self.status = format!("Inventory {completed}/{total}: {path}");
            }
            ProgressEvent::Parsing {
                completed,
                total,
                path,
                parser_mode,
            } => {
                self.stage = "parsing".into();
                self.progress = fraction(completed, total);
                self.status = format!("Parsing {completed}/{total}: {path} ({parser_mode})");
            }
            ProgressEvent::Analyzing { facts } => {
                self.stage = "analysis".into();
                self.status = format!("Building graph and rules from {facts} facts…");
            }
            ProgressEvent::Finalizing => {
                self.stage = "finalizing".into();
                self.status = "Finalizing deterministic report…".into();
            }
            ProgressEvent::Complete { files_scanned } => {
                self.progress = 1.0;
                self.status = format!("Complete: {files_scanned} files");
            }
        }
    }

    fn apply_scan_result(&mut self, result: Result<ScanReport, ScanError>) {
        self.scanning = false;
        self.cancellation = None;
        match result {
            Ok(report) => {
                self.progress = 1.0;
                self.stage = "complete".into();
                self.status = if report.findings.is_empty() {
                    "Complete: no findings.".into()
                } else {
                    format!("Complete: {} findings.", report.findings.len())
                };
                self.report = Some(report.clone());
                self.record_history(report, self.current_repository.clone());
            }
            Err(ScanError::Cancelled) => {
                self.progress = 0.0;
                self.stage = "cancelled".into();
                self.status = "Cancelled. No partial report was published.".into();
                self.report = None;
            }
            Err(error) => {
                self.progress = 0.0;
                self.stage = "error".into();
                self.status = error.to_string();
                self.report = None;
            }
        }
    }

    fn receive_messages(&mut self) {
        while let Ok(message) = self.receiver.try_recv() {
            self.apply_message(message);
        }
    }

    fn keyboard_shortcuts(&mut self, context: &egui::Context) {
        if context.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::R)) {
            self.start_scan();
        }
        if context.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.cancel_scan();
        }
        for (key, page) in [
            (egui::Key::Num1, Page::Overview),
            (egui::Key::Num2, Page::Findings),
            (egui::Key::Num3, Page::Architecture),
            (egui::Key::Num4, Page::Dependencies),
            (egui::Key::Num5, Page::History),
            (egui::Key::Num6, Page::AiValidation),
            (egui::Key::Num7, Page::Settings),
        ] {
            if context.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, key)) {
                self.page = page;
            }
        }
    }

    fn toolbar(&mut self, root_ui: &mut egui::Ui) {
        egui::Panel::top("toolbar").show(root_ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("Secure Engine");
                ui.separator();
                ui.label("Repository");
                ui.add_enabled(
                    !self.scanning,
                    egui::TextEdit::singleline(&mut self.repository_input).desired_width(330.0),
                );
                if ui
                    .add_enabled(
                        !self.scanning && !self.operation_busy,
                        egui::Button::new("Browse…"),
                    )
                    .clicked()
                {
                    self.pick_repository();
                }
                if ui
                    .add_enabled(!self.scanning, egui::Button::new("Start"))
                    .clicked()
                {
                    self.start_scan();
                }
                if ui
                    .add_enabled(self.scanning, egui::Button::new("Cancel"))
                    .clicked()
                {
                    self.cancel_scan();
                }
                if ui
                    .add_enabled(
                        !self.scanning && self.report.is_some(),
                        egui::Button::new("Rescan"),
                    )
                    .clicked()
                {
                    self.start_scan();
                }
                if ui
                    .add_enabled(
                        !self.scanning && self.report.is_some(),
                        egui::Button::new("Clear"),
                    )
                    .clicked()
                {
                    self.clear_result();
                }
            });
            if !self.recent_projects.is_empty() {
                ui.horizontal(|ui| {
                    ui.weak("Recent:");
                    for project in self.recent_projects.clone().into_iter().take(3) {
                        let label = project
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("repository");
                        if ui
                            .add_enabled(!self.scanning, egui::Button::new(label))
                            .clicked()
                        {
                            self.repository_input = project.display().to_string();
                        }
                    }
                });
            }
        });
    }

    fn navigation(&mut self, root_ui: &mut egui::Ui) {
        egui::Panel::left("navigation")
            .resizable(false)
            .default_size(150.0)
            .show(root_ui, |ui| {
                ui.strong("Workspace");
                ui.add_space(6.0);
                for (page, label, shortcut) in [
                    (Page::Overview, "Overview", "Ctrl+1"),
                    (Page::Findings, "Findings", "Ctrl+2"),
                    (Page::Architecture, "Architecture", "Ctrl+3"),
                    (Page::Dependencies, "Dependencies", "Ctrl+4"),
                    (Page::History, "Scan History", "Ctrl+5"),
                    (Page::AiValidation, "AI Validation", "Ctrl+6"),
                    (Page::Settings, "Settings", "Ctrl+7"),
                ] {
                    if ui
                        .selectable_label(self.page == page, format!("{label}  {shortcut}"))
                        .clicked()
                    {
                        self.page = page;
                    }
                }
                ui.separator();
                ui.weak("Ctrl+R: rescan");
                ui.weak("Esc: cancel");
            });
    }

    fn central(&mut self, root_ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(root_ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.page {
                Page::Overview => self.overview(ui),
                Page::Findings => self.findings(ui),
                Page::Architecture => self.architecture(ui),
                Page::Dependencies => self.dependencies(ui),
                Page::History => self.history(ui),
                Page::AiValidation => self.ai_validation(ui),
                Page::Settings => self.settings(ui),
            });
        });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Overview");
        if self.scanning {
            ui.spinner();
            ui.label("A typed background scan is in progress. The interface remains responsive.");
        }
        let Some(report) = self.report.clone() else {
            ui.add_space(16.0);
            ui.weak(match self.stage.as_str() {
                "cancelled" => "The last scan was cancelled; no partial result was retained.",
                "error" => "The last scan failed. Review the status message below.",
                _ => "No completed scan. Select a committed fixture or synthetic repository and press Start.",
            });
            return;
        };
        let taxonomy_summary = taxonomy_catalog_summary(&report.taxonomy_catalog);
        egui::Grid::new("overview-summary")
            .striped(true)
            .show(ui, |ui| {
                summary_row(ui, "Repository", &report.repository.name);
                summary_row(ui, "Files", &report.scan.files_scanned.to_string());
                summary_row(ui, "Facts", &report.facts.len().to_string());
                summary_row(
                    ui,
                    "Graph nodes / edges",
                    &format!("{} / {}", report.analysis.nodes, report.analysis.edges),
                );
                summary_row(
                    ui,
                    "Rules evaluated",
                    &report.analysis.rules_evaluated.to_string(),
                );
                summary_row(ui, "Findings", &report.findings.len().to_string());
                summary_row(ui, "Neutral taxonomy", &taxonomy_summary);
                summary_row(
                    ui,
                    "Cache hits / misses",
                    &format!(
                        "{} / {}",
                        report.parsing.cache_hits, report.parsing.cache_misses
                    ),
                );
                summary_row(ui, "Duration", &format!("{} ms", report.scan.duration_ms));
                summary_row(ui, "Warnings", &report.parser_diagnostics.len().to_string());
                summary_row(ui, "Bounded errors", &report.errors.len().to_string());
                summary_row(ui, "Fingerprint", &report.report_fingerprint);
            });
        ui.add_space(10.0);
        if report.findings.is_empty() {
            ui.strong("No findings in this completed scan.");
        } else {
            ui.label(format!(
                "{} active findings are ready for inspection.",
                report.findings.len()
            ));
            if ui.button("Open findings").clicked() {
                self.page = Page::Findings;
            }
        }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(!self.operation_busy, egui::Button::new("Export JSON…"))
                .clicked()
            {
                self.export_report(ExportFormat::SecureJson);
            }
            if ui
                .add_enabled(!self.operation_busy, egui::Button::new("Export SARIF…"))
                .clicked()
            {
                self.export_report(ExportFormat::Sarif);
            }
            if ui
                .add_enabled(!self.operation_busy, egui::Button::new("Create baseline…"))
                .clicked()
            {
                self.create_baseline_file();
            }
            if ui
                .add_enabled(!self.operation_busy, egui::Button::new("Compare baseline…"))
                .clicked()
            {
                self.compare_baseline_file();
            }
        });
        if let Some(comparison) = &self.comparison {
            ui.label(format!(
                "Baseline comparison — new: {}, changed: {}, resolved: {}, unchanged: {}",
                comparison.new.len(),
                comparison.changed.len(),
                comparison.resolved.len(),
                comparison.unchanged.len()
            ));
        }
        if self.baseline.is_some() {
            ui.weak("A deterministic baseline is loaded for this session.");
        }
    }

    #[allow(clippy::too_many_lines)]
    fn findings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Findings");
        let Some(report) = self.report.clone() else {
            ui.weak("Complete or reopen a scan to inspect findings.");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label("Search");
            ui.add(
                egui::TextEdit::singleline(&mut self.finding_filter.search).desired_width(160.0),
            );
            for (label, value) in [
                ("Severity", &mut self.finding_filter.severity),
                ("Confidence", &mut self.finding_filter.confidence),
                ("Rule", &mut self.finding_filter.rule),
                ("File", &mut self.finding_filter.file),
                ("Category", &mut self.finding_filter.category),
            ] {
                ui.label(label);
                ui.add(egui::TextEdit::singleline(value).desired_width(90.0));
            }
        });
        ui.horizontal(|ui| {
            egui::ComboBox::from_label("Suppression")
                .selected_text(format!("{:?}", self.finding_filter.suppression))
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.finding_filter.suppression,
                        SuppressionFilter::Any,
                        "Any",
                    );
                    ui.selectable_value(
                        &mut self.finding_filter.suppression,
                        SuppressionFilter::Active,
                        "Active",
                    );
                    ui.selectable_value(
                        &mut self.finding_filter.suppression,
                        SuppressionFilter::Suppressed,
                        "Suppressed diagnostics",
                    );
                });
            egui::ComboBox::from_label("Sort")
                .selected_text(format!("{:?}", self.finding_sort))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.finding_sort, FindingSort::Severity, "Severity");
                    ui.selectable_value(
                        &mut self.finding_sort,
                        FindingSort::Confidence,
                        "Confidence",
                    );
                    ui.selectable_value(&mut self.finding_sort, FindingSort::Rule, "Rule");
                    ui.selectable_value(&mut self.finding_sort, FindingSort::File, "File");
                    ui.selectable_value(&mut self.finding_sort, FindingSort::Category, "Category");
                });
        });
        let rows = filter_findings(&report, &self.finding_filter, self.finding_sort)
            .into_iter()
            .map(|finding| {
                (
                    finding.finding_id.clone(),
                    finding.rule_id.clone(),
                    finding.severity.clone(),
                    finding.confidence.clone(),
                    finding.category.clone(),
                    finding
                        .sink
                        .as_ref()
                        .map_or("unknown", |sink| sink.path.as_str())
                        .to_owned(),
                    finding.title.clone(),
                )
            })
            .collect::<Vec<_>>();
        ui.separator();
        egui::Grid::new("finding-table")
            .striped(true)
            .num_columns(7)
            .show(ui, |ui| {
                for heading in [
                    "Rule",
                    "Severity",
                    "Confidence",
                    "Category",
                    "File",
                    "Title",
                    "",
                ] {
                    ui.strong(heading);
                }
                ui.end_row();
                for (id, rule, severity, confidence, category, file, title) in rows {
                    ui.label(rule);
                    ui.label(severity);
                    ui.label(confidence);
                    ui.label(category);
                    ui.label(file);
                    ui.label(title);
                    if ui
                        .selectable_label(self.selected_finding.as_deref() == Some(&id), "Inspect")
                        .clicked()
                    {
                        self.selected_finding = Some(id);
                        self.source_preview = None;
                    }
                    ui.end_row();
                }
            });
        if self.finding_filter.suppression == SuppressionFilter::Suppressed {
            ui.weak("Suppressed findings are not retained as active results; audit diagnostics are shown below.");
        }
        let selected = self
            .selected_finding
            .as_deref()
            .and_then(|id| {
                report
                    .findings
                    .iter()
                    .find(|finding| finding.finding_id == id)
            })
            .cloned();
        if let Some(finding) = selected {
            ui.separator();
            ui.heading(format!("{} — {}", finding.rule_id, finding.title));
            detail(ui, "Invariant", &finding.invariant);
            if let Some(taxonomy) = &finding.taxonomy {
                detail(
                    ui,
                    "Neutral taxonomy",
                    &format!(
                        "{} · {} · {}",
                        taxonomy.taxonomy_version, taxonomy.category_id, taxonomy.invariant_id
                    ),
                );
            }
            if let Some(cwe) = &finding.primary_cwe {
                detail(ui, "Primary CWE", &format!("{} · {}", cwe.id, cwe.url));
            }
            if let Some(provenance) = &finding.taxonomy_provenance {
                detail(
                    ui,
                    "Taxonomy provenance",
                    &format!(
                        "{} · commit {} · content {} · {}",
                        provenance.taxonomy_name,
                        provenance.source_commit,
                        provenance.content_hash,
                        provenance.mapping_basis
                    ),
                );
            }
            detail(ui, "Impact", &finding.impact);
            detail(ui, "Prerequisites", &finding.prerequisites.join("; "));
            detail(ui, "Remediation", &finding.remediation);
            detail(ui, "Verification", &finding.verification_state);
            detail(ui, "Limitations", &finding.limitations.join("; "));
            if let Some(fingerprint) = &finding.semantic_fingerprint {
                detail(ui, "Semantic fingerprint", fingerprint);
            }
            ui.strong("Ordered source-to-sink path");
            for (index, step) in finding.evidence_path.iter().enumerate() {
                ui.label(format!(
                    "{}. {} — {}:{}:{}",
                    index.saturating_add(1),
                    step.kind,
                    step.location.path,
                    step.location.span.start_line,
                    step.location.span.start_column
                ));
                if let Some(semantic) = &step.semantic {
                    ui.weak(format!(
                        "   {} · {}{}",
                        semantic.identity,
                        semantic.certainty,
                        semantic
                            .policy
                            .as_deref()
                            .map_or_else(String::new, |policy| format!(" · {policy}"))
                    ));
                }
            }
            if let Some(sink) = finding.sink.clone() {
                if ui
                    .add_enabled(
                        !self.source_loading,
                        egui::Button::new("Load safe source preview"),
                    )
                    .clicked()
                {
                    self.load_source(sink.clone());
                }
                ui.horizontal(|ui| {
                    ui.label("Suppression reason");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.suppression_reason)
                            .desired_width(360.0),
                    );
                    let valid_reason = self.suppression_reason.trim().chars().count() >= 8;
                    if ui
                        .add_enabled(
                            valid_reason && !self.scanning,
                            egui::Button::new("Suppress exactly and rescan"),
                        )
                        .clicked()
                    {
                        self.controls.suppressions.push(Suppression {
                            rule_id: finding.rule_id.clone(),
                            path: sink.path,
                            start_byte: sink.span.start_byte,
                            reason: self.suppression_reason.trim().to_owned(),
                        });
                        self.suppression_reason.clear();
                        self.start_scan();
                    }
                });
            }
            if self.source_loading {
                ui.spinner();
            }
            if let Some(preview) = &self.source_preview {
                ui.strong(format!(
                    "{} lines {}–{} (highlight {}:{}–{}:{})",
                    preview.path,
                    preview.first_line,
                    preview.last_line,
                    preview.highlight_start_line,
                    preview.highlight_start_column,
                    preview.highlight_end_line,
                    preview.highlight_end_column
                ));
                let mut text = preview.text.clone();
                ui.add(
                    egui::TextEdit::multiline(&mut text)
                        .code_editor()
                        .interactive(false)
                        .desired_rows(12),
                );
            }
        }
        if !report.suppression_diagnostics.is_empty() {
            ui.separator();
            ui.strong("Suppression audit");
            for diagnostic in &report.suppression_diagnostics {
                ui.label(format!(
                    "{} / {} — {}",
                    diagnostic.rule_id, diagnostic.code, diagnostic.message
                ));
            }
        }
    }

    fn architecture(&mut self, ui: &mut egui::Ui) {
        ui.heading("Architecture");
        let Some(report) = self.report.as_ref() else {
            ui.weak("Complete or reopen a scan to inspect the evidence graph.");
            return;
        };
        ui.label(format!(
            "{} nodes · {} edges",
            report.graph.nodes.len(),
            report.graph.edges.len()
        ));
        let relevant = self.selected_finding.as_deref().and_then(|id| {
            report
                .findings
                .iter()
                .find(|finding| finding.finding_id == id)
        });
        let node_ids = relevant.map(|finding| {
            finding
                .evidence_path
                .iter()
                .map(|step| step.node_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
        });
        ui.columns(2, |columns| {
            columns[0].strong("Relevant nodes");
            for node in report
                .graph
                .nodes
                .iter()
                .filter(|node| {
                    node_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(node.node_id.as_str()))
                })
                .take(250)
            {
                columns[0].label(format!(
                    "{} · {} · {}:{}",
                    node.kind,
                    node.name.as_deref().unwrap_or("unnamed"),
                    node.location.path,
                    node.location.span.start_line
                ));
            }
            columns[1].strong("Relevant edges");
            for edge in report
                .graph
                .edges
                .iter()
                .filter(|edge| {
                    node_ids.as_ref().is_none_or(|ids| {
                        ids.contains(edge.from_node.as_str()) || ids.contains(edge.to_node.as_str())
                    })
                })
                .take(400)
            {
                columns[1].label(format!(
                    "{} · {} → {}",
                    edge.kind, edge.from_node, edge.to_node
                ));
            }
        });
        for limitation in &report.limitations {
            ui.weak(format!("{} — {}", limitation.code, limitation.message));
        }
    }

    fn dependencies(&mut self, ui: &mut egui::Ui) {
        ui.heading("Dependencies and manifests");
        let Some(report) = self.report.as_ref() else {
            ui.weak("Complete or reopen a scan to inspect dependency evidence.");
            return;
        };
        ui.strong("Languages");
        for language in &report.languages {
            ui.label(format!(
                "{} — {} files, {} bytes",
                language.name, language.file_count, language.bytes
            ));
        }
        ui.separator();
        ui.strong("Manifests");
        for manifest in &report.manifests {
            ui.label(format!("{} — {}", manifest.kind, manifest.location.path));
        }
        ui.separator();
        ui.strong("Framework evidence");
        for framework in &report.frameworks {
            ui.label(format!("{} — {}", framework.name, framework.evidence.path));
        }
        ui.separator();
        ui.strong("Capabilities and trust boundaries");
        for capability in &report.capabilities {
            ui.label(format!(
                "{} — {} ({})",
                capability.capability, capability.reason, capability.evidence.path
            ));
        }
        for boundary in &report.trust_boundaries {
            ui.label(format!(
                "{} — {} ({})",
                boundary.kind, boundary.description, boundary.evidence.path
            ));
        }
    }

    fn history(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan History");
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.refresh_history();
            }
            ui.label(format!("Retention: {}", self.history_retention));
            if self.history_recovered > 0 {
                ui.label(format!(
                    "Recovered {} corrupt entries",
                    self.history_recovered
                ));
            }
        });
        if self.history.is_empty() {
            ui.weak("No completed local scans are stored.");
            return;
        }
        for scan in self.history.clone() {
            ui.group(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(&scan.display_name);
                    ui.label(format!(
                        "{} · {} findings · {}",
                        scan.saved_at, scan.findings, scan.scan_id
                    ));
                    ui.label(if scan.repository_available {
                        "repository available"
                    } else {
                        "repository moved or missing"
                    });
                    if !scan.taxonomy_versions.is_empty() {
                        ui.label(format!("taxonomy {}", scan.taxonomy_versions.join(", ")));
                    }
                    if ui
                        .add_enabled(!self.operation_busy, egui::Button::new("Reopen"))
                        .clicked()
                    {
                        self.open_history(scan.scan_id.clone());
                    }
                    if ui
                        .add_enabled(
                            !self.operation_busy && self.report.is_some(),
                            egui::Button::new("Compare"),
                        )
                        .clicked()
                    {
                        self.compare_history(scan.scan_id.clone());
                    }
                    if ui
                        .add_enabled(!self.operation_busy, egui::Button::new("Delete"))
                        .clicked()
                    {
                        self.delete_history(scan.scan_id.clone());
                    }
                });
            });
        }
        if let Some(comparison) = &self.comparison {
            ui.separator();
            ui.strong(format!(
                "Comparison: {} new, {} changed, {} resolved, {} unchanged",
                comparison.new.len(),
                comparison.changed.len(),
                comparison.resolved.len(),
                comparison.unchanged.len()
            ));
        }
    }

    #[allow(clippy::too_many_lines)]
    fn ai_validation(&mut self, ui: &mut egui::Ui) {
        ui.heading("Optional AI-assisted validation");
        ui.strong("Disabled by default · assessments never replace deterministic findings");
        ui.checkbox(
            &mut self.ai_enabled,
            "Enable AI validation controls for this session",
        );
        if !self.ai_enabled {
            self.ai_consent = false;
            ui.weak("No provider is configured or contacted while this switch is off.");
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label("Project AI configuration");
            ui.add(egui::TextEdit::singleline(&mut self.ai_config_path).desired_width(460.0));
            if ui
                .add_enabled(!self.ai_busy, egui::Button::new("Load configuration"))
                .clicked()
            {
                self.load_ai_configuration();
            }
        });
        if let Some(configuration) = &self.ai_configuration {
            egui::Grid::new("ai-configuration")
                .striped(true)
                .show(ui, |ui| {
                    summary_row(ui, "Provider", &configuration.provider);
                    summary_row(ui, "Model", &configuration.model);
                    summary_row(
                        ui,
                        "Request scope",
                        configuration.endpoint.as_deref().unwrap_or("offline"),
                    );
                    summary_row(
                        ui,
                        "Maximum output tokens",
                        &configuration.limits.max_output_tokens.to_string(),
                    );
                    summary_row(
                        ui,
                        "Maximum cost",
                        &configuration.limits.max_cost_microunits.map_or_else(
                            || "not configured".into(),
                            |value| format!("{value} microunits"),
                        ),
                    );
                    summary_row(
                        ui,
                        "Timeout",
                        &format!("{} seconds", configuration.limits.timeout_seconds),
                    );
                });
        }
        let mut budget_changed = false;
        if let Some(configuration) = self.ai_configuration.as_mut() {
            ui.horizontal_wrapped(|ui| {
                ui.label("Per-operation output token limit");
                budget_changed |= ui
                    .add(
                        egui::DragValue::new(&mut configuration.limits.max_output_tokens)
                            .range(1..=32_000),
                    )
                    .changed();
                ui.label("Timeout seconds");
                budget_changed |= ui
                    .add(
                        egui::DragValue::new(&mut configuration.limits.timeout_seconds)
                            .range(1..=600),
                    )
                    .changed();
                if let Some(maximum_cost) = configuration.limits.max_cost_microunits.as_mut() {
                    ui.label("Maximum cost microunits");
                    budget_changed |= ui
                        .add(egui::DragValue::new(maximum_cost).range(1..=u64::MAX))
                        .changed();
                } else {
                    ui.weak("No cost budget/pricing configured by the project");
                }
            });
        }
        if budget_changed {
            self.ai_preview = None;
            self.ai_assessment = None;
            self.ai_consent = false;
            self.status = "AI budget changed; prepare and consent to a new exact preview.".into();
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "Selected deterministic finding: {}",
                self.selected_finding.as_deref().unwrap_or("none")
            ));
            if ui
                .add_enabled(
                    !self.ai_busy
                        && self.report.is_some()
                        && self.selected_finding.is_some()
                        && self.ai_configuration.is_some(),
                    egui::Button::new("Prepare exact payload preview"),
                )
                .clicked()
            {
                self.prepare_ai_preview();
            }
        });
        if let Some(preview) = self.ai_preview.clone() {
            ui.separator();
            ui.heading("Exact redacted request preview");
            ui.label(format!(
                "{} / {} · {} approximate input tokens · {} redaction(s)",
                preview.provider,
                preview.model,
                preview.approximate_input_tokens,
                preview.redactions
            ));
            ui.label(format!("Endpoint scope: {}", preview.endpoint_scope));
            ui.label(format!(
                "Conservative cost bound: {}",
                preview.conservative_cost_bound_microunits.map_or_else(
                    || "not configured".into(),
                    |value| { format!("{value} microunits") }
                )
            ));
            ui.label(format!(
                "Payload fingerprint: {}",
                preview.payload_fingerprint
            ));
            let mut payload = serde_json::to_string_pretty(&preview.payload)
                .unwrap_or_else(|_| "Payload preview unavailable".into());
            ui.add(
                egui::TextEdit::multiline(&mut payload)
                    .code_editor()
                    .interactive(false)
                    .desired_rows(16),
            );
            ui.checkbox(
                &mut self.ai_consent,
                format!(
                    "I consent to exactly this request ({})",
                    preview.consent_fingerprint
                ),
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.ai_consent && !self.ai_busy,
                        egui::Button::new("Validate selected finding"),
                    )
                    .clicked()
                {
                    self.start_ai_validation();
                }
                if ui
                    .add_enabled(self.ai_busy, egui::Button::new("Cancel"))
                    .clicked()
                {
                    self.cancel_ai_validation();
                }
                if self.ai_busy {
                    ui.spinner();
                    ui.label("Bounded provider request in progress");
                }
            });
        }
        if let Some(assessment) = &self.ai_assessment {
            ui.separator();
            ui.heading("AI assessment (separate, uncertain evidence)");
            ui.label(format!(
                "Status: {:?} · evidence: {:?}",
                assessment.assessment.status, assessment.assessment.evidence_assessment
            ));
            detail(
                ui,
                "Confidence explanation",
                &assessment.assessment.confidence_explanation,
            );
            detail(
                ui,
                "Proposed remediation",
                &assessment.assessment.remediation_proposal,
            );
            detail(
                ui,
                "Verification suggestions",
                &assessment.assessment.verification_suggestions.join("; "),
            );
            detail(
                ui,
                "Limitations",
                &assessment.assessment.limitations.join("; "),
            );
            detail(ui, "Uncertainty", &assessment.assessment.uncertainty);
            ui.weak(format!(
                "Provenance: {} / {} · prompt {} · schema {} · cache {}",
                assessment.provider,
                assessment.model,
                assessment.prompt_version,
                assessment.schema_version,
                if assessment.cache_hit { "hit" } else { "miss" }
            ));
            if let Some(report) = &self.report
                && let Some(finding) = report
                    .findings
                    .iter()
                    .find(|finding| finding.finding_id == assessment.finding_id)
            {
                ui.strong("Deterministic evidence remains authoritative");
                detail(ui, "Severity", &finding.severity);
                detail(ui, "Confidence", &finding.confidence);
                detail(ui, "Invariant", &finding.invariant);
                detail(ui, "Fingerprint", &finding.fingerprint);
                if let Some(fingerprint) = &finding.semantic_fingerprint {
                    detail(ui, "Semantic fingerprint", fingerprint);
                }
            }
        }
        ui.separator();
        if ui
            .add_enabled(!self.ai_busy, egui::Button::new("Delete local AI data"))
            .clicked()
        {
            self.delete_local_ai_data();
        }
    }

    #[allow(clippy::too_many_lines)]
    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.horizontal(|ui| {
            ui.label("Text scale");
            if ui
                .add(egui::Slider::new(&mut self.text_scale, 0.8..=1.6))
                .changed()
            {
                self.context.set_pixels_per_point(self.text_scale);
            }
            ui.label("History retention");
            if ui
                .add(egui::DragValue::new(&mut self.history_retention).range(1..=10_000))
                .changed()
            {
                self.refresh_history();
            }
        });
        ui.label(format!(
            "Private history directory: {}",
            self.history_directory.display()
        ));
        ui.separator();
        ui.heading("Scan configuration");
        ui.add_enabled_ui(!self.scanning, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.controls.include_hidden, "Hidden files");
                ui.checkbox(
                    &mut self.controls.respect_ignore_files,
                    "Honor ignore files",
                );
                ui.checkbox(&mut self.controls.include_generated, "Generated/build");
                ui.checkbox(&mut self.controls.include_vendor, "Vendor dependencies");
                ui.checkbox(
                    &mut self.controls.include_nested_repositories,
                    "Nested repositories",
                );
                ui.checkbox(&mut self.controls.parse_cache_enabled, "Parse cache");
                ui.checkbox(
                    &mut self.controls.clear_cache_before_scan,
                    "Clear cache before scan",
                );
            });
            egui::Grid::new("resource-controls")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    number_control(
                        ui,
                        "Max files",
                        &mut self.controls.max_files,
                        1..=10_000_000,
                    );
                    ui.label("Max file bytes");
                    ui.add(
                        egui::DragValue::new(&mut self.controls.max_file_bytes)
                            .range(1..=1024_u64 * 1024 * 1024),
                    );
                    ui.end_row();
                    ui.label("Max total bytes");
                    ui.add(
                        egui::DragValue::new(&mut self.controls.max_total_bytes)
                            .range(1..=16_u64 * 1024 * 1024 * 1024 * 1024),
                    );
                    number_control(ui, "Max errors", &mut self.controls.max_errors, 1..=1000);
                    ui.end_row();
                    ui.label("Max cache bytes");
                    ui.add(
                        egui::DragValue::new(&mut self.controls.max_cache_bytes)
                            .range(1..=16_u64 * 1024 * 1024 * 1024),
                    );
                    number_control(
                        ui,
                        "Parser diagnostics",
                        &mut self.controls.max_parser_diagnostics,
                        1..=100_000,
                    );
                    ui.end_row();
                    number_control(
                        ui,
                        "Facts per file",
                        &mut self.controls.max_facts_per_file,
                        1..=100_000,
                    );
                    number_control(
                        ui,
                        "Total facts",
                        &mut self.controls.max_total_facts,
                        1..=10_000_000,
                    );
                    ui.end_row();
                    number_control(
                        ui,
                        "Graph nodes",
                        &mut self.controls.max_graph_nodes,
                        1..=10_000_000,
                    );
                    number_control(
                        ui,
                        "Graph edges",
                        &mut self.controls.max_graph_edges,
                        1..=20_000_000,
                    );
                    ui.end_row();
                    number_control(
                        ui,
                        "Call depth",
                        &mut self.controls.max_interprocedural_depth,
                        1..=32,
                    );
                    number_control(
                        ui,
                        "Max findings",
                        &mut self.controls.max_findings,
                        1..=1_000_000,
                    );
                    ui.end_row();
                    number_control(
                        ui,
                        "Max depth (0 unlimited)",
                        &mut self.max_depth_input,
                        0..=1024,
                    );
                    ui.end_row();
                });
            ui.horizontal(|ui| {
                ui.label("Cache directory (optional)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cache_directory_input)
                        .desired_width(420.0),
                );
            });
            ui.columns(2, |columns| {
                columns[0].label("Include globs — one per line");
                columns[0].add(
                    egui::TextEdit::multiline(&mut self.include_patterns_input).desired_rows(3),
                );
                columns[1].label("Exclude globs — one per line");
                columns[1].add(
                    egui::TextEdit::multiline(&mut self.exclude_patterns_input).desired_rows(3),
                );
            });
            ui.strong(format!(
                "Exact suppressions: {}",
                self.controls.suppressions.len()
            ));
            for suppression in &self.controls.suppressions {
                ui.label(format!(
                    "{} · {}:{} · {}",
                    suppression.rule_id,
                    suppression.path,
                    suppression.start_byte,
                    suppression.reason
                ));
            }
        });
    }

    fn status_bar(&mut self, root_ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show(root_ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::ProgressBar::new(self.progress).desired_width(170.0));
                ui.strong(format!("{}:", self.stage));
                ui.label(&self.status);
            });
        });
    }
}

impl eframe::App for SecureApp {
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_messages();
        self.keyboard_shortcuts(context);
        if self.scanning || self.operation_busy || self.source_loading {
            context.request_repaint_after(std::time::Duration::from_millis(80));
        }
    }

    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.toolbar(root_ui);
        self.navigation(root_ui);
        self.status_bar(root_ui);
        self.central(root_ui);
    }
}

impl Drop for SecureApp {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
    }
}

fn read_baseline_file(path: &Path) -> Result<Baseline, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Baseline could not be read".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 * 1024
    {
        return Err("Baseline must be a regular file no larger than 64 MiB".into());
    }
    let bytes = fs::read(path).map_err(|_| "Baseline could not be read".to_owned())?;
    let baseline = serde_json::from_slice::<Baseline>(&bytes)
        .map_err(|_| "Baseline is malformed".to_owned())?;
    secure_engine::validate_baseline(&baseline).map_err(|error| error.to_string())?;
    Ok(baseline)
}

fn read_recorded_ai_response(path: &Path) -> Result<serde_json::Value, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Recorded AI response could not be read".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err("Recorded AI response must be a regular file no larger than 1 MiB".into());
    }
    let bytes = fs::read(path).map_err(|_| "Recorded AI response could not be read".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|_| "Recorded AI response is malformed".into())
}

fn fraction(completed: usize, total: usize) -> f32 {
    let basis_points = completed
        .saturating_mul(10_000)
        .checked_div(total)
        .unwrap_or(0);
    f32::from(u16::try_from(basis_points).unwrap_or(10_000)) / 10_000.0
}

fn remember_project(projects: &mut Vec<PathBuf>, project: PathBuf) {
    projects.retain(|existing| existing != &project);
    projects.insert(0, project);
    projects.truncate(8);
}

fn summary_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.label(value);
    ui.end_row();
}

fn taxonomy_catalog_summary(catalog: &[secure_engine::TaxonomyDescriptor]) -> String {
    catalog
        .iter()
        .map(|taxonomy| format!("{} {}", taxonomy.taxonomy_name, taxonomy.taxonomy_version))
        .collect::<Vec<_>>()
        .join(", ")
}

fn detail(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.label(value);
}

fn number_control(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut usize,
    range: std::ops::RangeInclusive<usize>,
) {
    ui.label(label);
    ui.add(egui::DragValue::new(value).range(range));
}

fn parse_patterns(input: &str) -> Vec<String> {
    input
        .lines()
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .map(str::to_owned)
        .collect()
}

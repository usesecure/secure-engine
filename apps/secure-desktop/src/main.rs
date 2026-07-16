#![allow(missing_docs)]

use crossbeam_channel::{Receiver, Sender, TryRecvError, bounded};
use eframe::egui;
use secure_desktop::{InventoryControls, spawn_inventory_worker};
use secure_engine::{CancellationToken, ProgressEvent, ScanError, ScanReport};
use std::path::PathBuf;

fn main() -> eframe::Result {
    let initial_repository = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 720.0])
            .with_min_inner_size([640.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Secure Engine",
        options,
        Box::new(move |_creation_context| Ok(Box::new(SecureApp::new(initial_repository)))),
    )
}

enum WorkerMessage {
    Progress(ProgressEvent),
    Finished(Box<Result<ScanReport, ScanError>>),
}

struct SecureApp {
    repository_input: String,
    controls: InventoryControls,
    include_patterns_input: String,
    exclude_patterns_input: String,
    max_depth_input: usize,
    status: String,
    progress: f32,
    report: Option<ScanReport>,
    receiver: Option<Receiver<WorkerMessage>>,
    cancellation: Option<CancellationToken>,
}

impl SecureApp {
    fn new(repository_input: String) -> Self {
        Self {
            repository_input,
            controls: InventoryControls::default(),
            include_patterns_input: String::new(),
            exclude_patterns_input: String::new(),
            max_depth_input: 0,
            status: "Ready. Choose a local repository.".into(),
            progress: 0.0,
            report: None,
            receiver: None,
            cancellation: None,
        }
    }

    fn scanning(&self) -> bool {
        self.receiver.is_some()
    }

    fn start_scan(&mut self, context: &egui::Context) {
        let mut controls = self.controls.clone();
        controls.include_patterns = parse_patterns(&self.include_patterns_input);
        controls.exclude_patterns = parse_patterns(&self.exclude_patterns_input);
        controls.max_depth = (self.max_depth_input > 0).then_some(self.max_depth_input);
        let request = controls.request(PathBuf::from(self.repository_input.trim()));
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let (sender, receiver) = bounded(256);
        let repaint_context = context.clone();
        self.receiver = Some(receiver);
        self.cancellation = Some(cancellation);
        self.report = None;
        self.progress = 0.0;
        self.status = "Discovering repository files…".into();

        let progress_sender = sender.clone();
        let completion_sender = sender;
        let completion_context = repaint_context.clone();
        let _worker = spawn_inventory_worker(
            request,
            worker_cancellation,
            move |event| {
                let _ignored = progress_sender.try_send(WorkerMessage::Progress(event));
                repaint_context.request_repaint();
            },
            move |result| {
                send_finished(&completion_sender, result);
                completion_context.request_repaint();
            },
        );
    }

    fn cancel_scan(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
            self.status = "Cancelling…".into();
        }
    }

    fn receive_worker_messages(&mut self) {
        let Some(receiver) = self.receiver.take() else {
            return;
        };
        let mut keep_receiver = true;
        loop {
            match receiver.try_recv() {
                Ok(WorkerMessage::Progress(event)) => self.apply_progress(event),
                Ok(WorkerMessage::Finished(result)) => {
                    self.apply_result(*result);
                    keep_receiver = false;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.status = "Scan worker stopped unexpectedly".into();
                    self.cancellation = None;
                    keep_receiver = false;
                    break;
                }
            }
        }
        if keep_receiver {
            self.receiver = Some(receiver);
        }
    }

    fn apply_progress(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::Discovering => self.status = "Discovering repository files…".into(),
            ProgressEvent::DiscoveryProgress {
                entries_seen,
                candidate_files,
            } => {
                self.status =
                    format!("Discovery: {entries_seen} entries, {candidate_files} matching files");
            }
            ProgressEvent::Inspecting {
                completed,
                total,
                path,
            } => {
                let basis_points = completed
                    .saturating_mul(10_000)
                    .checked_div(total)
                    .unwrap_or(0);
                self.progress = f32::from(u16::try_from(basis_points).unwrap_or(10_000)) / 10_000.0;
                self.status = format!("Inventory {completed}/{total}: {path}");
            }
            ProgressEvent::Finalizing => self.status = "Finalizing deterministic report…".into(),
            ProgressEvent::Complete { files_scanned } => {
                self.progress = 1.0;
                self.status = format!("Complete: {files_scanned} files");
            }
        }
    }

    fn apply_result(&mut self, result: Result<ScanReport, ScanError>) {
        self.cancellation = None;
        match result {
            Ok(report) => {
                self.progress = 1.0;
                self.status = format!("Complete: {} files", report.scan.files_scanned);
                self.report = Some(report);
            }
            Err(ScanError::Cancelled) => {
                self.progress = 0.0;
                self.status = "Cancelled. No partial report was published.".into();
                self.report = None;
            }
            Err(error) => {
                self.progress = 0.0;
                self.status = error.to_string();
                self.report = None;
            }
        }
    }
}

impl eframe::App for SecureApp {
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_worker_messages();
        if self.scanning() {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    #[allow(clippy::too_many_lines)]
    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = root_ui.ctx().clone();
        egui::Panel::top("toolbar").show(root_ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Secure Engine");
                ui.separator();
                ui.label("Repository");
                ui.add_enabled(
                    !self.scanning(),
                    egui::TextEdit::singleline(&mut self.repository_input).desired_width(360.0),
                );
                if ui
                    .add_enabled(!self.scanning(), egui::Button::new("Scan"))
                    .clicked()
                {
                    self.start_scan(&context);
                }
                if ui
                    .add_enabled(self.scanning(), egui::Button::new("Cancel"))
                    .clicked()
                {
                    self.cancel_scan();
                }
            });
        });

        egui::CentralPanel::default().show(root_ui, |ui| {
            ui.heading("Deterministic repository inventory");
            ui.label(
                "Phase 1 inventories local repository evidence; it does not claim vulnerabilities.",
            );
            let controls_enabled = !self.scanning();
            ui.collapsing("Inventory controls", |ui| {
                ui.add_enabled_ui(controls_enabled, |ui| {
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
                    });
                    egui::Grid::new("resource-controls")
                        .num_columns(4)
                        .show(ui, |ui| {
                            ui.label("Max files");
                            ui.add(
                                egui::DragValue::new(&mut self.controls.max_files)
                                    .range(1..=10_000_000),
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
                            ui.label("Max errors");
                            ui.add(
                                egui::DragValue::new(&mut self.controls.max_errors).range(1..=1000),
                            );
                            ui.end_row();
                            ui.label("Max depth (0 = unlimited)");
                            ui.add(egui::DragValue::new(&mut self.max_depth_input).range(0..=1024));
                            ui.end_row();
                        });
                    ui.columns(2, |columns| {
                        columns[0].label("Include globs — one per line");
                        columns[0].add(
                            egui::TextEdit::multiline(&mut self.include_patterns_input)
                                .desired_rows(2),
                        );
                        columns[1].label("Exclude globs — one per line");
                        columns[1].add(
                            egui::TextEdit::multiline(&mut self.exclude_patterns_input)
                                .desired_rows(2),
                        );
                    });
                });
            });
            ui.add_space(8.0);
            if let Some(report) = &self.report {
                egui::Grid::new("summary").striped(true).show(ui, |ui| {
                    summary_row(ui, "Repository", &report.repository.name);
                    summary_row(ui, "Repository kind", &report.repository.repository_kind);
                    summary_row(ui, "Files", &report.scan.files_scanned.to_string());
                    summary_row(
                        ui,
                        "Candidate files",
                        &report.inventory.candidate_files.to_string(),
                    );
                    summary_row(
                        ui,
                        "Bytes scanned",
                        &report.inventory.bytes_scanned.to_string(),
                    );
                    summary_row(
                        ui,
                        "Text / binary",
                        &format!(
                            "{} / {}",
                            report.inventory.text_files, report.inventory.binary_files
                        ),
                    );
                    summary_row(
                        ui,
                        "Generated / vendor",
                        &format!(
                            "{} / {}",
                            report.inventory.generated_files, report.inventory.vendor_files
                        ),
                    );
                    summary_row(
                        ui,
                        "Symlinks skipped",
                        &report.inventory.symlinks_skipped.to_string(),
                    );
                    summary_row(
                        ui,
                        "Nested repositories skipped",
                        &report.inventory.nested_repositories_skipped.to_string(),
                    );
                    summary_row(
                        ui,
                        "Limits reached",
                        &format!(
                            "files: {}, bytes: {}",
                            report.inventory.hit_file_limit, report.inventory.hit_total_byte_limit
                        ),
                    );
                    summary_row(ui, "Languages", &report.languages.len().to_string());
                    summary_row(ui, "Manifests", &report.manifests.len().to_string());
                    summary_row(ui, "Framework hints", &report.frameworks.len().to_string());
                    summary_row(ui, "Entry points", &report.entry_points.len().to_string());
                    summary_row(ui, "Capabilities", &report.capabilities.len().to_string());
                    summary_row(
                        ui,
                        "Trust boundaries",
                        &report.trust_boundaries.len().to_string(),
                    );
                    summary_row(ui, "Findings", &report.findings.len().to_string());
                    summary_row(ui, "Skipped files", &report.skipped_files.len().to_string());
                    summary_row(ui, "Bounded errors", &report.errors.len().to_string());
                    summary_row(ui, "Schema", &report.schema_version);
                    summary_row(ui, "Report fingerprint", &report.report_fingerprint);
                });
                ui.add_space(12.0);
                ui.collapsing("Detected languages", |ui| {
                    for language in &report.languages {
                        ui.label(format!(
                            "{} — {} files, {} bytes",
                            language.name, language.file_count, language.bytes
                        ));
                    }
                });
                ui.collapsing("Capabilities and trust boundaries", |ui| {
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
                });
                ui.collapsing("Analysis limitations", |ui| {
                    for limitation in &report.limitations {
                        ui.label(format!("{} — {}", limitation.code, limitation.message));
                    }
                });
                ui.collapsing("Exclusions and skipped inputs", |ui| {
                    for exclusion in &report.exclusions {
                        ui.label(format!("{} — {}", exclusion.reason, exclusion.count));
                    }
                    for skipped in &report.skipped_files {
                        ui.label(format!("{} — {}", skipped.path, skipped.reason));
                    }
                });
            } else {
                ui.weak("No completed report yet.");
            }
        });

        egui::Panel::bottom("status").show(root_ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::ProgressBar::new(self.progress).desired_width(180.0));
                ui.label(&self.status);
            });
        });
    }
}

impl Drop for SecureApp {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
    }
}

fn send_finished(sender: &Sender<WorkerMessage>, result: Result<ScanReport, ScanError>) {
    let _ignored = sender.send(WorkerMessage::Finished(Box::new(result)));
}

fn summary_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.label(value);
    ui.end_row();
}

fn parse_patterns(input: &str) -> Vec<String> {
    input
        .lines()
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .map(str::to_owned)
        .collect()
}

#![allow(missing_docs)]

use std::path::PathBuf;
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError, bounded};
use eframe::egui;
use secure_desktop::inventory_repository;
use secure_engine::{CancellationToken, ProgressEvent, ScanError, ScanReport, ScanRequest};

fn main() -> eframe::Result {
    let initial_repository = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 620.0])
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
        let request = ScanRequest::new(PathBuf::from(self.repository_input.trim()));
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let (sender, receiver) = bounded(256);
        let repaint_context = context.clone();
        self.receiver = Some(receiver);
        self.cancellation = Some(cancellation);
        self.report = None;
        self.progress = 0.0;
        self.status = "Discovering repository files…".into();

        thread::spawn(move || {
            let progress_sender = sender.clone();
            let result = inventory_repository(&request, &worker_cancellation, |event| {
                let _ignored = progress_sender.try_send(WorkerMessage::Progress(event));
                repaint_context.request_repaint();
            });
            send_finished(&sender, result);
            repaint_context.request_repaint();
        });
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
                "Phase 0 reports evidence and limitations; it does not claim vulnerabilities.",
            );
            ui.add_space(8.0);
            if let Some(report) = &self.report {
                egui::Grid::new("summary").striped(true).show(ui, |ui| {
                    summary_row(ui, "Repository", &report.repository.name);
                    summary_row(ui, "Files", &report.scan.files_scanned.to_string());
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

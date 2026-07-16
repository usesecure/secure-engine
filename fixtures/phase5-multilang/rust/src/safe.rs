use axum::{Router, routing::post};
use std::process::Command;

fn routes() -> Router {
    Router::new().route("/safe", post(safe_command))
}

async fn safe_command(input: String) {
    if !authorized() {
        return;
    }
    let safe = allowlist(input);
    Command::new("tool").arg(safe).status();
}

unsafe fn raw_pointer_boundary(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

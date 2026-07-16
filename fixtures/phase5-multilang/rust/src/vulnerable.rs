use axum::{Router, routing::get};
use std::process::Command;

fn routes() -> Router {
    Router::new().route("/run", get(run_command))
}

async fn run_command(input: String) {
    Command::new("sh").arg("-c").arg(input).output();
    sqlx::query(input);
    std::fs::read(input);
    reqwest::get(input).await;
    axum::response::Redirect::to(input);
}

fn local_only(value: String) -> String {
    value.trim().to_owned()
}

fn crossLanguage(value: String) {
    std::process::Command::new("sh").arg("-c").arg(value).output();
}

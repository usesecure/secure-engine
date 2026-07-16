use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::CancellationToken;

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn write_atomic(
    target: &Path,
    bytes: &[u8],
    cancellation: &CancellationToken,
) -> io::Result<()> {
    check_cancelled(cancellation)?;
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    let name = target
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let temporary = temporary_path(parent, name);
    let result = (|| -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        for chunk in bytes.chunks(64 * 1024) {
            check_cancelled(cancellation)?;
            file.write_all(chunk)?;
        }
        check_cancelled(cancellation)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        check_cancelled(cancellation)?;
        fs::rename(&temporary, target)?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ignored = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn temporary_path(parent: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let sequence = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut temporary_name = OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(format!(".secure-tmp-{}-{sequence}", std::process::id()));
    parent.join(temporary_name)
}

fn check_cancelled(cancellation: &CancellationToken) -> io::Result<()> {
    if cancellation.is_cancelled() {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Ok(())
    }
}

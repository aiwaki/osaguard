use plist::Value;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::ptr;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItem, MenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::UpdaterExt;
#[cfg(target_os = "macos")]
use trash::{
    macos::{DeleteMethod, TrashContextExtMacos},
    TrashContext,
};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn osaguard_accessibility_trusted() -> libc::c_int;
    fn osaguard_request_accessibility() -> libc::c_int;
    fn osaguard_harden_process(error: *mut libc::c_char, error_len: usize) -> i32;
    fn osaguard_password_prompt_and_store(
        account: *const libc::c_char,
        locale: *const libc::c_char,
        error: *mut libc::c_char,
        error_len: usize,
    ) -> i32;
    fn osaguard_password_exists(
        account: *const libc::c_char,
        error: *mut libc::c_char,
        error_len: usize,
    ) -> i32;
    fn osaguard_password_delete_all(error: *mut libc::c_char, error_len: usize) -> i32;
    fn osaguard_auth_dialog_active(error: *mut libc::c_char, error_len: usize) -> i32;
    fn osaguard_watcher_run(
        account: *const libc::c_char,
        control_fd: i32,
        error: *mut libc::c_char,
        error_len: usize,
    ) -> i32;
    fn osaguard_integrity_state_get(error: *mut libc::c_char, error_len: usize) -> i32;
    fn osaguard_integrity_state_set(state: i32, error: *mut libc::c_char, error_len: usize) -> i32;
    fn osaguard_integrity_state_delete(error: *mut libc::c_char, error_len: usize) -> i32;
}

const INSTALLED_APP: &str = "/Applications/OsaGuard.app";
const LEGACY_WATCHER_LABEL: &str = "dev.aiwaki.osaguard.watcher";
const UPDATE_NOTIFICATION_SCHEMA: u32 = 1;
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const ACKNOWLEDGEMENT: &str = "I_UNDERSTAND_PASSWORDLESS_ADMIN";
const REMOVE_PASSWORD_CONFIRMATION: &str = "REMOVE_SAVED_PASSWORD";
const UNINSTALL_CONFIRMATION: &str = "UNINSTALL_OSAGUARD";
const INSTALL_UPDATE_CONFIRMATION: &str = "INSTALL_SIGNED_UPDATE";

const ID_OPEN: &str = "open";
const ID_TOGGLE: &str = "toggle";
const ID_PASSWORD: &str = "password";
const ID_UPDATE: &str = "update";
const ID_UNINSTALL: &str = "uninstall";
const ID_QUIT: &str = "quit";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Locale {
    En,
    Ru,
}

impl Locale {
    fn system() -> Self {
        let locale = sys_locale::get_locale().unwrap_or_else(|| "en".into());
        if locale.to_ascii_lowercase().starts_with("ru") {
            Self::Ru
        } else {
            Self::En
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
        }
    }

    fn state_install(self) -> &'static str {
        match self {
            Self::En => "Installation required",
            Self::Ru => "Нужна установка",
        }
    }

    fn state_setup(self) -> &'static str {
        match self {
            Self::En => "Setup required",
            Self::Ru => "Нужна настройка",
        }
    }

    fn state_ready(self) -> &'static str {
        match self {
            Self::En => "Ready · automatic confirmation is on",
            Self::Ru => "Готово · автоподтверждение включено",
        }
    }

    fn state_paused(self) -> &'static str {
        match self {
            Self::En => "Paused",
            Self::Ru => "Приостановлено",
        }
    }

    fn state_error(self) -> &'static str {
        match self {
            Self::En => "Status unavailable",
            Self::Ru => "Статус недоступен",
        }
    }

    fn open(self) -> &'static str {
        match self {
            Self::En => "Open OsaGuard…",
            Self::Ru => "Открыть OsaGuard…",
        }
    }

    fn pause(self) -> &'static str {
        match self {
            Self::En => "Pause automatic confirmation",
            Self::Ru => "Приостановить автоподтверждение",
        }
    }

    fn resume(self) -> &'static str {
        match self {
            Self::En => "Resume automatic confirmation",
            Self::Ru => "Возобновить автоподтверждение",
        }
    }

    fn save_password(self) -> &'static str {
        match self {
            Self::En => "Save administrator password…",
            Self::Ru => "Сохранить пароль администратора…",
        }
    }

    fn change_password(self) -> &'static str {
        match self {
            Self::En => "Change saved password…",
            Self::Ru => "Изменить сохранённый пароль…",
        }
    }

    fn resave_password(self) -> &'static str {
        match self {
            Self::En => "Re-save administrator password…",
            Self::Ru => "Сохранить пароль заново…",
        }
    }

    fn check_updates(self) -> &'static str {
        match self {
            Self::En => "Check for Updates…",
            Self::Ru => "Проверить обновления…",
        }
    }

    fn checking_updates(self) -> &'static str {
        match self {
            Self::En => "Checking for Updates…",
            Self::Ru => "Проверка обновлений…",
        }
    }

    fn updates_unavailable(self) -> &'static str {
        match self {
            Self::En => "Updates unavailable in this preview build",
            Self::Ru => "Обновления недоступны в этой preview-сборке",
        }
    }

    fn install_update(self, version: &str) -> String {
        match self {
            Self::En => format!("Install OsaGuard {version}…"),
            Self::Ru => format!("Установить OsaGuard {version}…"),
        }
    }

    fn installing_update(self) -> &'static str {
        match self {
            Self::En => "Installing Update…",
            Self::Ru => "Установка обновления…",
        }
    }

    fn uninstall(self) -> &'static str {
        match self {
            Self::En => "Uninstall OsaGuard…",
            Self::Ru => "Удалить OsaGuard…",
        }
    }

    fn update_notification_title(self) -> &'static str {
        match self {
            Self::En => "OsaGuard update available",
            Self::Ru => "Доступно обновление OsaGuard",
        }
    }

    fn update_notification_body(self, version: &str) -> String {
        match self {
            Self::En => format!(
                "OsaGuard {version} is ready. Open OsaGuard to review and install it."
            ),
            Self::Ru => format!(
                "OsaGuard {version} готов к установке. Откройте OsaGuard, чтобы проверить и установить его."
            ),
        }
    }

    fn quit(self) -> &'static str {
        match self {
            Self::En => "Quit OsaGuard",
            Self::Ru => "Выйти из OsaGuard",
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            Self::En => "OsaGuard — AppleScript administrator confirmation",
            Self::Ru => "OsaGuard — подтверждения администратора AppleScript",
        }
    }
}

#[derive(Clone, Debug)]
struct UserInfo {
    account: String,
    home: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupStatus {
    locale: String,
    version: String,
    installed: bool,
    accessibility_granted: bool,
    password_saved: bool,
    password_state: KeychainItemState,
    protected_state: KeychainItemState,
    risk_acknowledged: bool,
    configured: bool,
    enabled: bool,
    watcher_running: bool,
    automatic_active: bool,
    update_status: UpdateStatus,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallResult {
    outcome: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasswordActionResult {
    outcome: String,
    status: Option<SetupStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum UpdatePhase {
    Unconfigured,
    Idle,
    Checking,
    UpToDate,
    Available,
    Downloading,
    Ready,
    Installing,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateStatus {
    configured: bool,
    phase: UpdatePhase,
    version: Option<String>,
    error_code: Option<String>,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            configured: false,
            phase: UpdatePhase::Unconfigured,
            version: None,
            error_code: None,
        }
    }
}

impl UpdateStatus {
    fn configured(phase: UpdatePhase) -> Self {
        Self {
            configured: true,
            phase,
            version: None,
            error_code: None,
        }
    }

    fn available(phase: UpdatePhase, version: impl Into<String>) -> Self {
        Self {
            configured: true,
            phase,
            version: Some(version.into()),
            error_code: None,
        }
    }

    fn error(code: impl Into<String>, version: Option<String>) -> Self {
        Self {
            configured: true,
            phase: UpdatePhase::Error,
            version,
            error_code: Some(code.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct UpdateNotificationState {
    schema: u32,
    last_notified_version: Option<String>,
}

impl Default for UpdateNotificationState {
    fn default() -> Self {
        Self {
            schema: UPDATE_NOTIFICATION_SCHEMA,
            last_notified_version: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionErrorEvent {
    code: &'static str,
}

#[derive(Clone)]
struct MenuHandles {
    state: MenuItem<tauri::Wry>,
    toggle: MenuItem<tauri::Wry>,
    password: MenuItem<tauri::Wry>,
    update: MenuItem<tauri::Wry>,
    uninstall: MenuItem<tauri::Wry>,
}

const NATIVE_ERROR_CAPACITY: usize = 4096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ProtectedState {
    #[default]
    Missing,
    Paused,
    Enabled,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum KeychainItemState {
    #[default]
    Missing,
    Ready,
    NeedsReenrollment,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProtectedStateInspection {
    state: ProtectedState,
    item_state: KeychainItemState,
}

fn native_error(buffer: &[libc::c_char; NATIVE_ERROR_CAPACITY], fallback: &str) -> String {
    let detail = unsafe {
        // SAFETY: every native bridge call receives this zero-initialized fixed buffer and
        // leaves its final byte NUL. The buffer remains alive for this conversion.
        CStr::from_ptr(buffer.as_ptr())
    }
    .to_string_lossy();
    if detail.is_empty() {
        fallback.to_owned()
    } else {
        format!("{fallback}: {detail}")
    }
}

fn native_c_string(value: &str, label: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("{label} contains an embedded NUL byte"))
}

/// Apply process-wide native hardening before this process can ask for, read, or type a
/// password. The Go bridge makes this idempotent because the watcher also invokes it when
/// it is run outside the Tauri application.
fn harden_native_process() -> Result<(), String> {
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the writable error buffer remains valid for the native call.
        osaguard_harden_process(error.as_mut_ptr(), error.len())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(native_error(
            &error,
            "could not harden the OsaGuard process",
        ))
    }
}

fn password_prompt_and_store(account: &str, locale: &str) -> Result<&'static str, String> {
    let account = native_c_string(account, "account")?;
    let locale = native_c_string(locale, "locale")?;
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: both C strings and the writable error buffer remain valid for the full
        // blocking call. Password bytes are handled entirely inside the native bridge.
        osaguard_password_prompt_and_store(
            account.as_ptr(),
            locale.as_ptr(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    match result {
        0 => Ok("saved"),
        1 => Ok("cancelled"),
        _ => Err(native_error(
            &error,
            "could not save the administrator password",
        )),
    }
}

fn decode_password_state(result: i32) -> Result<KeychainItemState, String> {
    match result {
        0 => Ok(KeychainItemState::Missing),
        1 => Ok(KeychainItemState::Ready),
        2 => Ok(KeychainItemState::NeedsReenrollment),
        _ => Err("invalid password Keychain state".into()),
    }
}

fn password_state(account: &str) -> Result<KeychainItemState, String> {
    let account = native_c_string(account, "account")?;
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the C string and writable error buffer remain valid for the call.
        osaguard_password_exists(account.as_ptr(), error.as_mut_ptr(), error.len())
    };
    if result < 0 {
        Err(native_error(&error, "inspect saved password"))
    } else {
        decode_password_state(result)
    }
}

fn password_delete_all() -> Result<(), String> {
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the writable error buffer remains valid for the native call.
        osaguard_password_delete_all(error.as_mut_ptr(), error.len())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(native_error(
            &error,
            "could not remove saved OsaGuard passwords",
        ))
    }
}

fn decode_protected_state(result: i32) -> Result<ProtectedStateInspection, String> {
    match result {
        0 => Ok(ProtectedStateInspection {
            state: ProtectedState::Missing,
            item_state: KeychainItemState::Missing,
        }),
        1 => Ok(ProtectedStateInspection {
            state: ProtectedState::Paused,
            item_state: KeychainItemState::Ready,
        }),
        2 => Ok(ProtectedStateInspection {
            state: ProtectedState::Enabled,
            item_state: KeychainItemState::Ready,
        }),
        3 => Ok(ProtectedStateInspection {
            // Never infer acknowledgement or enabled state from an item whose
            // caller-only ACL belongs to a different application identity.
            state: ProtectedState::Missing,
            item_state: KeychainItemState::NeedsReenrollment,
        }),
        _ => Err("invalid protected Keychain state".into()),
    }
}

fn protected_state_inspection() -> Result<ProtectedStateInspection, String> {
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the writable error buffer remains valid for the call.
        osaguard_integrity_state_get(error.as_mut_ptr(), error.len())
    };
    if result < 0 {
        Err(native_error(&error, "read protected OsaGuard state"))
    } else {
        decode_protected_state(result)
    }
}

fn protected_state() -> Result<ProtectedState, String> {
    let inspection = protected_state_inspection()?;
    if inspection.item_state == KeychainItemState::NeedsReenrollment {
        Err("protected OsaGuard state belongs to a different application identity".into())
    } else {
        Ok(inspection.state)
    }
}

fn set_protected_state(state: ProtectedState) -> Result<(), String> {
    let value = match state {
        ProtectedState::Missing => return delete_protected_state(),
        ProtectedState::Paused => 1,
        ProtectedState::Enabled => 2,
    };
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the integer is a validated ABI enum and the writable error buffer
        // remains valid for the call.
        osaguard_integrity_state_set(value, error.as_mut_ptr(), error.len())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(native_error(&error, "write protected OsaGuard state"))
    }
}

fn delete_protected_state() -> Result<(), String> {
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the writable error buffer remains valid for the call.
        osaguard_integrity_state_delete(error.as_mut_ptr(), error.len())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(native_error(&error, "delete protected OsaGuard state"))
    }
}

fn run_native_watcher(account: CString, control: OwnedFd) -> Result<(), String> {
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the C string, owned read descriptor, and writable error buffer remain
        // alive for the complete blocking watcher call.
        osaguard_watcher_run(
            account.as_ptr(),
            control.as_raw_fd(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(native_error(&error, "automatic confirmation stopped"))
    }
}

#[derive(Default)]
struct WatcherProcess {
    control: Option<OwnedFd>,
    worker: Option<thread::JoinHandle<Result<(), String>>>,
}

impl WatcherProcess {
    fn take_finished(&mut self) -> Result<bool, String> {
        let Some(worker) = self.worker.as_ref() else {
            self.control.take();
            return Ok(false);
        };
        if !worker.is_finished() {
            return Ok(true);
        }
        self.control.take();
        let worker = self
            .worker
            .take()
            .expect("finished watcher worker disappeared");
        match worker.join() {
            Ok(Ok(())) => Ok(false),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("automatic confirmation worker panicked".into()),
        }
    }

    fn is_running(&mut self) -> Result<bool, String> {
        self.take_finished()
    }

    fn start(&mut self, account: &str) -> Result<(), String> {
        let account = native_c_string(account, "account")?;
        self.start_worker(move |control| run_native_watcher(account, control))
    }

    fn start_worker(
        &mut self,
        run: impl FnOnce(OwnedFd) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        if self.is_running()? {
            return Ok(());
        }
        let mut descriptors = [-1; 2];
        if unsafe {
            // SAFETY: descriptors points to storage for the two pipe descriptors.
            libc::pipe(descriptors.as_mut_ptr())
        } != 0
        {
            return Err(format!(
                "create automatic confirmation control pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let read = unsafe {
            // SAFETY: pipe returned two new owned file descriptors.
            OwnedFd::from_raw_fd(descriptors[0])
        };
        let write = unsafe {
            // SAFETY: pipe returned two new owned file descriptors.
            OwnedFd::from_raw_fd(descriptors[1])
        };
        for descriptor in [&read, &write] {
            if unsafe {
                // SAFETY: descriptor is live and owned for this call.
                libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC)
            } == -1
            {
                return Err(format!(
                    "protect automatic confirmation control pipe: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        let worker = thread::Builder::new()
            .name("osaguard-watcher".into())
            .spawn(move || run(read))
            .map_err(|error| format!("start automatic confirmation: {error}"))?;
        self.control = Some(write);
        self.worker = Some(worker);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.control.take();
        let Some(worker) = self.worker.as_ref() else {
            return Ok(());
        };
        for _ in 0..80 {
            if worker.is_finished() {
                return self.take_finished().map(|_| ());
            }
            thread::sleep(Duration::from_millis(25));
        }
        Err("automatic confirmation did not stop after cancellation".into())
    }
}

impl Drop for WatcherProcess {
    fn drop(&mut self) {
        self.control.take();
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            let _ = self.worker.take().and_then(|worker| worker.join().ok());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleOperation {
    Password,
    Update,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum LifecyclePhase {
    #[default]
    Running,
    Uninstalling,
    Exiting,
}

#[derive(Debug, Default)]
struct LifecycleState {
    phase: LifecyclePhase,
    operation: Option<LifecycleOperation>,
}

#[derive(Clone, Default)]
struct LifecycleCoordinator {
    state: Arc<Mutex<LifecycleState>>,
}

impl LifecycleCoordinator {
    fn try_begin(&self, operation: LifecycleOperation) -> Option<LifecyclePermit> {
        let mut state = self.state.lock().ok()?;
        if state.phase != LifecyclePhase::Running || state.operation.is_some() {
            return None;
        }
        state.operation = Some(operation);
        if operation == LifecycleOperation::Uninstall {
            state.phase = LifecyclePhase::Uninstalling;
        }
        Some(LifecyclePermit {
            coordinator: self.clone(),
            operation,
            committed_shutdown: false,
        })
    }

    fn begin_shutdown(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = LifecyclePhase::Exiting;
        }
    }

    fn is_running(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.phase == LifecyclePhase::Running)
            .unwrap_or(false)
    }
}

struct LifecyclePermit {
    coordinator: LifecycleCoordinator,
    operation: LifecycleOperation,
    committed_shutdown: bool,
}

impl LifecyclePermit {
    fn commit_shutdown(&mut self) {
        if let Ok(mut state) = self.coordinator.state.lock() {
            state.phase = LifecyclePhase::Exiting;
            state.operation = None;
        }
        self.committed_shutdown = true;
    }
}

impl Drop for LifecyclePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.coordinator.state.lock() {
            if state.operation == Some(self.operation) {
                state.operation = None;
            }
            if self.operation == LifecycleOperation::Uninstall
                && state.phase == LifecyclePhase::Uninstalling
                && !self.committed_shutdown
            {
                state.phase = LifecyclePhase::Running;
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
struct OperationGate {
    active: Arc<AtomicBool>,
}

#[cfg(test)]
impl OperationGate {
    fn try_enter(&self) -> Option<OperationPermit> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| OperationPermit {
                active: self.active.clone(),
            })
    }
}

#[cfg(test)]
struct OperationPermit {
    active: Arc<AtomicBool>,
}

#[cfg(test)]
impl Drop for OperationPermit {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[derive(Default)]
struct RuntimeState {
    menu: Mutex<Option<MenuHandles>>,
    update_status: Mutex<UpdateStatus>,
    lifecycle: LifecycleCoordinator,
    last_notified_version: Mutex<Option<String>>,
    watcher: Mutex<WatcherProcess>,
}

fn current_user() -> Result<UserInfo, String> {
    let uid = unsafe {
        // SAFETY: geteuid has no preconditions and returns the effective uid.
        libc::geteuid()
    };
    let mut capacity = 16 * 1024;
    loop {
        let mut record = unsafe {
            // SAFETY: passwd is a C record that may be initialized to zero before getpwuid_r.
            std::mem::zeroed::<libc::passwd>()
        };
        let mut result: *mut libc::passwd = ptr::null_mut();
        let mut buffer = vec![0_u8; capacity];
        let status = unsafe {
            // SAFETY: all pointers reference writable storage for the duration of the call.
            libc::getpwuid_r(
                uid,
                &mut record,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity *= 2;
            continue;
        }
        if status != 0 || result.is_null() || record.pw_name.is_null() || record.pw_dir.is_null() {
            return Err("could not resolve the current macOS user".into());
        }
        let account = unsafe {
            // SAFETY: getpwuid_r returned non-null NUL-terminated strings backed by buffer.
            CStr::from_ptr(record.pw_name)
        }
        .to_str()
        .map_err(|_| "current account name is not valid UTF-8")?
        .to_owned();
        let home = unsafe {
            // SAFETY: same lifetime and termination guarantee as pw_name above.
            CStr::from_ptr(record.pw_dir)
        }
        .to_str()
        .map_err(|_| "current home path is not valid UTF-8")?;
        let home = PathBuf::from(home);
        if account.is_empty() || !home.is_absolute() {
            return Err("macOS returned an invalid account record".into());
        }
        return Ok(UserInfo { account, home });
    }
}

fn app_support_dir(user: &UserInfo) -> PathBuf {
    user.home.join("Library/Application Support/OsaGuard")
}

fn update_notification_state_path(user: &UserInfo) -> PathBuf {
    app_support_dir(user).join("update-notifications.json")
}

fn launch_agent_path(user: &UserInfo) -> PathBuf {
    user.home
        .join("Library/LaunchAgents")
        .join(format!("{LEGACY_WATCHER_LABEL}.plist"))
}

fn read_update_notification_state(user: &UserInfo) -> Result<UpdateNotificationState, String> {
    let path = update_notification_state_path(user);
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UpdateNotificationState::default())
        }
        Err(error) => return Err(format!("read update notification state: {error}")),
    };
    if data.len() > 16 * 1024 {
        return Err("update notification state is unexpectedly large".into());
    }
    let state: UpdateNotificationState = serde_json::from_slice(&data)
        .map_err(|error| format!("parse update notification state: {error}"))?;
    if state.schema != UPDATE_NOTIFICATION_SCHEMA {
        return Err(format!(
            "unsupported update notification state schema {}",
            state.schema
        ));
    }
    Ok(state)
}

fn write_update_notification_state(
    user: &UserInfo,
    state: &UpdateNotificationState,
) -> Result<(), String> {
    let directory = app_support_dir(user);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create settings directory: {error}"))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect settings directory: {error}"))?;
    let mut data = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("encode update notification state: {error}"))?;
    data.push(b'\n');
    atomic_write(&update_notification_state_path(user), &data, 0o600)
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("destination has no parent directory")?;
    fs::create_dir_all(parent).map_err(|error| format!("create destination directory: {error}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("destination has an invalid file name")?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|error| format!("create temporary file: {error}"))?;
    let result = (|| {
        file.write_all(data)
            .map_err(|error| format!("write temporary file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync temporary file: {error}"))?;
        fs::rename(&temporary, path).map_err(|error| format!("replace destination: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn app_bundle_path(executable: &Path) -> Option<PathBuf> {
    executable.ancestors().find_map(|ancestor| {
        if ancestor.extension().and_then(|value| value.to_str()) != Some("app") {
            return None;
        }
        let macos = ancestor.join("Contents/MacOS");
        executable
            .starts_with(&macos)
            .then(|| ancestor.to_path_buf())
    })
}

fn installed_application_path(executable: &Path) -> bool {
    app_bundle_path(executable).as_deref() == Some(Path::new(INSTALLED_APP))
}

fn current_executable() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("resolve application executable: {error}"))
}

fn output_error(prefix: &str, output: &Output) -> String {
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    if detail.is_empty() {
        prefix.into()
    } else {
        let start = detail.len().saturating_sub(2048);
        format!("{prefix}: {}", &detail[start..])
    }
}

fn decode_accessibility_request_result(result: libc::c_int) -> Result<bool, String> {
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("could not create the Accessibility permission request".into()),
    }
}

#[cfg(target_os = "macos")]
fn accessibility_trusted_from_app_process() -> bool {
    (unsafe {
        // SAFETY: the C bridge takes no arguments, retains no state, and returns a bool-like int.
        osaguard_accessibility_trusted()
    }) == 1
}

#[cfg(not(target_os = "macos"))]
fn accessibility_trusted_from_app_process() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn request_accessibility_from_app_process() -> Result<bool, String> {
    let result = unsafe {
        // SAFETY: the C bridge takes no arguments, retains no Rust-owned data,
        // and returns a small integer status after releasing its CF dictionary.
        osaguard_request_accessibility()
    };
    decode_accessibility_request_result(result)
}

#[cfg(not(target_os = "macos"))]
fn request_accessibility_from_app_process() -> Result<bool, String> {
    Err("Accessibility permission is only available on macOS".into())
}

fn uid() -> u32 {
    unsafe {
        // SAFETY: geteuid has no preconditions and does not retain pointers.
        libc::geteuid()
    }
}

fn legacy_launchd_service() -> String {
    format!("gui/{}/{LEGACY_WATCHER_LABEL}", uid())
}

fn launchctl(arguments: &[&str]) -> Result<Output, String> {
    Command::new("/bin/launchctl")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("run launchctl: {error}"))
}

fn launchctl_ok(arguments: &[&str], prefix: &str) -> Result<(), String> {
    let output = launchctl(arguments)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(output_error(prefix, &output))
    }
}

fn legacy_watcher_loaded() -> bool {
    launchctl(&["print", &legacy_launchd_service()])
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn cleanup_legacy_launch_agent(user: &UserInfo) -> Result<(), String> {
    if legacy_watcher_loaded() {
        launchctl_ok(
            &["bootout", &legacy_launchd_service()],
            "could not stop the obsolete OsaGuard watcher",
        )?;
    }
    let path = launch_agent_path(user);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {
            Err("the obsolete OsaGuard watcher path is unexpectedly a directory".into())
        }
        Ok(_) => fs::remove_file(&path)
            .map_err(|error| format!("remove obsolete OsaGuard watcher: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspect obsolete OsaGuard watcher: {error}")),
    }
}

fn watcher_running(app: &AppHandle) -> Result<bool, String> {
    app.state::<RuntimeState>()
        .watcher
        .lock()
        .map_err(|_| "automatic confirmation process state is unavailable".to_owned())?
        .is_running()
}

fn start_watcher(app: &AppHandle, user: &UserInfo) -> Result<(), String> {
    cleanup_legacy_launch_agent(user)?;
    let executable = current_executable()?;
    if !installed_application_path(&executable) {
        return Err("OsaGuard must be installed in /Applications first".into());
    }
    app.state::<RuntimeState>()
        .watcher
        .lock()
        .map_err(|_| "automatic confirmation process state is unavailable".to_owned())?
        .start(&user.account)
}

fn stop_watcher(app: &AppHandle) -> Result<(), String> {
    app.state::<RuntimeState>()
        .watcher
        .lock()
        .map_err(|_| "automatic confirmation process state is unavailable".to_owned())?
        .stop()
}

fn stop_all_watchers(app: &AppHandle, user: &UserInfo) -> Result<(), String> {
    let stop_result = stop_watcher(app);
    let cleanup_result = cleanup_legacy_launch_agent(user);
    stop_result.and(cleanup_result)
}

fn updater_configured(app: &AppHandle) -> bool {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|value| value.as_object())
        .is_some_and(|config| {
            config
                .get("pubkey")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
                && config
                    .get("endpoints")
                    .and_then(|value| value.as_array())
                    .is_some_and(|value| !value.is_empty())
        })
}

fn current_update_status(app: &AppHandle) -> UpdateStatus {
    app.state::<RuntimeState>()
        .update_status
        .lock()
        .map(|status| status.clone())
        .unwrap_or_else(|_| UpdateStatus::error("state_unavailable", None))
}

fn set_update_status(app: &AppHandle, status: UpdateStatus) {
    if let Ok(mut current) = app.state::<RuntimeState>().update_status.lock() {
        *current = status;
    }
    refresh_menu(app);
}

fn compute_status(app: &AppHandle) -> Result<SetupStatus, String> {
    let locale = Locale::system();
    let executable = current_executable()?;
    let installed = installed_application_path(&executable);
    let accessibility_granted = accessibility_trusted_from_app_process();
    let (password_state, protected_item_state, risk_acknowledged, enabled, watcher_running) =
        if installed {
            let user = current_user()?;
            let password_state = password_state(&user.account)?;
            let protected = protected_state_inspection()?;
            (
                password_state,
                protected.item_state,
                protected.item_state == KeychainItemState::Ready
                    && protected.state != ProtectedState::Missing,
                protected.item_state == KeychainItemState::Ready
                    && protected.state == ProtectedState::Enabled,
                watcher_running(app)?,
            )
        } else {
            // A copy launched from a DMG or a build directory must not inspect Keychain
            // state or discover a watcher owned by the installed application.
            (
                KeychainItemState::Missing,
                KeychainItemState::Missing,
                false,
                false,
                false,
            )
        };
    let password_saved = password_state == KeychainItemState::Ready;
    let configured = installed && accessibility_granted && password_saved && risk_acknowledged;
    let update_status = current_update_status(app);
    Ok(SetupStatus {
        locale: locale.code().into(),
        version: app.package_info().version.to_string(),
        installed,
        accessibility_granted,
        password_saved,
        password_state,
        protected_state: protected_item_state,
        risk_acknowledged,
        configured,
        enabled,
        watcher_running,
        automatic_active: configured && enabled && watcher_running,
        update_status,
    })
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn show_action_error(app: &AppHandle, event: &str, code: &'static str) {
    show_main_window(app);
    let _ = app.emit(event, ActionErrorEvent { code });
}

fn refresh_menu(app: &AppHandle) {
    let locale = Locale::system();
    let status = compute_status(app);
    let state = app.state::<RuntimeState>();
    let handles = match state.menu.lock() {
        Ok(handles) => handles.clone(),
        Err(_) => None,
    };
    let Some(handles) = handles else {
        return;
    };
    let label = match &status {
        Ok(status) if !status.installed => locale.state_install(),
        Ok(status) if !status.configured => locale.state_setup(),
        Ok(status) if status.automatic_active => locale.state_ready(),
        Ok(_) => locale.state_paused(),
        Err(_) => locale.state_error(),
    };
    let _ = handles.state.set_text(label);
    let active = status
        .as_ref()
        .map(|status| status.automatic_active)
        .unwrap_or(false);
    let configured = status
        .as_ref()
        .map(|status| status.configured)
        .unwrap_or(false);
    let _ = handles.toggle.set_text(if active {
        locale.pause()
    } else {
        locale.resume()
    });
    let _ = handles.toggle.set_enabled(configured);
    let password_enabled = status
        .as_ref()
        .map(|status| status.installed && status.accessibility_granted)
        .unwrap_or(false);
    let password_state = status
        .as_ref()
        .map(|status| status.password_state)
        .unwrap_or(KeychainItemState::Missing);
    let _ = handles.password.set_text(match password_state {
        KeychainItemState::Ready => locale.change_password(),
        KeychainItemState::NeedsReenrollment => locale.resave_password(),
        KeychainItemState::Missing => locale.save_password(),
    });
    let _ = handles.password.set_enabled(password_enabled);

    let update_status = status
        .as_ref()
        .map(|status| status.update_status.clone())
        .unwrap_or_else(|_| UpdateStatus::error("state_unavailable", None));
    let installed = status
        .as_ref()
        .map(|status| status.installed)
        .unwrap_or(false);
    let (update_label, mut update_enabled) = match update_status.phase {
        UpdatePhase::Unconfigured => (locale.updates_unavailable().to_owned(), false),
        UpdatePhase::Checking | UpdatePhase::Downloading => {
            (locale.checking_updates().to_owned(), false)
        }
        UpdatePhase::Installing => (locale.installing_update().to_owned(), false),
        UpdatePhase::Available | UpdatePhase::Ready => (
            update_status
                .version
                .as_deref()
                .map(|version| locale.install_update(version))
                .unwrap_or_else(|| locale.check_updates().to_owned()),
            true,
        ),
        _ => (locale.check_updates().to_owned(), update_status.configured),
    };
    update_enabled &= installed;
    let _ = handles.update.set_text(update_label);
    let _ = handles.update.set_enabled(update_enabled);
    let uninstall_enabled = status
        .as_ref()
        .map(|status| status.installed)
        .unwrap_or(false);
    let _ = handles.uninstall.set_enabled(uninstall_enabled);
}

fn set_enabled_inner(app: &AppHandle, enabled: bool) -> Result<SetupStatus, String> {
    let user = current_user()?;
    let previous = protected_state()?;
    if enabled {
        let status = compute_status(app)?;
        if !status.installed {
            return Err("install OsaGuard in /Applications before enabling it".into());
        }
        if !status.accessibility_granted {
            return Err("Accessibility permission is not granted".into());
        }
        if !status.password_saved {
            return Err("no administrator password is saved".into());
        }
        if previous == ProtectedState::Missing {
            return Err("the automatic-mode security warning has not been acknowledged".into());
        }
        let autostart_was_enabled = app
            .autolaunch()
            .is_enabled()
            .map_err(|error| format!("inspect OsaGuard login item: {error}"))?;
        if !autostart_was_enabled {
            app.autolaunch()
                .enable()
                .map_err(|error| format!("enable OsaGuard at login: {error}"))?;
        }
        if let Err(error) = start_watcher(app, &user) {
            if !autostart_was_enabled {
                let _ = app.autolaunch().disable();
            }
            return Err(error);
        }
        if let Err(error) = set_protected_state(ProtectedState::Enabled) {
            let _ = stop_all_watchers(app, &user);
            if !autostart_was_enabled {
                let _ = app.autolaunch().disable();
            }
            let _ = set_protected_state(previous);
            return Err(error);
        }
    } else {
        stop_all_watchers(app, &user)?;
        let paused = if previous == ProtectedState::Missing {
            ProtectedState::Missing
        } else {
            ProtectedState::Paused
        };
        if let Err(error) = set_protected_state(paused) {
            if previous == ProtectedState::Enabled {
                let _ = start_watcher(app, &user);
            }
            return Err(error);
        }
    }
    refresh_menu(app);
    compute_status(app)
}

#[tauri::command]
fn get_status(app: AppHandle) -> Result<SetupStatus, String> {
    compute_status(&app)
}

#[tauri::command]
async fn request_accessibility(app: AppHandle) -> Result<SetupStatus, String> {
    request_accessibility_from_app_process()?;
    thread::sleep(Duration::from_millis(250));
    refresh_menu(&app);
    compute_status(&app)
}

#[tauri::command]
fn open_accessibility_settings() -> Result<(), String> {
    Command::new("/usr/bin/open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("open Accessibility settings: {error}"))
}

async fn store_password_inner(app: AppHandle) -> Result<PasswordActionResult, String> {
    let lifecycle = app.state::<RuntimeState>().lifecycle.clone();
    let Some(_permit) = lifecycle.try_begin(LifecycleOperation::Password) else {
        return Ok(PasswordActionResult {
            outcome: "already_open".into(),
            status: compute_status(&app).ok(),
        });
    };
    let initial = compute_status(&app)?;
    if !initial.installed {
        return Err("install OsaGuard in /Applications before saving a password".into());
    }
    if !initial.accessibility_granted {
        return Err("Accessibility permission is required before saving a password".into());
    }
    let locale = Locale::system().code();
    let user = current_user()?;
    let account = user.account;
    let task =
        tauri::async_runtime::spawn_blocking(move || password_prompt_and_store(&account, locale));
    let outcome = task
        .await
        .map_err(|error| format!("password dialog task failed: {error}"))??;
    refresh_menu(&app);
    Ok(PasswordActionResult {
        outcome: outcome.into(),
        status: compute_status(&app).ok(),
    })
}

#[tauri::command]
async fn store_password(app: AppHandle) -> Result<PasswordActionResult, String> {
    store_password_inner(app).await
}

#[tauri::command]
fn forget_password(app: AppHandle, confirmation: String) -> Result<SetupStatus, String> {
    if confirmation != REMOVE_PASSWORD_CONFIRMATION {
        return Err("password removal was not explicitly confirmed".into());
    }
    let lifecycle = app.state::<RuntimeState>().lifecycle.clone();
    let Some(_permit) = lifecycle.try_begin(LifecycleOperation::Password) else {
        return Err("OsaGuard is busy with another protected operation".into());
    };
    let user = current_user()?;
    let previous = protected_state()?;
    let should_restore = previous == ProtectedState::Enabled;
    stop_all_watchers(&app, &user)?;
    let paused = if previous == ProtectedState::Missing {
        ProtectedState::Missing
    } else {
        ProtectedState::Paused
    };
    if let Err(error) = set_protected_state(paused) {
        let _ = restore_watcher(&app, &user, should_restore);
        return Err(error);
    }
    if let Err(error) = password_delete_all() {
        let _ = set_protected_state(previous);
        let _ = restore_watcher(&app, &user, should_restore);
        return Err(error);
    }
    refresh_menu(&app);
    compute_status(&app)
}

#[tauri::command]
fn enable_automatic(app: AppHandle, acknowledgement: String) -> Result<SetupStatus, String> {
    if acknowledgement != ACKNOWLEDGEMENT {
        return Err("automatic mode was not explicitly acknowledged".into());
    }
    let protected = protected_state_inspection()?;
    if protected.item_state != KeychainItemState::Ready
        || protected.state == ProtectedState::Missing
    {
        set_protected_state(ProtectedState::Paused)?;
    }
    set_enabled_inner(&app, true)
}

#[tauri::command]
fn set_enabled(app: AppHandle, enabled: bool) -> Result<SetupStatus, String> {
    set_enabled_inner(&app, enabled)
}

fn verify_bundle(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect application bundle: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("application bundle must be a real directory, not a symbolic link".into());
    }
    let info = Value::from_file(path.join("Contents/Info.plist"))
        .map_err(|error| format!("read application Info.plist: {error}"))?;
    let identifier = info
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("CFBundleIdentifier"))
        .and_then(Value::as_string);
    if identifier != Some("dev.aiwaki.osaguard") {
        return Err("application bundle has an unexpected identifier".into());
    }
    let output = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("verify application signature: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(output_error(
            "application signature verification failed",
            &output,
        ))
    }
}

fn parse_bundle_version(value: &str) -> Result<[u64; 3], String> {
    let parts = value
        .split('.')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("application version must contain three numeric components".into());
            }
            part.parse::<u64>()
                .map_err(|_| "application version component is too large".to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    parts
        .try_into()
        .map_err(|_| "application version must contain three numeric components".into())
}

fn bundle_version(path: &Path) -> Result<[u64; 3], String> {
    let info = Value::from_file(path.join("Contents/Info.plist"))
        .map_err(|error| format!("read application Info.plist: {error}"))?;
    let version = info
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("CFBundleShortVersionString"))
        .and_then(Value::as_string)
        .ok_or("application bundle has no short version")?;
    parse_bundle_version(version)
}

fn schedule_open_application(path: &Path) -> Result<(), String> {
    Command::new("/bin/sh")
        .args([
            "-c",
            "/bin/sleep 1; exec /usr/bin/open -n \"$1\"",
            "osaguard-relaunch",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("schedule installed application relaunch: {error}"))
}

#[cfg(target_os = "macos")]
fn move_replaced_bundle_to_trash(path: &Path) -> Result<(), String> {
    let mut context = TrashContext::new();
    context.set_delete_method(DeleteMethod::NsFileManager);
    context
        .delete(path)
        .map_err(|error| format!("move replaced OsaGuard to Trash: {error}"))
}

#[cfg(not(target_os = "macos"))]
fn move_replaced_bundle_to_trash(_path: &Path) -> Result<(), String> {
    Err("application replacement is only available on macOS".into())
}

fn install_application_bundle() -> Result<InstallResult, String> {
    let executable = current_executable()?;
    if installed_application_path(&executable) {
        return Ok(InstallResult {
            outcome: "already_installed".into(),
        });
    }
    let source = app_bundle_path(&executable)
        .ok_or("installation is available only from a packaged OsaGuard.app")?;
    verify_bundle(&source)?;
    let source_version = bundle_version(&source)?;
    let destination = Path::new(INSTALLED_APP);
    let replacing = if destination.exists() {
        verify_bundle(destination)?;
        if source_version <= bundle_version(destination)? {
            schedule_open_application(destination)?;
            return Ok(InstallResult {
                outcome: "opened_existing".into(),
            });
        }
        true
    } else {
        false
    };
    let temporary = PathBuf::from(format!(
        "/Applications/.OsaGuard-installing-{}.app",
        std::process::id()
    ));
    if temporary.exists() {
        return Err("a previous OsaGuard installation is still in progress".into());
    }
    let output = Command::new("/usr/bin/ditto")
        .args(["--rsrc", "--extattr"])
        .arg(&source)
        .arg(&temporary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("copy OsaGuard to Applications: {error}"))?;
    if !output.status.success() {
        let _ = fs::remove_dir_all(&temporary);
        return Err(output_error("copy OsaGuard to Applications", &output));
    }
    if let Err(error) = verify_bundle(&temporary) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    if replacing {
        let backup = PathBuf::from(format!(
            "/Applications/.OsaGuard-replaced-{}.app",
            std::process::id()
        ));
        if backup.exists() {
            let _ = fs::remove_dir_all(&temporary);
            return Err("a previous OsaGuard replacement is still in progress".into());
        }
        if let Err(error) = fs::rename(destination, &backup) {
            let _ = fs::remove_dir_all(&temporary);
            return Err(format!("stage installed OsaGuard for replacement: {error}"));
        }
        if let Err(error) = fs::rename(&temporary, destination) {
            let restore = fs::rename(&backup, destination);
            let _ = fs::remove_dir_all(&temporary);
            return match restore {
                Ok(()) => Err(format!("finish OsaGuard replacement: {error}")),
                Err(restore_error) => Err(format!(
                    "finish OsaGuard replacement: {error}; restore previous OsaGuard: {restore_error}"
                )),
            };
        }
        if let Err(error) = schedule_open_application(destination) {
            let displaced = fs::rename(destination, &temporary);
            let restored = fs::rename(&backup, destination);
            let _ = fs::remove_dir_all(&temporary);
            return match (displaced, restored) {
                (Ok(()), Ok(())) => Err(error),
                (displaced, restored) => Err(format!(
                    "{error}; replacement rollback failed (new: {displaced:?}, previous: {restored:?})"
                )),
            };
        }
        if let Err(error) = move_replaced_bundle_to_trash(&backup) {
            eprintln!(
                "OsaGuard replacement succeeded but its recoverable backup remains at {}: {error}",
                backup.display()
            );
        }
        return Ok(InstallResult {
            outcome: "updated".into(),
        });
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(format!("finish OsaGuard installation: {error}"));
    }
    if let Err(error) = schedule_open_application(destination) {
        let cleanup = fs::remove_dir_all(destination);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; remove incomplete OsaGuard installation: {cleanup_error}"
            )),
        };
    }
    Ok(InstallResult {
        outcome: "installed".into(),
    })
}

#[tauri::command]
async fn install_app(app: AppHandle) -> Result<InstallResult, String> {
    let task = tauri::async_runtime::spawn_blocking(install_application_bundle);
    let result = task
        .await
        .map_err(|error| format!("installation task failed: {error}"))??;
    if matches!(
        result.outcome.as_str(),
        "installed" | "updated" | "opened_existing"
    ) {
        let app = app.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(250));
            app.exit(0);
        });
    }
    Ok(result)
}

fn reset_accessibility_permission() -> Result<(), String> {
    let output = Command::new("/usr/bin/tccutil")
        .args(["reset", "Accessibility", "dev.aiwaki.osaguard"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("reset Accessibility permission: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(output_error("reset Accessibility permission", &output))
    }
}

#[derive(Clone, Debug)]
struct SupportFileSnapshot {
    name: String,
    data: Vec<u8>,
    mode: u32,
}

#[derive(Clone, Debug)]
struct SupportRemovalPlan {
    original: PathBuf,
    staged: PathBuf,
    existed: bool,
    files: Vec<SupportFileSnapshot>,
}

fn plan_support_removal(user: &UserInfo) -> Result<SupportRemovalPlan, String> {
    let original = app_support_dir(user);
    let staged = original.with_file_name(format!(".OsaGuard-uninstalling-{}", std::process::id()));
    if staged.exists() {
        return Err("a previous OsaGuard settings cleanup is still in progress".into());
    }
    let metadata = match fs::symlink_metadata(&original) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SupportRemovalPlan {
                original,
                staged,
                existed: false,
                files: Vec::new(),
            })
        }
        Err(error) => return Err(format!("inspect OsaGuard settings: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("OsaGuard settings path is not a real directory".into());
    }
    let mut files = Vec::new();
    let mut total_size = 0_u64;
    for entry in
        fs::read_dir(&original).map_err(|error| format!("inspect OsaGuard settings: {error}"))?
    {
        let entry = entry.map_err(|error| format!("inspect OsaGuard settings: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "OsaGuard settings contain an invalid file name")?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("inspect OsaGuard settings file: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("OsaGuard settings contain an unexpected non-file entry".into());
        }
        total_size = total_size
            .checked_add(metadata.len())
            .ok_or("OsaGuard settings size overflow")?;
        if total_size > 256 * 1024 {
            return Err("OsaGuard settings are unexpectedly large".into());
        }
        let data = fs::read(entry.path())
            .map_err(|error| format!("back up OsaGuard settings before uninstall: {error}"))?;
        files.push(SupportFileSnapshot {
            name,
            data,
            mode: metadata.permissions().mode() & 0o777,
        });
    }
    Ok(SupportRemovalPlan {
        original,
        staged,
        existed: true,
        files,
    })
}

fn stage_support_removal(plan: &SupportRemovalPlan) -> Result<(), String> {
    if plan.existed {
        fs::rename(&plan.original, &plan.staged)
            .map_err(|error| format!("stage OsaGuard settings removal: {error}"))?;
    }
    Ok(())
}

fn restore_support(plan: &SupportRemovalPlan) -> Result<(), String> {
    if !plan.existed {
        return Ok(());
    }
    if plan.staged.exists() && !plan.original.exists() {
        fs::rename(&plan.staged, &plan.original)
            .map_err(|error| format!("restore OsaGuard settings: {error}"))?;
    }
    fs::create_dir_all(&plan.original)
        .map_err(|error| format!("recreate OsaGuard settings: {error}"))?;
    fs::set_permissions(&plan.original, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect restored OsaGuard settings: {error}"))?;
    for file in &plan.files {
        atomic_write(&plan.original.join(&file.name), &file.data, file.mode)?;
    }
    let _ = fs::remove_dir_all(&plan.staged);
    Ok(())
}

fn finish_support_removal(plan: &SupportRemovalPlan) -> Result<(), String> {
    if plan.existed {
        fs::remove_dir_all(&plan.staged)
            .map_err(|error| format!("remove OsaGuard settings: {error}"))?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct TrashMovePlan {
    trash_directory: PathBuf,
    source_device: u64,
    source_inode: u64,
}

fn plan_trash_move(user: &UserInfo) -> Result<TrashMovePlan, String> {
    let source = fs::symlink_metadata(INSTALLED_APP)
        .map_err(|error| format!("inspect installed app before uninstall: {error}"))?;
    if source.file_type().is_symlink() || !source.is_dir() {
        return Err("installed OsaGuard bundle is not a real directory".into());
    }
    let trash_directory = user.home.join(".Trash");
    let trash = fs::symlink_metadata(&trash_directory)
        .map_err(|error| format!("inspect macOS Trash: {error}"))?;
    if trash.file_type().is_symlink() || !trash.is_dir() {
        return Err("macOS Trash path is not a real directory".into());
    }
    Ok(TrashMovePlan {
        trash_directory,
        source_device: source.dev(),
        source_inode: source.ino(),
    })
}

fn find_trashed_app(plan: &TrashMovePlan) -> Result<PathBuf, String> {
    for entry in fs::read_dir(&plan.trash_directory)
        .map_err(|error| format!("inspect macOS Trash after uninstall: {error}"))?
    {
        let entry = entry.map_err(|error| format!("inspect macOS Trash entry: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("inspect trashed OsaGuard bundle: {error}"))?;
        if metadata.dev() == plan.source_device && metadata.ino() == plan.source_inode {
            return Ok(entry.path());
        }
    }
    Err("could not locate OsaGuard in the Trash after moving it".into())
}

#[cfg(target_os = "macos")]
fn move_installed_app_to_trash(plan: &TrashMovePlan) -> Result<PathBuf, String> {
    let mut context = TrashContext::new();
    context.set_delete_method(DeleteMethod::NsFileManager);
    context
        .delete(Path::new(INSTALLED_APP))
        .map_err(|error| format!("move OsaGuard to Trash: {error}"))?;
    find_trashed_app(plan)
}

#[cfg(not(target_os = "macos"))]
fn move_installed_app_to_trash(_plan: &TrashMovePlan) -> Result<PathBuf, String> {
    Err("uninstallation is only available on macOS".into())
}

fn restore_app_from_trash(path: &Path, plan: &TrashMovePlan) -> Result<(), String> {
    if Path::new(INSTALLED_APP).exists() {
        return Err("cannot restore OsaGuard because its Applications path is occupied".into());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect trashed OsaGuard before rollback: {error}"))?;
    if metadata.dev() != plan.source_device || metadata.ino() != plan.source_inode {
        return Err("refusing to restore an unexpected app from the Trash".into());
    }
    fs::rename(path, INSTALLED_APP)
        .map_err(|error| format!("restore OsaGuard from the Trash: {error}"))
}

#[tauri::command]
async fn uninstall_app(app: AppHandle, acknowledgement: String) -> Result<(), String> {
    if acknowledgement != UNINSTALL_CONFIRMATION {
        return Err("uninstallation was not explicitly confirmed".into());
    }
    let executable = current_executable()?;
    if !installed_application_path(&executable) {
        return Err("only the installed /Applications copy can uninstall OsaGuard".into());
    }
    let lifecycle = app.state::<RuntimeState>().lifecycle.clone();
    let Some(mut permit) = lifecycle.try_begin(LifecycleOperation::Uninstall) else {
        return Err("OsaGuard is busy with another protected operation".into());
    };
    verify_bundle(Path::new(INSTALLED_APP))?;
    let user = current_user()?;

    // Complete every read-only check before mutating autostart, the watcher,
    // protected Keychain state, local settings, TCC, or the app bundle.
    let support_plan = plan_support_removal(&user)?;
    let trash_plan = plan_trash_move(&user)?;
    let protected_before = protected_state()?;
    let autostart_was_enabled = app
        .autolaunch()
        .is_enabled()
        .map_err(|error| format!("inspect OsaGuard login item: {error}"))?;
    let watcher_should_restore = watcher_running(&app).unwrap_or(false)
        || protected_state()
            .map(|state| state == ProtectedState::Enabled)
            .unwrap_or(false);

    if autostart_was_enabled {
        app.autolaunch()
            .disable()
            .map_err(|error| format!("disable OsaGuard at login: {error}"))?;
    }
    if let Err(error) = stop_all_watchers(&app, &user) {
        if autostart_was_enabled {
            let _ = app.autolaunch().enable();
        }
        let _ = restore_watcher(&app, &user, watcher_should_restore);
        return Err(error);
    }

    let mut staged_support = false;
    let mut trashed_app: Option<PathBuf> = None;
    let transaction = (|| {
        stage_support_removal(&support_plan)?;
        staged_support = support_plan.existed;
        let trashed = move_installed_app_to_trash(&trash_plan)?;
        trashed_app = Some(trashed);
        finish_support_removal(&support_plan)?;
        staged_support = false;
        delete_protected_state()?;
        password_delete_all()?;
        Ok(())
    })();

    if let Err(error) = transaction {
        let mut rollback_errors = Vec::new();
        let discovered_app = if trashed_app.is_none() && !Path::new(INSTALLED_APP).exists() {
            find_trashed_app(&trash_plan).ok()
        } else {
            None
        };
        if let Some(path) = trashed_app.as_deref().or(discovered_app.as_deref()) {
            if let Err(rollback) = restore_app_from_trash(path, &trash_plan) {
                rollback_errors.push(rollback);
            }
        }
        if staged_support || support_plan.existed {
            if let Err(rollback) = restore_support(&support_plan) {
                rollback_errors.push(rollback);
            }
        }
        if autostart_was_enabled {
            if let Err(rollback) = app.autolaunch().enable() {
                rollback_errors.push(format!("restore OsaGuard at login: {rollback}"));
            }
        }
        if let Err(rollback) = set_protected_state(protected_before) {
            rollback_errors.push(format!("restore protected OsaGuard state: {rollback}"));
        }
        if let Err(rollback) = restore_watcher(&app, &user, watcher_should_restore) {
            rollback_errors.push(rollback);
        }
        if rollback_errors.is_empty() {
            return Err(error);
        }
        return Err(format!(
            "{error}; uninstall rollback also failed: {}",
            rollback_errors.join("; ")
        ));
    }

    // TCC cleanup is idempotent and best-effort: a stale permission row is harmless,
    // while failing after the irreversible Keychain deletion would make rollback unsafe.
    let _ = reset_accessibility_permission();
    permit.commit_shutdown();
    let exit_app = app.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(350));
        exit_app.exit(0);
    });
    Ok(())
}

fn maybe_notify_update_available(app: &AppHandle, version: &str) {
    let state = app.state::<RuntimeState>();
    if !state.lifecycle.is_running() {
        return;
    }
    if state
        .last_notified_version
        .lock()
        .map(|last| last.as_deref() == Some(version))
        .unwrap_or(false)
    {
        return;
    }
    let locale = Locale::system();
    if app
        .notification()
        .builder()
        .title(locale.update_notification_title())
        .body(locale.update_notification_body(version))
        .show()
        .is_err()
    {
        return;
    }
    if let Ok(mut last) = state.last_notified_version.lock() {
        *last = Some(version.to_owned());
    }
    if let Ok(user) = current_user() {
        let notification_state = UpdateNotificationState {
            last_notified_version: Some(version.to_owned()),
            ..UpdateNotificationState::default()
        };
        let _ = write_update_notification_state(&user, &notification_state);
    }
}

async fn check_updates_inner(app: &AppHandle) -> Result<UpdateStatus, String> {
    if !updater_configured(app) {
        let status = UpdateStatus::default();
        set_update_status(app, status.clone());
        return Ok(status);
    }
    let installed = current_executable()
        .map(|executable| installed_application_path(&executable))
        .unwrap_or(false);
    if !installed {
        let status = UpdateStatus::default();
        set_update_status(app, status.clone());
        return Ok(status);
    }
    let lifecycle = app.state::<RuntimeState>().lifecycle.clone();
    let Some(_permit) = lifecycle.try_begin(LifecycleOperation::Update) else {
        return Ok(current_update_status(app));
    };
    set_update_status(app, UpdateStatus::configured(UpdatePhase::Checking));
    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(error) => {
            let status = UpdateStatus::error("unavailable", None);
            set_update_status(app, status);
            return Err(format!("initialize updater: {error}"));
        }
    };
    match updater.check().await {
        Ok(Some(update)) => {
            let version = update.version.clone();
            let status = UpdateStatus::available(UpdatePhase::Available, version.clone());
            set_update_status(app, status.clone());
            if lifecycle.is_running() {
                maybe_notify_update_available(app, &version);
            }
            Ok(status)
        }
        Ok(None) => {
            let status = UpdateStatus::configured(UpdatePhase::UpToDate);
            set_update_status(app, status.clone());
            Ok(status)
        }
        Err(error) => {
            let status = UpdateStatus::error("check_failed", None);
            set_update_status(app, status);
            Err(format!("check for updates: {error}"))
        }
    }
}

#[tauri::command]
async fn check_for_updates(app: AppHandle) -> Result<UpdateStatus, String> {
    check_updates_inner(&app).await
}

fn update_ready_with_error(version: &str, code: &str) -> UpdateStatus {
    UpdateStatus {
        configured: true,
        phase: UpdatePhase::Ready,
        version: Some(version.to_owned()),
        error_code: Some(code.to_owned()),
    }
}

fn active_auth_dialog() -> Result<bool, String> {
    let mut error = [0; NATIVE_ERROR_CAPACITY];
    let result = unsafe {
        // SAFETY: the writable error buffer remains valid for the call.
        osaguard_auth_dialog_active(error.as_mut_ptr(), error.len())
    };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(native_error(&error, "inspect current administrator dialog")),
    }
}

fn restore_watcher(app: &AppHandle, user: &UserInfo, should_restore: bool) -> Result<(), String> {
    if should_restore {
        start_watcher(app, user)
    } else {
        Ok(())
    }
}

fn validate_update_install_request(
    installed: bool,
    expected_version: &str,
    actual_version: &str,
    acknowledgement: &str,
) -> Result<(), &'static str> {
    if acknowledgement != INSTALL_UPDATE_CONFIRMATION {
        return Err("confirmation_required");
    }
    if !installed {
        return Err("not_installed");
    }
    if expected_version.is_empty() || expected_version != actual_version {
        return Err("version_changed");
    }
    Ok(())
}

fn update_install_is_unprivileged() -> bool {
    let applications = c"/Applications";
    let installed = c"/Applications/OsaGuard.app";
    let applications_writable = unsafe {
        // SAFETY: the pointer is a static NUL-terminated C string.
        libc::access(applications.as_ptr(), libc::W_OK)
    } == 0;
    let installed_writable = unsafe {
        // SAFETY: the pointer is a static NUL-terminated C string.
        libc::access(installed.as_ptr(), libc::W_OK)
    } == 0;
    applications_writable && installed_writable
}

#[tauri::command]
async fn install_update(
    app: AppHandle,
    expected_version: String,
    acknowledgement: String,
) -> Result<UpdateStatus, String> {
    if !updater_configured(&app) {
        let status = UpdateStatus::default();
        set_update_status(&app, status.clone());
        return Err("updates are unavailable in this preview build".into());
    }
    if acknowledgement != INSTALL_UPDATE_CONFIRMATION {
        let status = update_ready_with_error(&expected_version, "confirmation_required");
        set_update_status(&app, status);
        return Err("update installation was not explicitly confirmed".into());
    }
    let installed = current_executable()
        .map(|executable| installed_application_path(&executable))
        .unwrap_or(false);
    if !installed {
        let status = update_ready_with_error(&expected_version, "not_installed");
        set_update_status(&app, status);
        return Err("only the installed /Applications copy can install updates".into());
    }
    if !update_install_is_unprivileged() {
        let status = update_ready_with_error(&expected_version, "manual_update_required");
        set_update_status(&app, status);
        return Err("this update requires manual installation from the signed DMG".into());
    }
    let lifecycle = app.state::<RuntimeState>().lifecycle.clone();
    let Some(_permit) = lifecycle.try_begin(LifecycleOperation::Update) else {
        let version = current_update_status(&app)
            .version
            .unwrap_or_else(|| expected_version.clone());
        set_update_status(&app, update_ready_with_error(&version, "busy"));
        return Err("OsaGuard is busy with another protected operation".into());
    };
    set_update_status(&app, UpdateStatus::configured(UpdatePhase::Checking));
    let updater = app.updater().map_err(|error| {
        set_update_status(&app, UpdateStatus::error("unavailable", None));
        format!("initialize updater: {error}")
    })?;
    let Some(update) = updater.check().await.map_err(|error| {
        set_update_status(&app, UpdateStatus::error("check_failed", None));
        format!("check for update before installation: {error}")
    })?
    else {
        let status = UpdateStatus::configured(UpdatePhase::UpToDate);
        set_update_status(&app, status.clone());
        return Ok(status);
    };
    let version = update.version.clone();
    if let Err(code) =
        validate_update_install_request(true, &expected_version, &version, &acknowledgement)
    {
        let status = UpdateStatus {
            configured: true,
            phase: UpdatePhase::Available,
            version: Some(version),
            error_code: Some(code.into()),
        };
        set_update_status(&app, status);
        return Err("the available update changed; review it before installing".into());
    }
    set_update_status(
        &app,
        UpdateStatus::available(UpdatePhase::Downloading, version.clone()),
    );
    let bytes = update.download(|_, _| {}, || {}).await.map_err(|error| {
        set_update_status(
            &app,
            UpdateStatus::error("download_failed", Some(version.clone())),
        );
        format!("download and verify update: {error}")
    })?;
    set_update_status(
        &app,
        UpdateStatus::available(UpdatePhase::Ready, version.clone()),
    );

    if !lifecycle.is_running() {
        set_update_status(&app, update_ready_with_error(&version, "busy"));
        return Err("OsaGuard is shutting down".into());
    }

    if active_auth_dialog().inspect_err(|_| {
        set_update_status(
            &app,
            update_ready_with_error(&version, "auth_dialog_check_failed"),
        );
    })? {
        set_update_status(
            &app,
            update_ready_with_error(&version, "auth_dialog_active"),
        );
        return Err("an administrator dialog is currently active".into());
    }

    let user = current_user().inspect_err(|_| {
        set_update_status(
            &app,
            UpdateStatus::error("user_unavailable", Some(version.clone())),
        );
    })?;
    let should_restore = watcher_running(&app).unwrap_or(false)
        || protected_state()
            .map(|state| state == ProtectedState::Enabled)
            .unwrap_or(false);
    if let Err(error) = stop_all_watchers(&app, &user) {
        let restore = restore_watcher(&app, &user, should_restore);
        let code = if restore.is_err() {
            "watcher_restore_failed"
        } else {
            "watcher_stop_failed"
        };
        set_update_status(&app, UpdateStatus::error(code, Some(version.clone())));
        return Err(format!(
            "stop automatic confirmation before update: {error}"
        ));
    }

    match active_auth_dialog() {
        Ok(false) => {}
        Ok(true) => {
            let restore = restore_watcher(&app, &user, should_restore);
            let code = if restore.is_err() {
                "watcher_restore_failed"
            } else {
                "auth_dialog_active"
            };
            set_update_status(&app, update_ready_with_error(&version, code));
            return Err("an administrator dialog appeared before installation".into());
        }
        Err(error) => {
            let restore = restore_watcher(&app, &user, should_restore);
            let code = if restore.is_err() {
                "watcher_restore_failed"
            } else {
                "auth_dialog_check_failed"
            };
            set_update_status(&app, update_ready_with_error(&version, code));
            return Err(error);
        }
    }

    set_update_status(
        &app,
        UpdateStatus::available(UpdatePhase::Installing, version.clone()),
    );
    if let Err(error) = update.install(bytes) {
        let restore = restore_watcher(&app, &user, should_restore);
        let code = if restore.is_err() {
            "watcher_restore_failed"
        } else {
            "install_failed"
        };
        set_update_status(&app, UpdateStatus::error(code, Some(version.clone())));
        return Err(format!("install verified update: {error}"));
    }
    lifecycle.begin_shutdown();
    app.restart();
}

fn handle_menu(app: &AppHandle, id: &str) {
    match id {
        ID_OPEN => show_main_window(app),
        ID_PASSWORD => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if store_password_inner(app.clone()).await.is_err() {
                    show_action_error(&app, "password-action-error", "save_failed");
                }
            });
        }
        ID_TOGGLE => {
            let enabled = compute_status(app)
                .map(|status| !status.automatic_active)
                .unwrap_or(false);
            if set_enabled_inner(app, enabled).is_err() {
                show_action_error(app, "runtime-action-error", "automatic_confirmation_failed");
            }
        }
        ID_UPDATE => {
            let update_status = current_update_status(app);
            if matches!(
                update_status.phase,
                UpdatePhase::Available | UpdatePhase::Ready
            ) {
                show_main_window(app);
                let _ = app.emit("install-update-requested", ());
            } else {
                show_main_window(app);
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = check_updates_inner(&app).await;
                });
            }
        }
        ID_UNINSTALL => {
            show_main_window(app);
            let _ = app.emit("uninstall-requested", ());
        }
        ID_QUIT => {
            app.state::<RuntimeState>().lifecycle.begin_shutdown();
            if let Ok(user) = current_user() {
                let _ = stop_all_watchers(app, &user);
            } else {
                let _ = stop_watcher(app);
            }
            app.exit(0);
        }
        _ => {}
    }
    refresh_menu(app);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Fail closed: a process that could retain a core dump or accept a debugger must not
    // access the administrator password. This happens before Tauri creates UI or starts
    // the watcher, so no password operation can race the hardening step.
    if let Err(error) = harden_native_process() {
        eprintln!("OsaGuard refused to start: {error}");
        return;
    }

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(RuntimeState::default())
        .invoke_handler(tauri::generate_handler![
            get_status,
            request_accessibility,
            open_accessibility_settings,
            store_password,
            forget_password,
            enable_automatic,
            set_enabled,
            install_app,
            check_for_updates,
            install_update,
            uninstall_app
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let locale = Locale::system();
            let state = MenuItemBuilder::with_id("state", locale.state_setup())
                .enabled(false)
                .build(app)?;
            let open = MenuItemBuilder::with_id(ID_OPEN, locale.open()).build(app)?;
            let toggle = MenuItemBuilder::with_id(ID_TOGGLE, locale.resume()).build(app)?;
            let password =
                MenuItemBuilder::with_id(ID_PASSWORD, locale.save_password()).build(app)?;
            let update = MenuItemBuilder::with_id(ID_UPDATE, locale.check_updates()).build(app)?;
            let uninstall =
                MenuItemBuilder::with_id(ID_UNINSTALL, locale.uninstall()).build(app)?;
            let quit = MenuItemBuilder::with_id(ID_QUIT, locale.quit())
                .accelerator("CmdOrCtrl+Q")
                .build(app)?;
            let menu = MenuBuilder::new(app)
                .item(&state)
                .separator()
                .item(&open)
                .item(&toggle)
                .item(&password)
                .separator()
                .item(&update)
                .separator()
                .item(&uninstall)
                .item(&quit)
                .build()?;
            *app.state::<RuntimeState>()
                .menu
                .lock()
                .map_err(|_| std::io::Error::other("OsaGuard menu state is unavailable"))? =
                Some(MenuHandles {
                    state,
                    toggle,
                    password,
                    update,
                    uninstall,
                });

            let tray_icon = Image::from_bytes(include_bytes!("../icons/tray-template.png"))?;
            TrayIconBuilder::with_id("main")
                .tooltip(locale.tooltip())
                .icon(tray_icon)
                .icon_as_template(true)
                .show_menu_on_left_click(true)
                .menu(&menu)
                .on_menu_event(|app, event| handle_menu(app, event.id().as_ref()))
                .build(app)?;

            let handle = app.handle().clone();
            let initial_update_status = if updater_configured(&handle) {
                UpdateStatus::configured(UpdatePhase::Idle)
            } else {
                UpdateStatus::default()
            };
            if let Ok(mut status) = handle.state::<RuntimeState>().update_status.lock() {
                *status = initial_update_status;
            }
            if let Ok(user) = current_user() {
                if let Ok(notification_state) = read_update_notification_state(&user) {
                    if let Ok(mut last) =
                        handle.state::<RuntimeState>().last_notified_version.lock()
                    {
                        *last = notification_state.last_notified_version;
                    }
                }
                if cleanup_legacy_launch_agent(&user).is_err() {
                    show_action_error(&handle, "runtime-action-error", "cleanup_failed");
                }
            }
            let status = compute_status(&handle);
            if let Ok(status) = &status {
                if status.configured && status.enabled && !status.watcher_running {
                    if let Ok(user) = current_user() {
                        if start_watcher(&handle, &user).is_err() {
                            show_action_error(
                                &handle,
                                "runtime-action-error",
                                "automatic_confirmation_failed",
                            );
                        }
                    }
                }
                if !status.configured {
                    show_main_window(&handle);
                }
            } else {
                show_main_window(&handle);
            }
            refresh_menu(&handle);

            let update_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(15)).await;
                loop {
                    let _ = check_updates_inner(&update_handle).await;
                    tokio::time::sleep(UPDATE_CHECK_INTERVAL).await;
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build OsaGuard");
    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { code, api, .. } => {
            if code.is_none() {
                api.prevent_exit();
            } else {
                app.state::<RuntimeState>().lifecycle.begin_shutdown();
                if let Ok(user) = current_user() {
                    let _ = stop_all_watchers(app, &user);
                } else {
                    let _ = stop_watcher(app);
                }
            }
        }
        tauri::RunEvent::Exit => {
            app.state::<RuntimeState>().lifecycle.begin_shutdown();
            if let Ok(user) = current_user() {
                let _ = stop_all_watchers(app, &user);
            } else {
                let _ = stop_watcher(app);
            }
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use std::{
        os::fd::AsRawFd,
        path::Path,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };

    use super::{
        app_bundle_path, decode_accessibility_request_result, decode_password_state,
        decode_protected_state, installed_application_path, native_c_string, parse_bundle_version,
        update_ready_with_error, validate_update_install_request, KeychainItemState,
        LifecycleCoordinator, LifecycleOperation, LifecyclePhase, OperationGate, ProtectedState,
        UpdatePhase, UpdateStatus, WatcherProcess, INSTALL_UPDATE_CONFIRMATION,
    };

    #[test]
    fn decodes_native_accessibility_request_status() {
        assert_eq!(decode_accessibility_request_result(0), Ok(false));
        assert_eq!(decode_accessibility_request_result(1), Ok(true));
        assert!(decode_accessibility_request_result(-1).is_err());
    }

    #[test]
    fn rejects_nul_in_native_bridge_strings() {
        assert!(native_c_string("normal", "value").is_ok());
        assert!(native_c_string("bad\0value", "value").is_err());
    }

    #[test]
    fn decodes_keychain_reenrollment_without_trusting_the_old_item() {
        assert_eq!(decode_password_state(0), Ok(KeychainItemState::Missing));
        assert_eq!(decode_password_state(1), Ok(KeychainItemState::Ready));
        assert_eq!(
            decode_password_state(2),
            Ok(KeychainItemState::NeedsReenrollment)
        );
        assert!(decode_password_state(-1).is_err());

        let protected = decode_protected_state(3).expect("decode protected state");
        assert_eq!(protected.state, ProtectedState::Missing);
        assert_eq!(protected.item_state, KeychainItemState::NeedsReenrollment);
        assert_eq!(
            serde_json::to_value(KeychainItemState::NeedsReenrollment)
                .expect("serialize Keychain item state"),
            serde_json::json!("needs_reenrollment")
        );
    }

    #[test]
    fn operation_gate_allows_only_one_live_permit() {
        let gate = OperationGate::default();
        let permit = gate.try_enter().expect("first operation enters");
        assert!(gate.try_enter().is_none());
        drop(permit);
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn lifecycle_serializes_protected_operations_and_restores_after_failure() {
        let lifecycle = LifecycleCoordinator::default();
        let password = lifecycle
            .try_begin(LifecycleOperation::Password)
            .expect("begin password prompt");
        assert!(lifecycle.try_begin(LifecycleOperation::Update).is_none());
        assert!(lifecycle.try_begin(LifecycleOperation::Uninstall).is_none());
        drop(password);

        let uninstall = lifecycle
            .try_begin(LifecycleOperation::Uninstall)
            .expect("begin uninstall");
        assert!(!lifecycle.is_running());
        drop(uninstall);
        assert!(lifecycle.is_running());
    }

    #[test]
    fn committed_uninstall_keeps_the_lifecycle_shut_down() {
        let lifecycle = LifecycleCoordinator::default();
        let mut uninstall = lifecycle
            .try_begin(LifecycleOperation::Uninstall)
            .expect("begin uninstall");
        uninstall.commit_shutdown();
        drop(uninstall);
        assert!(!lifecycle.is_running());
        assert_eq!(
            lifecycle.state.lock().expect("lifecycle state").phase,
            LifecyclePhase::Exiting
        );
    }

    #[test]
    fn update_install_requires_the_canonical_app_version_and_acknowledgement() {
        assert_eq!(
            validate_update_install_request(true, "1.2.3", "1.2.3", INSTALL_UPDATE_CONFIRMATION),
            Ok(())
        );
        assert_eq!(
            validate_update_install_request(false, "1.2.3", "1.2.3", INSTALL_UPDATE_CONFIRMATION),
            Err("not_installed")
        );
        assert_eq!(
            validate_update_install_request(true, "1.2.3", "1.2.4", INSTALL_UPDATE_CONFIRMATION),
            Err("version_changed")
        );
        assert_eq!(
            validate_update_install_request(true, "1.2.3", "1.2.3", "wrong"),
            Err("confirmation_required")
        );
    }

    #[test]
    fn typed_update_status_serializes_for_the_webview_contract() {
        let status = UpdateStatus::available(UpdatePhase::Available, "1.2.3");
        assert_eq!(
            serde_json::to_value(status).expect("serialize update status"),
            serde_json::json!({
                "configured": true,
                "phase": "available",
                "version": "1.2.3",
                "errorCode": null
            })
        );
        let blocked = update_ready_with_error("1.2.3", "auth_dialog_active");
        assert_eq!(blocked.phase, UpdatePhase::Ready);
        assert_eq!(blocked.error_code.as_deref(), Some("auth_dialog_active"));
    }

    #[test]
    fn recognizes_only_the_canonical_installed_bundle() {
        assert!(installed_application_path(Path::new(
            "/Applications/OsaGuard.app/Contents/MacOS/osaguard-tray"
        )));
        assert!(!installed_application_path(Path::new(
            "/Applications/OsaGuard Beta.app/Contents/MacOS/osaguard-tray"
        )));
        assert!(!installed_application_path(Path::new(
            "/Users/test/OsaGuard.app/Contents/MacOS/osaguard-tray"
        )));
    }

    #[test]
    fn finds_the_enclosing_app_bundle_only_for_a_macos_executable() {
        assert_eq!(
            app_bundle_path(Path::new(
                "/Volumes/OsaGuard/OsaGuard.app/Contents/MacOS/osaguard-tray"
            )),
            Some(Path::new("/Volumes/OsaGuard/OsaGuard.app").to_path_buf())
        );
        assert_eq!(
            app_bundle_path(Path::new("/tmp/OsaGuard.app/not-a-macos-binary")),
            None
        );
    }

    #[test]
    fn compares_strict_three_component_bundle_versions() {
        assert_eq!(parse_bundle_version("0.1.1"), Ok([0, 1, 1]));
        assert!(parse_bundle_version("0.1").is_err());
        assert!(parse_bundle_version("0.1.1-preview.1").is_err());
        assert!(parse_bundle_version("0.01.1").is_ok());
        assert!(parse_bundle_version("0.1.1.0").is_err());
        assert!([0, 1, 1] > [0, 1, 0]);
    }

    #[test]
    fn watcher_does_not_spawn_a_duplicate_worker() {
        let started = Arc::new(AtomicBool::new(false));
        let started_in_worker = started.clone();
        let mut watcher = WatcherProcess::default();
        watcher
            .start_worker(move |control| {
                started_in_worker.store(true, Ordering::Release);
                let mut byte = [0_u8; 1];
                unsafe {
                    // SAFETY: control is a live pipe read descriptor and byte is writable.
                    libc::read(control.as_raw_fd(), byte.as_mut_ptr().cast(), byte.len());
                }
                Ok(())
            })
            .expect("start test watcher");
        for _ in 0..100 {
            if started.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert!(started.load(Ordering::Acquire));
        watcher
            .start_worker(|_| panic!("a second watcher must not be spawned"))
            .expect("keep existing watcher");
        watcher.stop().expect("stop test watcher");
        assert!(!watcher.is_running().expect("inspect stopped watcher"));
    }

    #[test]
    fn watcher_reaps_an_exited_worker() {
        let mut watcher = WatcherProcess::default();
        watcher
            .start_worker(|_| Ok(()))
            .expect("start test watcher");
        for _ in 0..100 {
            if !watcher.is_running().expect("inspect test watcher") {
                assert!(watcher.worker.is_none());
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("test watcher did not exit");
    }
}

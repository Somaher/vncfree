//! Per-user logon startup through the Windows Task Scheduler.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use sha2::{Digest, Sha256};
use windows::core::{Interface, BSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_ELEVATION_REQUIRED, ERROR_FILE_NOT_FOUND,
    ERROR_PRIVILEGE_NOT_HELD, E_ACCESSDENIED, E_INVALIDARG, HANDLE, VARIANT_FALSE, VARIANT_TRUE,
    WAIT_OBJECT_0,
};
use windows::Win32::Security::Authentication::Identity::{GetUserNameExW, NameSamCompatible};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::TaskScheduler::*;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::Res;

struct Apartment;

impl Apartment {
    fn new() -> windows::core::Result<Self> {
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;
        }
        Ok(Self)
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

struct Scheduler {
    service: ITaskService,
    folder: ITaskFolder,
    user: String,
    name: BSTR,
    // Release every COM interface before uninitializing its apartment.
    _apartment: Apartment,
}

fn task_name(user: &str) -> BSTR {
    let hash = Sha256::digest(user.to_lowercase().as_bytes());
    let suffix: String = hash[..8].iter().map(|byte| format!("{byte:02x}")).collect();
    BSTR::from(format!("vncfree-server-{suffix}"))
}

impl Scheduler {
    fn connect() -> windows::core::Result<Self> {
        let apartment = Apartment::new()?;
        unsafe {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let empty = VARIANT::default();
            service.Connect(&empty, &empty, &empty, &empty)?;
            let domain = service.ConnectedDomain()?.to_string();
            let account = service.ConnectedUser()?.to_string();
            let user = if domain.is_empty() {
                account
            } else {
                format!("{domain}\\{account}")
            };
            // Keep task names distinct for different Windows users without putting
            // account-name characters into a Task Scheduler path.
            let name = task_name(&user);
            let folder = service.GetFolder(&BSTR::from("\\"))?;
            Ok(Self {
                service,
                folder,
                user,
                name,
                _apartment: apartment,
            })
        }
    }

    fn task(&self) -> windows::core::Result<Option<IRegisteredTask>> {
        match unsafe { self.folder.GetTask(&self.name) } {
            Ok(task) => Ok(Some(task)),
            Err(error) if error.code() == ERROR_FILE_NOT_FOUND.to_hresult() => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn set_enabled(&self, enabled: bool, executable: &Path) -> windows::core::Result<()> {
        unsafe {
            if !enabled {
                if self.task()?.is_some() {
                    self.folder.DeleteTask(&self.name, 0)?;
                }
                return Ok(());
            }
            let definition = self.service.NewTask(0)?;
            let info = definition.RegistrationInfo()?;
            info.SetAuthor(&BSTR::from("vncfree"))?;
            info.SetDescription(&BSTR::from("Start vncfree-server headless when this user logs in. Uses the encrypted saved server configuration."))?;

            let principal = definition.Principal()?;
            principal.SetUserId(&BSTR::from(&self.user))?;
            principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
            principal.SetRunLevel(TASK_RUNLEVEL_LUA)?;

            let trigger: ILogonTrigger =
                definition.Triggers()?.Create(TASK_TRIGGER_LOGON)?.cast()?;
            trigger.SetUserId(&BSTR::from(&self.user))?;
            trigger.SetEnabled(VARIANT_TRUE)?;

            let action: IExecAction = definition.Actions()?.Create(TASK_ACTION_EXEC)?.cast()?;
            action.SetPath(&BSTR::from_wide(
                &executable.as_os_str().encode_wide().collect::<Vec<_>>(),
            ))?;
            action.SetArguments(&BSTR::from("--headless"))?;
            if let Some(directory) = executable.parent() {
                action.SetWorkingDirectory(&BSTR::from_wide(
                    &directory.as_os_str().encode_wide().collect::<Vec<_>>(),
                ))?;
            }

            let settings = definition.Settings()?;
            settings.SetEnabled(VARIANT_TRUE)?;
            settings.SetAllowDemandStart(VARIANT_TRUE)?;
            settings.SetStartWhenAvailable(VARIANT_TRUE)?;
            settings.SetDisallowStartIfOnBatteries(VARIANT_FALSE)?;
            settings.SetStopIfGoingOnBatteries(VARIANT_FALSE)?;
            settings.SetExecutionTimeLimit(&BSTR::from("PT0S"))?;
            settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)?;

            let empty = VARIANT::default();
            self.folder.RegisterTaskDefinition(
                &self.name,
                &definition,
                TASK_CREATE_OR_UPDATE.0,
                &VARIANT::from(self.user.as_str()),
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )?;
        }
        Ok(())
    }
}

pub fn enabled() -> Res<bool> {
    let scheduler = Scheduler::connect()?;
    match scheduler.task()? {
        Some(task) => Ok(unsafe { task.Enabled()?.as_bool() }),
        None => Ok(false),
    }
}

pub fn set_enabled(enabled: bool) -> Res<()> {
    let executable = std::env::current_exe()?;
    update_with_permission_retry(
        || Scheduler::connect().and_then(|scheduler| scheduler.set_enabled(enabled, &executable)),
        is_elevated,
        || elevate_update(enabled, &current_user()?, &executable),
    )
}

fn update_with_permission_retry(
    update: impl FnOnce() -> windows::core::Result<()>,
    elevated: impl FnOnce() -> windows::core::Result<bool>,
    retry: impl FnOnce() -> Res<()>,
) -> Res<()> {
    match update() {
        Ok(()) => Ok(()),
        Err(error) if permission_error(&error) => {
            if elevated()? {
                return Err(format!(
                    "Task Scheduler denied access even with administrator rights: {error}"
                )
                .into());
            }
            retry()
        }
        Err(error) => Err(format!("could not update autostart in Task Scheduler: {error}").into()),
    }
}

fn permission_error(error: &windows::core::Error) -> bool {
    [
        E_ACCESSDENIED,
        ERROR_ELEVATION_REQUIRED.to_hresult(),
        ERROR_PRIVILEGE_NOT_HELD.to_hresult(),
    ]
    .contains(&error.code())
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn is_elevated() -> windows::core::Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let token = OwnedHandle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut length = 0;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn current_user() -> windows::core::Result<String> {
    unsafe {
        let mut length = 0;
        GetUserNameExW(NameSamCompatible, None, &mut length);
        if length == 0 {
            return Err(windows::core::Error::from_thread());
        }
        let mut buffer = vec![0; length as usize];
        if !GetUserNameExW(
            NameSamCompatible,
            Some(PWSTR(buffer.as_mut_ptr())),
            &mut length,
        ) {
            return Err(windows::core::Error::from_thread());
        }
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Ok(String::from_utf16_lossy(&buffer[..end]))
    }
}

// ShellExecuteEx takes a Windows command line, not a shell script. Quote every
// argument using the Windows argv backslash/quote rules, including trailing slashes.
fn quote_argument(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        out.push_str(&"\\".repeat(if c == '"' { slashes * 2 + 1 } else { slashes }));
        out.push(c);
        slashes = 0;
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

fn elevate_update(enabled: bool, user: &str, executable: &Path) -> Res<()> {
    let _apartment = Apartment::new()?;
    let executable: Vec<u16> = executable.as_os_str().encode_wide().chain([0]).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain([0]).collect();
    let parameters = format!(
        "--autostart-helper {} {}",
        if enabled { "enable" } else { "disable" },
        quote_argument(user)
    );
    let parameters: Vec<u16> = parameters.encode_utf16().chain([0]).collect();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        if let Err(error) = ShellExecuteExW(&mut info) {
            if error.code() == ERROR_CANCELLED.to_hresult() {
                return Err(
                    "Autostart was not changed: the administrator permission prompt was cancelled"
                        .into(),
                );
            }
            return Err(format!(
                "could not request administrator rights for Task Scheduler: {error}"
            )
            .into());
        }
        if info.hProcess.is_invalid() {
            return Err(
                "Windows did not return a process for the administrator task update".into(),
            );
        }
        let process = OwnedHandle(info.hProcess);
        if WaitForSingleObject(process.0, INFINITE) != WAIT_OBJECT_0 {
            return Err(windows::core::Error::from_thread().into());
        }
        let mut exit_code = 0;
        GetExitCodeProcess(process.0, &mut exit_code)?;
        if exit_code != 0 {
            let error =
                windows::core::Error::from_hresult(windows::core::HRESULT(exit_code as i32));
            return Err(format!("administrator task update failed: {error}").into());
        }
    }
    Ok(())
}

/// Internal entry point for the elevated copy. It only updates Task Scheduler:
/// no config decryption, password arguments, UI, or desktop server is involved.
pub fn run_elevated_helper(args: &[String]) -> windows::core::Result<()> {
    let [action, user] = args else {
        return Err(E_INVALIDARG.into());
    };
    let enabled = match action.as_str() {
        "enable" => true,
        "disable" => false,
        _ => return Err(E_INVALIDARG.into()),
    };
    if !user.contains('\\') || user.contains('\0') || user.ends_with('\\') {
        return Err(E_INVALIDARG.into());
    }
    if !is_elevated()? {
        return Err(E_ACCESSDENIED.into());
    }
    let mut scheduler = Scheduler::connect()?;
    // UAC may have used a different administrator account. Always register the
    // principal, logon trigger, and task name for the original interactive user.
    scheduler.name = task_name(user);
    scheduler.user = user.clone();
    scheduler.set_enabled(enabled, &std::env::current_exe()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_or_unrelated_failures_do_not_prompt_and_elevation_retries_once() {
        assert!(update_with_permission_retry(
            || Ok(()),
            || panic!("no token check needed"),
            || panic!("must not elevate")
        )
        .is_ok());
        assert!(update_with_permission_retry(
            || Err(E_INVALIDARG.into()),
            || panic!("not a permissions error"),
            || panic!("must not elevate")
        )
        .is_err());
        let retried = std::cell::Cell::new(false);
        update_with_permission_retry(
            || Err(E_ACCESSDENIED.into()),
            || Ok(false),
            || {
                retried.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(retried.get());
        let error = update_with_permission_retry(
            || Err(E_ACCESSDENIED.into()),
            || Ok(true),
            || panic!("must not loop when already elevated"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("even with administrator rights"));
        let cancelled = update_with_permission_retry(
            || Err(E_ACCESSDENIED.into()),
            || Ok(false),
            || Err("administrator permission prompt was cancelled".into()),
        )
        .unwrap_err();
        assert!(cancelled.to_string().contains("cancelled"));
    }

    #[test]
    fn elevation_is_reserved_for_permission_failures() {
        for code in [
            E_ACCESSDENIED,
            ERROR_ELEVATION_REQUIRED.to_hresult(),
            ERROR_PRIVILEGE_NOT_HELD.to_hresult(),
        ] {
            assert!(permission_error(&windows::core::Error::from_hresult(code)));
        }
        for code in [
            E_INVALIDARG,
            ERROR_FILE_NOT_FOUND.to_hresult(),
            ERROR_CANCELLED.to_hresult(),
        ] {
            assert!(!permission_error(&windows::core::Error::from_hresult(code)));
        }
    }

    #[test]
    fn elevated_helper_rejects_invalid_requests_before_changing_tasks() {
        for args in [
            vec![],
            vec!["enable"],
            vec!["enable", "unqualified-user"],
            vec!["invalid", "DOMAIN\\user"],
            vec!["disable", "DOMAIN\\"],
            vec!["enable", "DOMAIN\\user\0extra"],
        ] {
            let args: Vec<_> = args.into_iter().map(str::to_string).collect();
            assert_eq!(run_elevated_helper(&args).unwrap_err().code(), E_INVALIDARG);
        }
    }

    #[test]
    fn elevation_arguments_round_trip_through_windows_argv() {
        use windows::Win32::UI::Shell::CommandLineToArgvW;
        let values = [
            "DOMAIN\\Jane Doe",
            "DOMAIN\\Zo\u{eb}",
            "quotes\"and\\slashes\\",
            "",
        ];
        for value in values {
            let command = format!(
                "server.exe --autostart-helper enable {}",
                quote_argument(value)
            );
            let wide: Vec<u16> = command.encode_utf16().chain([0]).collect();
            unsafe {
                let mut count = 0;
                let argv = CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut count);
                assert!(!argv.is_null());
                let arguments = std::slice::from_raw_parts(argv, count as usize);
                let decoded: Vec<String> =
                    arguments.iter().map(|s| s.to_string().unwrap()).collect();
                windows_sys::Win32::Foundation::LocalFree(argv as *mut _);
                assert_eq!(
                    decoded,
                    ["server.exe", "--autostart-helper", "enable", value]
                );
            }
        }
    }

    #[test]
    fn elevation_preserves_the_existing_per_user_task_name() {
        let scheduler = Scheduler::connect().unwrap();
        assert_eq!(task_name(&current_user().unwrap()), scheduler.name);
        assert!(is_elevated().is_ok());
    }

    #[test]
    #[ignore = "creates and removes a temporary task in Windows Task Scheduler"]
    fn registers_interactive_headless_task_and_removes_it() {
        let mut scheduler = Scheduler::connect().unwrap();
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        scheduler.name = BSTR::from(format!(
            "vncfree-autostart-test-{:016x}",
            u64::from_le_bytes(nonce)
        ));
        struct Cleanup<'a>(&'a Scheduler);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self.0.set_enabled(false, Path::new(""));
            }
        }
        let _cleanup = Cleanup(&scheduler);
        let path = std::env::current_exe().unwrap();
        assert!(scheduler.task().unwrap().is_none());
        scheduler.set_enabled(true, &path).unwrap();
        let task = scheduler.task().unwrap().unwrap();
        let xml = unsafe { task.Xml().unwrap().to_string() };
        assert!(xml.contains("--headless"));
        assert!(xml.contains("InteractiveToken"));
        let mut run_level = TASK_RUNLEVEL_TYPE::default();
        unsafe {
            task.Definition()
                .unwrap()
                .Principal()
                .unwrap()
                .RunLevel(&mut run_level)
                .unwrap();
        }
        assert_eq!(run_level, TASK_RUNLEVEL_LUA);
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("PT0S"));
        assert!(!xml.contains("--password"));
        // Re-enabling must update one task rather than create a duplicate.
        scheduler.set_enabled(true, &path).unwrap();
        scheduler.set_enabled(false, &path).unwrap();
        assert!(scheduler.task().unwrap().is_none());
        scheduler.set_enabled(false, &path).unwrap();
    }
}

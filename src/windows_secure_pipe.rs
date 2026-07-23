use interprocess::local_socket::tokio::prelude::LocalSocketStream;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, TokenUser, WinLocalSystemSid, SECURITY_MAX_SID_SIZE,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

pub(crate) fn connect_local_system_server(path: &Path) -> io::Result<LocalSocketStream> {
    connect_verified_server(path, verify_process_is_local_system)
}

pub(crate) fn connect_verified_server(
    path: &Path,
    verifier: fn(u32) -> io::Result<()>,
) -> io::Result<LocalSocketStream> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "named-pipe path contains NUL",
        ));
    }
    wide.push(0);

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    verify_pipe_server(handle.as_raw_handle(), verifier)?;

    let stream = interprocess::os::windows::named_pipe::local_socket::tokio::Stream::try_from(handle)?;
    Ok(LocalSocketStream::from(stream))
}

fn verify_pipe_server(pipe: *mut c_void, verifier: fn(u32) -> io::Result<()>) -> io::Result<()> {
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::last_os_error());
    }
    verifier(process_id)
}

fn verify_process_is_local_system(process_id: u32) -> io::Result<()> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut required = 0_u32;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, std::ptr::null_mut(), 0, &mut required) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut user = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            user.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() };

    let sid_words = (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<usize>());
    let mut system_sid = vec![0_usize; sid_words];
    let mut system_sid_size = SECURITY_MAX_SID_SIZE;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            system_sid.as_mut_ptr().cast(),
            &mut system_sid_size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { EqualSid(user.User.Sid, system_sid.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows named-pipe server is not LocalSystem",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_a_non_system_server_process() {
        let result = super::verify_process_is_local_system(std::process::id());
        assert!(matches!(
            result,
            Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }
}

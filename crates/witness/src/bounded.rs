use crate::types;
use std::{io, os, process, thread, time};

const LIMIT: usize = 256 * 1024;

fn nonblocking(fd: &impl os::fd::AsRawFd) -> io::Result<()> {
    // Owned pipe descriptor, used only by this thread.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain(reader: &mut impl io::Read, bytes: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(count) if bytes.len() + count <= LIMIT => bytes.extend_from_slice(&chunk[..count]),
            Ok(_) => return Err(io::Error::other("provider output exceeds limit")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn stop(child: &mut process::Child) {
    // The child starts a separate process group; tear down descendants too.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.wait();
}

pub(crate) fn run(
    executable: &std::path::Path,
    input: &[u8],
    timeout: time::Duration,
) -> Result<Vec<u8>, types::Error> {
    let mut source = tempfile::tempfile().map_err(unavailable)?;
    io::Write::write_all(&mut source, input).map_err(unavailable)?;
    std::io::Seek::rewind(&mut source).map_err(unavailable)?;
    let mut command = process::Command::new(executable);
    command
        .stdin(source)
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped());
    let mut child = os::unix::process::CommandExt::process_group(&mut command, 0)
        .spawn()
        .map_err(unavailable)?;
    let result = collect(&mut child, timeout);
    stop(&mut child);
    result
}

fn collect(child: &mut process::Child, timeout: time::Duration) -> Result<Vec<u8>, types::Error> {
    let mut out = child
        .stdout
        .take()
        .ok_or_else(|| unavailable("missing stdout"))?;
    let mut err = child
        .stderr
        .take()
        .ok_or_else(|| unavailable("missing stderr"))?;
    nonblocking(&out).map_err(unavailable)?;
    nonblocking(&err).map_err(unavailable)?;
    let start = time::Instant::now();
    let mut output = Vec::new();
    let mut diagnostic = Vec::new();
    loop {
        drain(&mut out, &mut output).map_err(unavailable)?;
        drain(&mut err, &mut diagnostic).map_err(unavailable)?;
        if let Some(status) = child.try_wait().map_err(unavailable)? {
            drain(&mut out, &mut output).map_err(unavailable)?;
            return if status.success() {
                Ok(output)
            } else {
                Err(unavailable("provider exited unsuccessfully"))
            };
        }
        if start.elapsed() >= timeout {
            return Err(unavailable("provider deadline exceeded"));
        }
        thread::sleep(time::Duration::from_millis(5));
    }
}

fn unavailable(error: impl std::fmt::Display) -> types::Error {
    types::Error::Unavailable(error.to_string())
}

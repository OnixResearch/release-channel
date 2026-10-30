use crate::crypto;
use std::sync::mpsc;
use std::thread;

#[cfg(unix)]
struct Running {
    child: std::process::Child,
    group: i32,
}

#[cfg(unix)]
impl Drop for Running {
    fn drop(&mut self) {
        // The process group is created exclusively for this caller-owned transport capability.
        unsafe {
            libc::kill(-self.group, libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
}
pub fn verify_reply(
    pin: &[u8; 32],
    request: &crate::model::Request,
    reply: &crate::model::SignedReply,
    minimum_revision: u64,
) -> crate::Result<crate::model::Snapshot> {
    crypto::verify(
        pin,
        b"release-channel-index/reply/v1\0",
        &reply.reply,
        &reply.signature,
    )?;
    if reply.reply.namespace != request.namespace
        || reply.reply.challenge != request.challenge
        || reply.reply.request_digest != crypto::request_digest(request)?
        || reply.reply.snapshot.revision < minimum_revision
    {
        return Err("reply namespace/challenge/revision mismatch".into());
    }
    reply.reply.snapshot.validate()?;
    Ok(reply.reply.snapshot.clone())
}

/// Only an exact externally committed highest claim with no unresolved reservation is current.
pub fn require_current(
    snapshot: &crate::model::Snapshot,
    candidate: &crate::model::Claim,
) -> crate::Result<()> {
    snapshot.validate()?;
    if snapshot.pending.is_some()
        || snapshot.highest.as_ref() != Some(candidate)
        || snapshot.committed.as_ref() != Some(candidate)
    {
        return Err("external high-water rejects stale, staged or orphan claim".into());
    }
    Ok(())
}

/// std::process::Command and SSH host/key policy are caller-owned capabilities, never discovered here.
#[cfg(unix)]
pub fn exchange(
    command: &mut std::process::Command,
    request: &crate::model::SignedRequest,
    timeout: std::time::Duration,
) -> crate::Result<crate::model::SignedReply> {
    if timeout.is_zero() || timeout > std::time::Duration::from_secs(60) {
        return Err("invalid transport deadline".into());
    }
    let mut bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > crate::model::MAX_FRAME {
        return Err("request exceeds bound".into());
    }
    std::os::unix::process::CommandExt::process_group(command, 0);
    let child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let group = i32::try_from(child.id()).map_err(|_| "invalid transport process id")?;
    let mut running = Running { child, group };
    let mut input = running.child.stdin.take().ok_or("missing process stdin")?;
    let output = running
        .child
        .stdout
        .take()
        .ok_or("missing process stdout")?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| {
            std::io::Write::write_all(&mut input, &bytes).map_err(|e| e.to_string())?;
            drop(input);
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(
                &mut std::io::Read::take(output, (crate::model::MAX_FRAME + 1) as u64),
                &mut bytes,
            )
            .map_err(|e| e.to_string())?;
            if bytes.len() > crate::model::MAX_FRAME {
                return Err("response exceeds bound".into());
            }
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())
        })();
        let _ = sender.send(result);
    });
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match running.child.try_wait().map_err(|e| e.to_string())? {
            Some(status) if status.success() => {
                drop(running);
                return receiver
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                    .map_err(|_| "transport response deadline".to_string())?;
            }
            Some(_) => return Err("capability process failed".into()),
            None if std::time::Instant::now() >= deadline => {
                return Err("capability process deadline".into());
            }
            None => thread::sleep(std::time::Duration::from_millis(2)),
        }
    }
}

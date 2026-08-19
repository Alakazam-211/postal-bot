//! frpc child of `p5-agent`. Tests inject a stub binary — no live frpc.
//!
//! The child is its own process-group leader so `stop` can SIGTERM/SIGKILL
//! the whole tree without signaling the agent. On Linux, `PR_SET_PDEATHSIG`
//! kills the group leader if the agent dies hard. macOS has no death-signal
//! API — SIGHUP is handled in `p5 agent run` so hangup still reaches `stop`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Where to find the `frpc` binary.
#[derive(Debug, Clone)]
pub enum FrpcBinary {
    Auto,
    Explicit(PathBuf),
}

pub fn resolve_frpc(bin: &FrpcBinary) -> Result<PathBuf, String> {
    match bin {
        FrpcBinary::Explicit(p) => {
            if p.exists() {
                Ok(p.clone())
            } else {
                Err(format!("frpc not found at {}", p.display()))
            }
        }
        FrpcBinary::Auto => {
            if let Some(found) = which_in_path("frpc") {
                return Ok(found);
            }
            for cand in common_frpc_locations() {
                if is_executable(&cand) {
                    return Ok(cand);
                }
            }
            Err(
                "frpc not installed: Postal tunnel needs the frp client on PATH \
                 (or set P5_FRPC)"
                    .into(),
            )
        }
    }
}

fn common_frpc_locations() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/opt/homebrew/bin/frpc"),
        PathBuf::from("/usr/local/bin/frpc"),
        PathBuf::from("/usr/bin/frpc"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        v.push(home.join(".local/bin/frpc"));
        v.push(home.join(".postal/bin/frpc"));
    }
    v
}

fn which_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if is_executable(&cand) {
            return Some(cand);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Supervised `frpc -c <toml>` (or a test stub with the same argv).
#[derive(Debug)]
pub struct TunnelChild {
    child: Option<Child>,
    pid: u32,
}

impl TunnelChild {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Reap with `try_wait`. A zombie still answers `kill(pid, 0)` — that
    /// must not keep `p5 status` at `tunnel: up`.
    pub fn is_alive(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) | Err(_) => {
                self.child = None;
                false
            }
        }
    }

    /// SIGTERM the process group, then SIGKILL. Do not leave grandchildren.
    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        #[cfg(unix)]
        {
            let pid = child.id() as i32;
            if pid > 1 {
                // Negative pid = process group (child is the leader).
                unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                }
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(200) {
                    match child.try_wait() {
                        Ok(Some(_)) => return,
                        Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                        Err(_) => break,
                    }
                }
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

impl Drop for TunnelChild {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn `bin -c config`. The binary may be a stub; argv matches real frpc.
pub fn spawn_frpc(bin: &FrpcBinary, config: &Path) -> Result<TunnelChild, String> {
    let path = resolve_frpc(bin)?;
    if !config.exists() {
        return Err(format!("frpc config missing: {}", config.display()));
    }
    let mut cmd = Command::new(&path);
    cmd.arg("-c")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own PGID so stop() can kill the tree without signaling p5-agent.
        cmd.process_group(0);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // Parent gone (SIGKILL/abort) → kernel delivers SIGKILL to this child.
        cmd.pre_exec(|| {
            unsafe {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
                if libc::getppid() == 1 {
                    libc::raise(libc::SIGKILL);
                }
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn frpc {}: {e}", path.display()))?;
    let pid = child.id();
    Ok(TunnelChild {
        child: Some(child),
        pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn stub(dir: &Path) -> PathBuf {
        let path = dir.join("frpc-stub");
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\nexec sleep 60\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn spawn_stub_no_live_frpc() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = stub(tmp.path());
        let cfg = tmp.path().join("frpc.toml");
        std::fs::write(&cfg, "serverAddr = \"127.0.0.1\"\n").unwrap();
        let mut child = spawn_frpc(&FrpcBinary::Explicit(bin), &cfg).unwrap();
        let args_path = tmp.path().join("args");
        for _ in 0..80 {
            if args_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(child.is_alive(), "stub child should still be sleeping");
        let args = std::fs::read_to_string(&args_path).unwrap_or_default();
        assert!(args.contains("-c"), "missing args file or -c: {args:?}");
        assert!(args.contains("frpc.toml"), "{args}");
        child.stop();
        assert!(!child.is_alive());
    }

    #[test]
    fn is_alive_reaps_exited_stub() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("frpc-exit");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = tmp.path().join("frpc.toml");
        std::fs::write(&cfg, "serverAddr = \"127.0.0.1\"\n").unwrap();
        let mut child = spawn_frpc(&FrpcBinary::Explicit(path), &cfg).unwrap();
        let mut down = false;
        for _ in 0..40 {
            if !child.is_alive() {
                down = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            down,
            "exited stub must reap to down (not stay a live zombie)"
        );
        assert!(!child.is_alive());
    }

    #[cfg(unix)]
    #[test]
    fn spawn_owns_process_group_and_stop_kills_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("frpc-tree");
        // Grandchild inherits the new PGID; group-kill must reap it too.
        std::fs::write(
            &path,
            "#!/bin/sh\nsleep 60 &\necho $! > \"$2.gc\"\nexec sleep 60\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = tmp.path().join("frpc.toml");
        std::fs::write(&cfg, "serverAddr = \"127.0.0.1\"\n").unwrap();
        let mut child = spawn_frpc(&FrpcBinary::Explicit(path), &cfg).unwrap();
        let gc_path = cfg.with_extension("toml.gc");
        for _ in 0..40 {
            if gc_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let gc: i32 = std::fs::read_to_string(&gc_path)
            .unwrap()
            .trim()
            .parse()
            .expect("grandchild pid");
        let child_pgid = unsafe { libc::getpgid(child.pid() as i32) };
        let self_pgid = unsafe { libc::getpgid(0) };
        assert_eq!(
            child_pgid,
            child.pid() as i32,
            "frpc must lead its own group"
        );
        assert_ne!(child_pgid, self_pgid, "must not share the agent's PGID");
        let gc_pgid = unsafe { libc::getpgid(gc) };
        assert_eq!(gc_pgid, child_pgid, "grandchild stays in the tunnel group");
        assert_eq!(unsafe { libc::kill(gc, 0) }, 0, "grandchild should be live");
        child.stop();
        assert!(!child.is_alive());
        let gc_gone = unsafe { libc::kill(gc, 0) } != 0;
        assert!(
            gc_gone,
            "stop must kill the process group, not only the leader"
        );
    }

    #[test]
    fn missing_stub_is_err() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("frpc.toml");
        std::fs::write(&cfg, "x\n").unwrap();
        let err = spawn_frpc(&FrpcBinary::Explicit(tmp.path().join("nope")), &cfg).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }
}

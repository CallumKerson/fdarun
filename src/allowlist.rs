//! The allowlist of jobs that may run a program through fdarun.
//!
//! The file grants Full Disk Access, so it is only trusted when root controls
//! it and every directory above it.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const PATH: &str = "/etc/fdarun.toml";

/// The launchd domain a job runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Domain {
    /// A per-user agent, run as that user.
    Agent,
    /// A system daemon, run as root.
    Daemon,
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Domain::Agent => "agent",
            Domain::Daemon => "daemon",
        })
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, Entry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub daemons: BTreeMap<String, Entry>,
}

/// A command line a job may run, and the SHA-256 of its program.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub argv: Vec<String>,
    pub sha256: String,
}

pub fn jobs(list: &Allowlist, domain: Domain) -> &BTreeMap<String, Entry> {
    match domain {
        Domain::Agent => &list.agents,
        Domain::Daemon => &list.daemons,
    }
}

pub fn jobs_mut(list: &mut Allowlist, domain: Domain) -> &mut BTreeMap<String, Entry> {
    match domain {
        Domain::Agent => &mut list.agents,
        Domain::Daemon => &mut list.daemons,
    }
}

/// Load the allowlist at `path`, which must be controlled by `owner` or root.
///
/// A missing file is an empty allowlist.
pub fn load(path: &Path, owner: u32) -> Result<Allowlist, String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            check_directories(path, owner)?;
            return Ok(Allowlist::default());
        }
        Err(err) => return Err(format!("{}: {err}", path.display())),
    };
    if !meta.file_type().is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    check_trusted(path, &meta, owner)?;
    check_directories(path, owner)?;
    let text = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    toml::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))
}

/// Replace the allowlist at `path` atomically, readable by everyone.
pub fn save(path: &Path, list: &Allowlist, owner: u32) -> Result<(), String> {
    check_directories(path, owner)?;
    let text = toml::to_string(list).map_err(|err| err.to_string())?;
    let file_name = path.file_name().ok_or("allowlist path has no file name")?;
    let temp = path.with_file_name(format!(
        ".{}.{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let write = || -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)
    };
    write().map_err(|err| {
        let _ = fs::remove_file(&temp);
        format!("{}: {err}", path.display())
    })
}

/// Check every directory above `path`, both as written and with symlinks
/// resolved, so nobody but `owner` or root could swap the file out.
fn check_directories(path: &Path, owner: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("allowlist path has no parent")?;
    let resolved =
        fs::canonicalize(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    for dir in parent.ancestors().chain(resolved.ancestors()) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let meta = fs::symlink_metadata(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
        check_trusted(dir, &meta, owner)?;
    }
    Ok(())
}

fn check_trusted(path: &Path, meta: &fs::Metadata, owner: u32) -> Result<(), String> {
    if meta.uid() != 0 && meta.uid() != owner {
        return Err(format!("{}: not owned by root", path.display()));
    }
    // A symlink's own mode is meaningless; only its owner can change it
    if !meta.file_type().is_symlink() && meta.mode() & 0o022 != 0 {
        return Err(format!("{}: writable by group or others", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    fn uid() -> u32 {
        unsafe { libc::getuid() }
    }

    fn sample() -> Allowlist {
        let mut list = Allowlist::default();
        list.agents.insert(
            "dev.example.job".into(),
            Entry {
                argv: vec!["/bin/echo".into(), "hello".into()],
                sha256: "abc".into(),
            },
        );
        list
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let list = load(&dir.path().join("fdarun.toml"), uid()).unwrap();
        assert_eq!(list, Allowlist::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fdarun.toml");
        save(&path, &sample(), uid()).unwrap();
        assert_eq!(load(&path, uid()).unwrap(), sample());
        let mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn refuses_file_owned_by_someone_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fdarun.toml");
        save(&path, &sample(), uid()).unwrap();
        let err = load(&path, uid() + 1).unwrap_err();
        assert!(err.contains("not owned by root"), "{err}");
    }

    #[test]
    fn refuses_group_writable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fdarun.toml");
        save(&path, &sample(), uid()).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o664)).unwrap();
        let err = load(&path, uid()).unwrap_err();
        assert!(err.contains("writable by group or others"), "{err}");
    }

    #[test]
    fn refuses_writable_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("etc");
        fs::create_dir(&sub).unwrap();
        let path = sub.join("fdarun.toml");
        save(&path, &sample(), uid()).unwrap();
        fs::set_permissions(&sub, Permissions::from_mode(0o777)).unwrap();
        let err = load(&path, uid()).unwrap_err();
        assert!(err.contains("writable by group or others"), "{err}");
    }

    #[test]
    fn refuses_symlinked_file() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        save(&real, &sample(), uid()).unwrap();
        let link = dir.path().join("fdarun.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = load(&link, uid()).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn refuses_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fdarun.toml");
        fs::write(&path, "[agents.job]\nargv = []\nsha256 = \"\"\nextra = 1\n").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path, uid()).is_err());
    }
}

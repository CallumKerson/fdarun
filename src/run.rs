//! Checking a command line against the allowlist.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::allowlist::{Allowlist, Domain, Entry, jobs};

/// The SHA-256 of the file at `path`, after following symlinks, in hex.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Build an entry for `argv`, pinning its program as it is now.
pub fn entry_for(argv: &[String]) -> Result<Entry, String> {
    let program = program(argv)?;
    let sha256 = sha256_file(program).map_err(|err| format!("{}: {err}", program.display()))?;
    Ok(Entry {
        argv: argv.to_vec(),
        sha256,
    })
}

/// Check that the job `label` may run exactly `argv`, and that its program is
/// unchanged since it was allowed.
pub fn authorise(
    list: &Allowlist,
    domain: Domain,
    label: &str,
    argv: &[String],
) -> Result<(), String> {
    let entry = jobs(list, domain)
        .get(label)
        .ok_or_else(|| format!("{domain} {label} is not in the allowlist"))?;
    if entry.argv != argv {
        return Err(format!(
            "{domain} {label} may only run {:?}, not {argv:?}",
            entry.argv
        ));
    }
    check_unchanged(entry)
}

/// Check that an entry's program still has the hash it was allowed with.
pub fn check_unchanged(entry: &Entry) -> Result<(), String> {
    let program = program(&entry.argv)?;
    let sha256 = sha256_file(program).map_err(|err| format!("{}: {err}", program.display()))?;
    if sha256 != entry.sha256 {
        return Err(format!(
            "{} has changed since it was allowed; check it, then allow it again with `sudo fdarun set`",
            program.display()
        ));
    }
    Ok(())
}

fn program(argv: &[String]) -> Result<&Path, String> {
    let program = Path::new(argv.first().ok_or("no program given")?);
    if !program.is_absolute() {
        return Err(format!(
            "{}: program must be an absolute path",
            program.display()
        ));
    }
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn allow(domain: Domain, label: &str, argv: &[String]) -> Allowlist {
        let mut list = Allowlist::default();
        crate::allowlist::jobs_mut(&mut list, domain)
            .insert(label.into(), entry_for(argv).unwrap());
        list
    }

    fn script(dir: &Path) -> String {
        let path = dir.join("job.sh");
        fs::write(&path, "#!/bin/sh\necho hello\n").unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn hashes_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        fs::write(&path, "").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn allows_exact_command() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![script(dir.path()), "--flag".into()];
        let list = allow(Domain::Agent, "job", &argv);
        authorise(&list, Domain::Agent, "job", &argv).unwrap();
    }

    #[test]
    fn refuses_unknown_label() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![script(dir.path())];
        let list = allow(Domain::Agent, "job", &argv);
        let err = authorise(&list, Domain::Agent, "other", &argv).unwrap_err();
        assert!(err.contains("not in the allowlist"), "{err}");
    }

    #[test]
    fn refuses_other_domain() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![script(dir.path())];
        let list = allow(Domain::Agent, "job", &argv);
        assert!(authorise(&list, Domain::Daemon, "job", &argv).is_err());
    }

    #[test]
    fn refuses_different_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![script(dir.path())];
        let list = allow(Domain::Agent, "job", &argv);
        let other = vec![argv[0].clone(), "--extra".into()];
        let err = authorise(&list, Domain::Agent, "job", &other).unwrap_err();
        assert!(err.contains("may only run"), "{err}");
    }

    #[test]
    fn refuses_changed_program() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![script(dir.path())];
        let list = allow(Domain::Agent, "job", &argv);
        fs::write(&argv[0], "#!/bin/sh\necho changed\n").unwrap();
        let err = authorise(&list, Domain::Agent, "job", &argv).unwrap_err();
        assert!(err.contains("has changed"), "{err}");
    }

    #[test]
    fn refuses_relative_program() {
        let err = entry_for(&["job.sh".into()]).unwrap_err();
        assert!(err.contains("absolute path"), "{err}");
    }

    #[test]
    fn refuses_empty_command() {
        assert!(entry_for(&[]).is_err());
    }
}

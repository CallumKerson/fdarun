//! Working out which launchd job is running fdarun.

use crate::allowlist::Domain;

/// The job's label and domain, from what launchd gives the process.
///
/// launchd sets `XPC_SERVICE_NAME` to the job's label and is the parent of
/// every job it starts. Root runs daemons and users run agents, so the
/// effective uid picks the domain. A daemon with a `UserName` runs as that
/// user, so allow it as an agent.
pub fn identify(
    service_name: Option<&str>,
    parent: u32,
    euid: u32,
) -> Result<(String, Domain), String> {
    if parent != 1 {
        return Err(
            "not started by launchd: run fdarun from a launchd job's ProgramArguments".into(),
        );
    }
    let label = match service_name {
        Some(label) if !label.is_empty() && label != "0" => label,
        _ => return Err("XPC_SERVICE_NAME is not set, so the job's label is unknown".into()),
    };
    let domain = if euid == 0 {
        Domain::Daemon
    } else {
        Domain::Agent
    };
    Ok((label.to_owned(), domain))
}

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_agent() {
        let (label, domain) = identify(Some("dev.example.job"), 1, 501).unwrap();
        assert_eq!(label, "dev.example.job");
        assert_eq!(domain, Domain::Agent);
    }

    #[test]
    fn identifies_daemon() {
        let (_, domain) = identify(Some("dev.example.job"), 1, 0).unwrap();
        assert_eq!(domain, Domain::Daemon);
    }

    #[test]
    fn refuses_other_parent() {
        let err = identify(Some("dev.example.job"), 4242, 501).unwrap_err();
        assert!(err.contains("not started by launchd"), "{err}");
    }

    #[test]
    fn refuses_missing_label() {
        assert!(identify(None, 1, 501).is_err());
        assert!(identify(Some(""), 1, 501).is_err());
        assert!(identify(Some("0"), 1, 501).is_err());
    }
}

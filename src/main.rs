//! fdarun gives allowlisted launchd jobs Full Disk Access.
//!
//! Grant Full Disk Access to fdarun, then have a job run
//! `fdarun exec PROGRAM [ARGUMENT ...]`. fdarun checks the job may run exactly
//! that command and that its program is unchanged, then replaces itself with
//! it, so the program runs with fdarun's access.

mod allowlist;
mod caller;
mod run;

use std::env;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::allowlist::{Allowlist, Domain, jobs, jobs_mut};

#[derive(Parser)]
#[command(version, about = "Give allowlisted launchd jobs Full Disk Access")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a program, if the calling launchd job may run it
    Exec {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// List the jobs and the command each may run
    List,
    /// Allow a job to run a program, pinning the program as it is now. Needs root
    Set {
        domain: Domain,
        label: String,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Remove a job. Needs root
    Remove { domain: Domain, label: String },
    /// Change a job's label. Needs root
    Rename {
        domain: Domain,
        from: String,
        to: String,
    },
    /// Check whether this process has Full Disk Access, or whether a job may
    /// run a program
    Test {
        #[arg(requires_all = ["label", "argv"])]
        domain: Option<Domain>,
        label: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
}

fn main() -> ExitCode {
    match dispatch(Cli::parse().command) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("fdarun: {message}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command) -> Result<ExitCode, String> {
    let path = Path::new(allowlist::PATH);
    match command {
        Command::Exec { argv } => {
            let list = allowlist::load(path, 0)?;
            let service_name = env::var("XPC_SERVICE_NAME").ok();
            let parent = std::os::unix::process::parent_id();
            let (label, domain) =
                caller::identify(service_name.as_deref(), parent, caller::euid())?;
            run::authorise(&list, domain, &label, &argv)?;
            let err = run::exec(&argv);
            Err(format!("{}: {err}", argv[0]))
        }
        Command::List => {
            let list = allowlist::load(path, 0)?;
            print_list(&list);
            Ok(ExitCode::SUCCESS)
        }
        Command::Set {
            domain,
            label,
            argv,
        } => {
            let mut list = load_as_root(path)?;
            let entry = run::entry_for(&argv)?;
            jobs_mut(&mut list, domain).insert(label.clone(), entry);
            allowlist::save(path, &list, 0)?;
            println!("{domain} {label} may run {argv:?}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Remove { domain, label } => {
            let mut list = load_as_root(path)?;
            if jobs_mut(&mut list, domain).remove(&label).is_none() {
                return Err(format!("{domain} {label} is not in the allowlist"));
            }
            allowlist::save(path, &list, 0)?;
            println!("Removed {domain} {label}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Rename { domain, from, to } => {
            let mut list = load_as_root(path)?;
            let entries = jobs_mut(&mut list, domain);
            if entries.contains_key(&to) {
                return Err(format!("{domain} {to} is already in the allowlist"));
            }
            let entry = entries
                .remove(&from)
                .ok_or_else(|| format!("{domain} {from} is not in the allowlist"))?;
            entries.insert(to.clone(), entry);
            allowlist::save(path, &list, 0)?;
            println!("Renamed {domain} {from} to {to}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Test {
            domain: Some(domain),
            label: Some(label),
            argv,
        } => {
            let list = allowlist::load(path, 0)?;
            run::authorise(&list, domain, &label, &argv)?;
            println!("{domain} {label} may run {argv:?}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Test { .. } => test_access(),
    }
}

fn load_as_root(path: &Path) -> Result<Allowlist, String> {
    if caller::euid() != 0 {
        return Err("this command requires root; run it with sudo".into());
    }
    allowlist::load(path, 0)
}

fn print_list(list: &Allowlist) {
    for domain in [Domain::Agent, Domain::Daemon] {
        for (label, entry) in jobs(list, domain) {
            let status = match run::check_unchanged(entry) {
                Ok(()) => String::new(),
                Err(err) => format!("\n    refused: {err}"),
            };
            println!("{domain} {label}: {:?}{status}", entry.argv);
        }
    }
}

/// Try to open the TCC database, which only Full Disk Access allows.
///
/// macOS checks the process that launched this one, so from a terminal this
/// reports the terminal's access, not fdarun's.
fn test_access() -> Result<ExitCode, String> {
    // Readable by everyone going by its mode, but TCC allows it only with FDA
    let tcc = Path::new("/Library/Application Support/com.apple.TCC/TCC.db");
    match File::open(tcc) {
        Ok(_) => {
            println!("Full Disk Access is enabled");
            Ok(ExitCode::SUCCESS)
        }
        Err(err)
            if err.kind() == io::ErrorKind::PermissionDenied
                || err.raw_os_error() == Some(libc::EPERM) =>
        {
            println!("Full Disk Access is not enabled");
            Ok(ExitCode::FAILURE)
        }
        Err(err) => Err(format!("{}: {err}", tcc.display())),
    }
}

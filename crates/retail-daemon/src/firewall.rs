//! Windows Firewall blocks unsolicited inbound traffic by default, so hosting
//! a network needs a rule scoped to this program for as long as hosting runs.
//! Other systems have no default inbound block to undo.

#[cfg(target_os = "windows")]
const RULE: &str = "retail";

/// Returns whether a rule was added
pub fn allow_inbound() -> bool {
    #[cfg(target_os = "windows")]
    {
        let Ok(exe) = std::env::current_exe() else { return false };
        remove_inbound();
        let program = format!("program={}", exe.display());
        let name = format!("name={RULE}");
        let ok = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", &name, "dir=in", "action=allow", &program, "enable=yes", "profile=any"])
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            tracing::warn!("could not add the Windows Firewall rule; devices may not reach this server");
        }
        ok
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub fn remove_inbound() {
    #[cfg(target_os = "windows")]
    {
        let name = format!("name={RULE}");
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &name, "dir=in"])
            .output();
    }
}

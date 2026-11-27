//! Windows Firewall blocks unsolicited inbound traffic by default, so hosting
//! a network (or being a helper node) needs a rule scoped to this program for
//! as long as that runs. Other systems have no default inbound block to undo.

use std::sync::Mutex;

#[cfg(target_os = "windows")]
const RULE: &str = "retail";

/// What needs the rule now: hosting, the helper node, the helper role
static USERS: Mutex<u32> = Mutex::new(0);

/// One more user of the rule; adds it for the first. Each call is paired
/// with a `release_inbound`. Returns whether the rule is there.
pub fn allow_inbound() -> bool {
    let mut users = USERS.lock().unwrap();
    *users += 1;
    if *users > 1 {
        return cfg!(target_os = "windows");
    }
    add_rule()
}

/// One user fewer; the last takes the rule away
pub fn release_inbound() {
    let mut users = USERS.lock().unwrap();
    *users = users.saturating_sub(1);
    if *users == 0 {
        remove_inbound();
    }
}

/// A user of the rule for as long as it lives, so no error or aborted task
/// can leave the rule behind
pub struct Inbound(());

impl Inbound {
    pub fn take() -> Self {
        allow_inbound();
        Inbound(())
    }
}

impl Drop for Inbound {
    fn drop(&mut self) {
        release_inbound();
    }
}

fn add_rule() -> bool {
    #[cfg(target_os = "windows")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        remove_inbound();
        let program = format!("program={}", exe.display());
        let name = format!("name={RULE}");
        let ok = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &name,
                "dir=in",
                "action=allow",
                &program,
                "enable=yes",
                "profile=any",
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            tracing::warn!(
                "could not add the Windows Firewall rule; devices may not reach this server"
            );
        }
        ok
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Takes the rule away whoever uses it (removing retail)
pub fn remove_inbound() {
    #[cfg(target_os = "windows")]
    {
        let name = format!("name={RULE}");
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &name, "dir=in"])
            .output();
    }
}

/// Peak resident set in bytes, `None` where unsupported
pub fn peak() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kb: u64 = status
            .lines()
            .find_map(|l| l.strip_prefix("VmHWM:"))?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        Some(kb * 1024)
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: plain struct filled in by the call, and the size passed matches
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            (GetProcessMemoryInfo(GetCurrentProcess(), &mut c, size) != 0)
                .then_some(c.PeakWorkingSetSize as u64)
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: getrusage fills the struct it is given
        unsafe {
            let mut u: libc::rusage = std::mem::zeroed();
            (libc::getrusage(libc::RUSAGE_SELF, &mut u) == 0).then_some(u.ru_maxrss as u64)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        None
    }
}

/// Current resident set in bytes, `None` where unsupported
pub fn current() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kb: u64 = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        Some(kb * 1024)
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: as in `peak`
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            (GetProcessMemoryInfo(GetCurrentProcess(), &mut c, size) != 0)
                .then_some(c.WorkingSetSize as u64)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

/// Releases freed heap memory to the OS (glibc only)
/// Installed memory, where the OS says (Linux)
pub fn total() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kb: u64 = info
            .lines()
            .find(|l| l.starts_with("MemTotal:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb * 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// On a small machine (a router, a Raspberry Pi Zero, a 512 MB VPS) the
/// smallest data-plane buffers, unless a limit was set: throughput there is
/// bound by the CPU anyway, and memory is what runs out
pub fn default_limit_mb() -> Option<u32> {
    const SMALL: u64 = 1 << 30;
    (total()? < SMALL).then_some(9)
}

pub fn trim() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: plain libc call without pointers
        let released = unsafe { libc::malloc_trim(0) };
        tracing::debug!(released, "over the memory limit: trimmed the heap");
    }
}

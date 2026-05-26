//! Cross-platform resident-memory sampling.
//!
//! - Apple: `mach_task_basic_info.resident_size` via `task_info`.
//! - Linux: `/proc/self/status:VmRSS`.
//! - Other: returns `(0, 0)`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Returns (resident-or-phys-footprint, virtual_size) in bytes for the current process.
///
/// Fails loudly: zero readings would corrupt the entire point of this tool, so any
/// kernel / sysfs error bubbles up as an `anyhow::Error` and callers should treat it
/// as fatal.
pub fn process_memory() -> anyhow::Result<(u64, u64)> {
    #[cfg(target_vendor = "apple")]
    {
        apple::task_vm_info()
    }
    #[cfg(target_os = "linux")]
    {
        linux::proc_status()
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    {
        anyhow::bail!(
            "wormhole-memprof has no memory backend for this target (supported: apple, linux)"
        )
    }
}

/// Force the system allocator to return freed pages to the OS.
/// On Apple platforms calls `malloc_zone_pressure_relief(NULL, 0)`.
/// Returns (bytes released by allocator, phys before, phys after).
pub fn release_memory() -> anyhow::Result<(u64, u64, u64)> {
    let (before, _) = process_memory()?;
    let released_reported: u64;
    #[cfg(target_vendor = "apple")]
    unsafe {
        extern "C" {
            fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
        }
        released_reported = malloc_zone_pressure_relief(std::ptr::null_mut(), 0) as u64;
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        released_reported = 0;
    }
    let (after, _) = process_memory()?;
    Ok((released_reported, before, after))
}

/// A background thread that samples `phys_footprint` (or `RSS`) at a fixed
/// interval and tracks the maximum observed value. Cheap enough to run with a
/// 25-50ms period.
pub struct PeakSampler {
    peak: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PeakSampler {
    pub fn start(period_ms: u64) -> Self {
        let peak = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let peak_t = peak.clone();
        let stop_t = stop.clone();
        let handle = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                let rss = match process_memory() {
                    Ok((rss, _)) => rss,
                    Err(e) => {
                        eprintln!("ERROR: memprof sampler failed to read process memory: {e}");
                        std::process::exit(1);
                    }
                };
                let mut cur = peak_t.load(Ordering::Relaxed);
                while rss > cur {
                    match peak_t.compare_exchange_weak(
                        cur,
                        rss,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(observed) => cur = observed,
                    }
                }
                thread::sleep(Duration::from_millis(period_ms));
            }
        });
        Self {
            peak,
            stop,
            handle: Some(handle),
        }
    }

    pub fn snapshot_and_reset(&self) -> u64 {
        self.peak.swap(0, Ordering::Relaxed)
    }
}

impl Drop for PeakSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub fn fmt_mb(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(target_vendor = "apple")]
mod apple {
    use std::mem::MaybeUninit;

    /// MACH_TASK_BASIC_INFO flavor; stable layout across macOS versions.
    const MACH_TASK_BASIC_INFO: u32 = 20;

    #[repr(C)]
    #[derive(Default)]
    struct MachTaskBasicInfo {
        virtual_size: u64,
        resident_size: u64,
        resident_size_max: u64,
        user_time: [i32; 2],
        system_time: [i32; 2],
        policy: i32,
        suspend_count: i32,
    }

    extern "C" {
        fn mach_task_self() -> u32;
        fn task_info(task: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
    }

    pub fn task_vm_info() -> anyhow::Result<(u64, u64)> {
        const COUNT: u32 =
            (std::mem::size_of::<MachTaskBasicInfo>() / std::mem::size_of::<u32>()) as u32;
        let mut info: MaybeUninit<MachTaskBasicInfo> = MaybeUninit::zeroed();
        let mut count = COUNT;
        unsafe {
            let kr = task_info(
                mach_task_self(),
                MACH_TASK_BASIC_INFO,
                info.as_mut_ptr() as *mut i32,
                &mut count,
            );
            if kr != 0 {
                anyhow::bail!("task_info(MACH_TASK_BASIC_INFO) failed with kern_return_t {kr}");
            }
            let info = info.assume_init();
            Ok((info.resident_size, info.virtual_size))
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;

    pub fn proc_status() -> anyhow::Result<(u64, u64)> {
        let s = fs::read_to_string("/proc/self/status")
            .map_err(|e| anyhow::anyhow!("failed to read /proc/self/status: {e}"))?;
        let mut rss_kb: Option<u64> = None;
        let mut vsz_kb: Option<u64> = None;
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss_kb = Some(parse_kb(rest)?);
            } else if let Some(rest) = line.strip_prefix("VmSize:") {
                vsz_kb = Some(parse_kb(rest)?);
            }
        }
        let rss = rss_kb.ok_or_else(|| anyhow::anyhow!("/proc/self/status missing VmRSS"))?;
        let vsz = vsz_kb.ok_or_else(|| anyhow::anyhow!("/proc/self/status missing VmSize"))?;
        Ok((rss * 1024, vsz * 1024))
    }

    fn parse_kb(rest: &str) -> anyhow::Result<u64> {
        rest.split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty VmRSS/VmSize line"))?
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("non-numeric VmRSS/VmSize: {e}"))
    }
}

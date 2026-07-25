//! Cross-platform resident-memory sampling.
//!
//! - Apple: `mach_task_basic_info.resident_size` via `task_info`.
//! - Linux: `/proc/self/status:VmRSS`.
//! - Other: returns `(0, 0)`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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

/// Upper bound for the sampler poll period. Sampling slower than once a
/// minute cannot produce a useful peak profile, and bounding the period keeps
/// the poll loop's wait short-lived relative to any run.
pub const MAX_SAMPLE_PERIOD_MS: u64 = 60_000;

/// A background thread that samples `phys_footprint` (or `RSS`) at a fixed
/// interval and tracks the maximum observed value. Cheap enough to run with a
/// 25-50ms period.
#[derive(Debug)]
pub struct PeakSampler {
    peak: Arc<AtomicU64>,
    /// `true` once shutdown is requested; paired with the condvar so the
    /// sampler's poll wait can be interrupted immediately on drop.
    shutdown: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PeakSampler {
    /// Start the sampler thread polling every `period_ms` milliseconds.
    ///
    /// Rejects `period_ms == 0` (the poll wait would return immediately,
    /// turning the sampler into a busy loop on the process-memory read) and
    /// periods above [`MAX_SAMPLE_PERIOD_MS`] (useless for profiling). The
    /// poll wait is condvar-based, so dropping the sampler interrupts it
    /// immediately instead of blocking shutdown for up to a full period.
    pub fn start(period_ms: u64) -> anyhow::Result<Self> {
        if period_ms == 0 || period_ms > MAX_SAMPLE_PERIOD_MS {
            anyhow::bail!(
                "sample period must be between 1 and {} ms, got {}",
                MAX_SAMPLE_PERIOD_MS,
                period_ms
            );
        }
        let peak = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new((Mutex::new(false), Condvar::new()));
        let peak_t = peak.clone();
        let shutdown_t = shutdown.clone();
        let handle = thread::spawn(move || {
            let (stopped, cvar) = &*shutdown_t;
            loop {
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
                // Wait out the poll period, waking immediately on shutdown.
                let guard = stopped.lock().unwrap();
                let (guard, _timeout) = cvar
                    .wait_timeout_while(guard, Duration::from_millis(period_ms), |stop| !*stop)
                    .unwrap();
                if *guard {
                    break;
                }
            }
        });
        Ok(Self {
            peak,
            shutdown,
            handle: Some(handle),
        })
    }

    /// Read current peak without resetting.
    pub fn peek(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }

    /// Reset peak to zero without returning the old value.
    pub fn reset(&self) {
        self.peak.store(0, Ordering::Relaxed);
    }
}

impl Drop for PeakSampler {
    fn drop(&mut self) {
        let (stopped, cvar) = &*self.shutdown;
        *stopped.lock().unwrap() = true;
        cvar.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

pub fn fmt_mb(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Dropping the sampler must not block on the tail of a long poll sleep:
    /// `Drop` joins the sampler thread, so a non-interruptible
    /// `thread::sleep(period)` makes shutdown take up to a full period after
    /// the work is done (audit finding: unbounded sampler interval).
    #[test]
    fn dropping_sampler_with_long_period_is_prompt() {
        let t0 = Instant::now();
        {
            let _sampler = PeakSampler::start(10_000).unwrap();
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "dropping the sampler blocked on its poll sleep ({}ms)",
            t0.elapsed().as_millis()
        );
    }

    /// A zero period would make the poll wait return immediately, turning the
    /// sampler thread into a busy loop on the process-memory read.
    #[test]
    fn sampler_rejects_out_of_range_periods() {
        let err = PeakSampler::start(0).unwrap_err();
        assert!(err.to_string().contains("between 1 and"), "got: {err}");
        let err = PeakSampler::start(MAX_SAMPLE_PERIOD_MS + 1).unwrap_err();
        assert!(err.to_string().contains("between 1 and"), "got: {err}");
    }
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

use crate::io_feedback::IoWindow;
use crate::scanner::ScanSummary;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LATENCY_BUCKETS: usize = 32;
const TIMING_SAMPLE_INTERVAL: u64 = 64;
static SESSION: OnceLock<Metrics> = OnceLock::new();

thread_local! {
    static LOCAL_IO: RefCell<LocalIoMetrics> = RefCell::new(LocalIoMetrics::default());
}

struct LocalIoMetrics {
    open_sequence: u64,
    read_sequence: u64,
    hash_sequence: u64,
    direct_open_ops: u64,
    cached_open_ops: u64,
    open_errors: u64,
    open_samples: u64,
    open_ns: u64,
    open_min_ns: u64,
    open_max_ns: u64,
    open_latency: [u64; LATENCY_BUCKETS],
    direct_read_ops: u64,
    direct_read_bytes: u64,
    cached_read_ops: u64,
    cached_read_bytes: u64,
    read_errors: u64,
    read_samples: u64,
    read_ns: u64,
    read_min_ns: u64,
    read_max_ns: u64,
    read_latency: [u64; LATENCY_BUCKETS],
    zero_length_reads: u64,
    hash_samples: u64,
    hash_sample_bytes: u64,
    hash_ns: u64,
    hash_min_ns: u64,
    hash_max_ns: u64,
    hash_latency: [u64; LATENCY_BUCKETS],
    direct_fallbacks: u64,
    short_reads: u64,
    early_eof_retries: u64,
    buffer_allocations: u64,
    buffer_bytes: u64,
    request_size_min: u64,
    request_size_max: u64,
    read_depth_min: u64,
    read_depth_max: u64,
}

impl Default for LocalIoMetrics {
    fn default() -> Self {
        Self {
            open_sequence: 0,
            read_sequence: 0,
            hash_sequence: 0,
            direct_open_ops: 0,
            cached_open_ops: 0,
            open_errors: 0,
            open_samples: 0,
            open_ns: 0,
            open_min_ns: u64::MAX,
            open_max_ns: 0,
            open_latency: [0; LATENCY_BUCKETS],
            direct_read_ops: 0,
            direct_read_bytes: 0,
            cached_read_ops: 0,
            cached_read_bytes: 0,
            read_errors: 0,
            read_samples: 0,
            read_ns: 0,
            read_min_ns: u64::MAX,
            read_max_ns: 0,
            read_latency: [0; LATENCY_BUCKETS],
            zero_length_reads: 0,
            hash_samples: 0,
            hash_sample_bytes: 0,
            hash_ns: 0,
            hash_min_ns: u64::MAX,
            hash_max_ns: 0,
            hash_latency: [0; LATENCY_BUCKETS],
            direct_fallbacks: 0,
            short_reads: 0,
            early_eof_retries: 0,
            buffer_allocations: 0,
            buffer_bytes: 0,
            request_size_min: u64::MAX,
            request_size_max: 0,
            read_depth_min: u64::MAX,
            read_depth_max: 0,
        }
    }
}

#[derive(Default)]
struct RunInfo {
    mode: String,
    input: String,
    algorithms: String,
    result: String,
    scan: Option<ScanRecord>,
    processing: Option<Duration>,
    output: Option<OutputRecord>,
}

struct ScanRecord {
    elapsed: Duration,
    files: u64,
    bytes: u64,
    skipped: u64,
    tiny_files: u64,
    small_files: u64,
    medium_files: u64,
    large_files: u64,
    largest_file: u64,
}

struct OutputRecord {
    elapsed: Duration,
    files: usize,
    bytes: u64,
}

struct Metrics {
    started: Instant,
    started_at: SystemTime,
    info: Mutex<RunInfo>,
    storage: Mutex<Vec<String>>,
    process_start: ProcessSnapshot,
    processing_start: Mutex<Option<ProcessSnapshot>>,
    processing_end: Mutex<Option<ProcessSnapshot>>,
    finished: Mutex<Option<(Duration, ProcessSnapshot)>>,
    files_started: AtomicU64,
    files_succeeded: AtomicU64,
    files_failed: AtomicU64,
    completion_lines: AtomicU64,
    completion_draws: AtomicU64,
    largest_completion_batch: AtomicU64,
    peak_pending_completions: AtomicU64,
    direct_open_ops: AtomicU64,
    cached_open_ops: AtomicU64,
    open_errors: AtomicU64,
    open_samples: AtomicU64,
    open_ns: AtomicU64,
    open_min_ns: AtomicU64,
    open_max_ns: AtomicU64,
    open_latency: [AtomicU64; LATENCY_BUCKETS],
    direct_read_ops: AtomicU64,
    direct_read_bytes: AtomicU64,
    cached_read_ops: AtomicU64,
    cached_read_bytes: AtomicU64,
    read_errors: AtomicU64,
    read_samples: AtomicU64,
    read_ns: AtomicU64,
    read_min_ns: AtomicU64,
    read_max_ns: AtomicU64,
    read_latency: [AtomicU64; LATENCY_BUCKETS],
    zero_length_reads: AtomicU64,
    hash_ns: AtomicU64,
    hash_samples: AtomicU64,
    hash_sample_bytes: AtomicU64,
    hash_min_ns: AtomicU64,
    hash_max_ns: AtomicU64,
    hash_latency: [AtomicU64; LATENCY_BUCKETS],
    direct_fallbacks: AtomicU64,
    short_reads: AtomicU64,
    early_eof_retries: AtomicU64,
    buffer_allocations: AtomicU64,
    buffer_bytes: AtomicU64,
    request_size_min: AtomicU64,
    request_size_max: AtomicU64,
    read_depth_min: AtomicU64,
    read_depth_max: AtomicU64,
    parallel_initial: AtomicU64,
    parallel_limit: AtomicU64,
    parallel_min: AtomicU64,
    parallel_max: AtomicU64,
    parallel_samples: AtomicU64,
    parallel_first_limit_sample: AtomicU64,
    parallel_samples_at_limit: AtomicU64,
    parallel_active_sum: AtomicU64,
    parallel_active_max: AtomicU64,
    parallel_increases: AtomicU64,
    parallel_decreases: AtomicU64,
    tuner_sample_bytes: AtomicU64,
    tuner_latency_windows: AtomicU64,
    tuner_latency_samples: AtomicU64,
    tuner_p95_max_ns: AtomicU64,
    tuner_p99_max_ns: AtomicU64,
}

impl Metrics {
    fn new(mode: &str) -> Self {
        Self {
            started: Instant::now(),
            started_at: SystemTime::now(),
            info: Mutex::new(RunInfo {
                mode: mode.to_string(),
                ..RunInfo::default()
            }),
            storage: Mutex::new(Vec::new()),
            process_start: ProcessSnapshot::capture(),
            processing_start: Mutex::new(None),
            processing_end: Mutex::new(None),
            finished: Mutex::new(None),
            files_started: AtomicU64::new(0),
            files_succeeded: AtomicU64::new(0),
            files_failed: AtomicU64::new(0),
            completion_lines: AtomicU64::new(0),
            completion_draws: AtomicU64::new(0),
            largest_completion_batch: AtomicU64::new(0),
            peak_pending_completions: AtomicU64::new(0),
            direct_open_ops: AtomicU64::new(0),
            cached_open_ops: AtomicU64::new(0),
            open_errors: AtomicU64::new(0),
            open_samples: AtomicU64::new(0),
            open_ns: AtomicU64::new(0),
            open_min_ns: AtomicU64::new(u64::MAX),
            open_max_ns: AtomicU64::new(0),
            open_latency: std::array::from_fn(|_| AtomicU64::new(0)),
            direct_read_ops: AtomicU64::new(0),
            direct_read_bytes: AtomicU64::new(0),
            cached_read_ops: AtomicU64::new(0),
            cached_read_bytes: AtomicU64::new(0),
            read_errors: AtomicU64::new(0),
            read_samples: AtomicU64::new(0),
            read_ns: AtomicU64::new(0),
            read_min_ns: AtomicU64::new(u64::MAX),
            read_max_ns: AtomicU64::new(0),
            read_latency: std::array::from_fn(|_| AtomicU64::new(0)),
            zero_length_reads: AtomicU64::new(0),
            hash_ns: AtomicU64::new(0),
            hash_samples: AtomicU64::new(0),
            hash_sample_bytes: AtomicU64::new(0),
            hash_min_ns: AtomicU64::new(u64::MAX),
            hash_max_ns: AtomicU64::new(0),
            hash_latency: std::array::from_fn(|_| AtomicU64::new(0)),
            direct_fallbacks: AtomicU64::new(0),
            short_reads: AtomicU64::new(0),
            early_eof_retries: AtomicU64::new(0),
            buffer_allocations: AtomicU64::new(0),
            buffer_bytes: AtomicU64::new(0),
            request_size_min: AtomicU64::new(u64::MAX),
            request_size_max: AtomicU64::new(0),
            read_depth_min: AtomicU64::new(u64::MAX),
            read_depth_max: AtomicU64::new(0),
            parallel_initial: AtomicU64::new(0),
            parallel_limit: AtomicU64::new(0),
            parallel_min: AtomicU64::new(u64::MAX),
            parallel_max: AtomicU64::new(0),
            parallel_samples: AtomicU64::new(0),
            parallel_first_limit_sample: AtomicU64::new(u64::MAX),
            parallel_samples_at_limit: AtomicU64::new(0),
            parallel_active_sum: AtomicU64::new(0),
            parallel_active_max: AtomicU64::new(0),
            parallel_increases: AtomicU64::new(0),
            parallel_decreases: AtomicU64::new(0),
            tuner_sample_bytes: AtomicU64::new(0),
            tuner_latency_windows: AtomicU64::new(0),
            tuner_latency_samples: AtomicU64::new(0),
            tuner_p95_max_ns: AtomicU64::new(0),
            tuner_p99_max_ns: AtomicU64::new(0),
        }
    }
}

pub fn start(mode: &str) {
    let _ = SESSION.set(Metrics::new(mode));
}

pub fn set_input(input: &str) {
    with_info(|info| info.input = input.to_string());
    record_platform_storage(input);
}

pub fn set_algorithms(algorithms: String) {
    with_info(|info| info.algorithms = algorithms);
}

pub fn record_scan(elapsed: Duration, summary: &ScanSummary) {
    with_info(|info| {
        info.scan = Some(ScanRecord {
            elapsed,
            files: summary.files,
            bytes: summary.bytes,
            skipped: summary.skipped,
            tiny_files: summary.workload.tiny_files,
            small_files: summary.workload.small_files,
            medium_files: summary.workload.medium_files,
            large_files: summary.workload.large_files,
            largest_file: summary.workload.largest_file,
        });
    });
}

pub fn record_processing(elapsed: Duration) {
    with_info(|info| info.processing = Some(elapsed));
    if let Some(metrics) = metrics() {
        *metrics
            .processing_end
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(ProcessSnapshot::capture());
    }
}

pub fn begin_processing() {
    if let Some(metrics) = metrics() {
        *metrics
            .processing_start
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(ProcessSnapshot::capture());
    }
}

pub fn record_output(elapsed: Duration, paths: &[PathBuf]) {
    let bytes = paths
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .map(|metadata| metadata.len())
        .sum();
    with_info(|info| {
        info.output = Some(OutputRecord {
            elapsed,
            files: paths.len(),
            bytes,
        });
    });
}

pub fn finish(result: &Result<()>) {
    with_info(|info| {
        info.result = match result {
            Ok(()) => "success".to_string(),
            Err(error) => format!("error: {error:#}"),
        };
    });
    if let Some(metrics) = metrics() {
        *metrics
            .finished
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            Some((metrics.started.elapsed(), ProcessSnapshot::capture()));
    }
}

pub fn write_report(directory: &Path) -> Result<PathBuf> {
    let metrics = SESSION.get().context("性能报告会话尚未初始化")?;
    let timestamp = metrics
        .started_at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = directory.join(format!(
        "verihash-performance-{timestamp}-{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, metrics.render())
        .with_context(|| format!("无法写入性能报告 {}", path.display()))?;
    Ok(path)
}

pub fn record_file_totals(started: u64, succeeded: u64, failed: u64) {
    if let Some(metrics) = metrics() {
        metrics.files_started.store(started, Ordering::Relaxed);
        metrics.files_succeeded.store(succeeded, Ordering::Relaxed);
        metrics.files_failed.store(failed, Ordering::Relaxed);
    }
}

pub fn record_progress_rendering(lines: u64, draws: u64, largest_batch: u64, peak_pending: u64) {
    if let Some(metrics) = metrics() {
        metrics.completion_lines.store(lines, Ordering::Relaxed);
        metrics.completion_draws.store(draws, Ordering::Relaxed);
        metrics
            .largest_completion_batch
            .store(largest_batch, Ordering::Relaxed);
        metrics
            .peak_pending_completions
            .store(peak_pending, Ordering::Relaxed);
    }
}

pub fn record_storage(description: String) {
    let Some(metrics) = metrics() else { return };
    let mut storage = metrics
        .storage
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !storage.contains(&description) {
        storage.push(description);
    }
}

pub fn sample_open_timing() -> bool {
    sample_due(|local| &mut local.open_sequence)
}

pub fn record_open(direct: bool, success: bool, elapsed: Option<Duration>) {
    if metrics().is_none() {
        return;
    }
    LOCAL_IO.with_borrow_mut(|local| {
        if direct {
            local.direct_open_ops += 1;
        } else {
            local.cached_open_ops += 1;
        }
        if !success {
            local.open_errors += 1;
        }
        if let Some(elapsed) = elapsed {
            local.open_samples += 1;
            let nanos = duration_ns(elapsed);
            local.open_ns = local.open_ns.saturating_add(nanos);
            local.open_min_ns = local.open_min_ns.min(nanos);
            local.open_max_ns = local.open_max_ns.max(nanos);
            local.open_latency[latency_bucket(elapsed)] += 1;
        }
    });
}

pub fn sample_read_timing() -> bool {
    sample_due(|local| &mut local.read_sequence)
}

pub fn record_read(direct: bool, bytes: usize, success: bool, elapsed: Option<Duration>) {
    if metrics().is_none() {
        return;
    }
    LOCAL_IO.with_borrow_mut(|local| {
        if direct {
            local.direct_read_ops += 1;
            local.direct_read_bytes += bytes as u64;
        } else {
            local.cached_read_ops += 1;
            local.cached_read_bytes += bytes as u64;
        }
        if !success {
            local.read_errors += 1;
        } else if bytes == 0 {
            local.zero_length_reads += 1;
        }
        let Some(elapsed) = elapsed else { return };
        local.read_samples += 1;
        let nanos = duration_ns(elapsed);
        local.read_ns = local.read_ns.saturating_add(nanos);
        local.read_min_ns = local.read_min_ns.min(nanos);
        local.read_max_ns = local.read_max_ns.max(nanos);
        local.read_latency[latency_bucket(elapsed)] += 1;
    });
}

pub fn sample_hash_timing() -> bool {
    sample_due(|local| &mut local.hash_sequence)
}

pub fn record_hash(bytes: usize, elapsed: Option<Duration>) {
    if metrics().is_none() {
        return;
    }
    if let Some(elapsed) = elapsed {
        LOCAL_IO.with_borrow_mut(|local| {
            local.hash_samples += 1;
            local.hash_sample_bytes += bytes as u64;
            let nanos = duration_ns(elapsed);
            local.hash_ns = local.hash_ns.saturating_add(nanos);
            local.hash_min_ns = local.hash_min_ns.min(nanos);
            local.hash_max_ns = local.hash_max_ns.max(nanos);
            local.hash_latency[latency_bucket(elapsed)] += 1;
        });
    }
}

#[cfg(windows)]
pub fn record_direct_fallback() {
    update_local(|local| local.direct_fallbacks += 1);
}

pub fn record_short_read() {
    update_local(|local| local.short_reads += 1);
}

pub fn record_early_eof() {
    update_local(|local| local.early_eof_retries += 1);
}

pub fn record_buffer_allocation(bytes: usize) {
    update_local(|local| {
        local.buffer_allocations += 1;
        local.buffer_bytes += bytes as u64;
    });
}

pub fn record_request_size(bytes: usize) {
    update_local(|local| {
        local.request_size_min = local.request_size_min.min(bytes as u64);
        local.request_size_max = local.request_size_max.max(bytes as u64);
    });
}

pub fn record_read_depth(depth: usize) {
    update_local(|local| {
        local.read_depth_min = local.read_depth_min.min(depth as u64);
        local.read_depth_max = local.read_depth_max.max(depth as u64);
    });
}

pub fn flush_thread_metrics() {
    let Some(metrics) = metrics() else { return };
    let local = LOCAL_IO.with(|cell| std::mem::take(&mut *cell.borrow_mut()));
    add(&metrics.direct_open_ops, local.direct_open_ops);
    add(&metrics.cached_open_ops, local.cached_open_ops);
    add(&metrics.open_errors, local.open_errors);
    add(&metrics.open_samples, local.open_samples);
    add(&metrics.open_ns, local.open_ns);
    if local.open_samples > 0 {
        metrics
            .open_min_ns
            .fetch_min(local.open_min_ns, Ordering::Relaxed);
        metrics
            .open_max_ns
            .fetch_max(local.open_max_ns, Ordering::Relaxed);
    }
    for (global, value) in metrics.open_latency.iter().zip(local.open_latency) {
        add(global, value);
    }
    add(&metrics.direct_read_ops, local.direct_read_ops);
    add(&metrics.direct_read_bytes, local.direct_read_bytes);
    add(&metrics.cached_read_ops, local.cached_read_ops);
    add(&metrics.cached_read_bytes, local.cached_read_bytes);
    add(&metrics.read_errors, local.read_errors);
    add(&metrics.read_samples, local.read_samples);
    add(&metrics.read_ns, local.read_ns);
    if local.read_samples > 0 {
        metrics
            .read_min_ns
            .fetch_min(local.read_min_ns, Ordering::Relaxed);
        metrics
            .read_max_ns
            .fetch_max(local.read_max_ns, Ordering::Relaxed);
    }
    for (global, value) in metrics.read_latency.iter().zip(local.read_latency) {
        add(global, value);
    }
    add(&metrics.zero_length_reads, local.zero_length_reads);
    add(&metrics.hash_samples, local.hash_samples);
    add(&metrics.hash_sample_bytes, local.hash_sample_bytes);
    add(&metrics.hash_ns, local.hash_ns);
    if local.hash_samples > 0 {
        metrics
            .hash_min_ns
            .fetch_min(local.hash_min_ns, Ordering::Relaxed);
        metrics
            .hash_max_ns
            .fetch_max(local.hash_max_ns, Ordering::Relaxed);
    }
    for (global, value) in metrics.hash_latency.iter().zip(local.hash_latency) {
        add(global, value);
    }
    add(&metrics.direct_fallbacks, local.direct_fallbacks);
    add(&metrics.short_reads, local.short_reads);
    add(&metrics.early_eof_retries, local.early_eof_retries);
    add(&metrics.buffer_allocations, local.buffer_allocations);
    add(&metrics.buffer_bytes, local.buffer_bytes);
    if local.request_size_min != u64::MAX {
        metrics
            .request_size_min
            .fetch_min(local.request_size_min, Ordering::Relaxed);
    }
    metrics
        .request_size_max
        .fetch_max(local.request_size_max, Ordering::Relaxed);
    if local.read_depth_min != u64::MAX {
        metrics
            .read_depth_min
            .fetch_min(local.read_depth_min, Ordering::Relaxed);
    }
    metrics
        .read_depth_max
        .fetch_max(local.read_depth_max, Ordering::Relaxed);
}

fn sample_due(sequence: impl FnOnce(&mut LocalIoMetrics) -> &mut u64) -> bool {
    if metrics().is_none() {
        return false;
    }
    LOCAL_IO.with_borrow_mut(|local| {
        let sequence = sequence(local);
        *sequence = sequence.wrapping_add(1);
        *sequence == 1 || sequence.is_multiple_of(TIMING_SAMPLE_INTERVAL)
    })
}

fn latency_bucket(elapsed: Duration) -> usize {
    let micros = elapsed.as_micros().max(1).min(u128::from(u64::MAX)) as u64;
    let bucket = (u64::BITS - micros.leading_zeros() - 1) as usize;
    bucket.min(LATENCY_BUCKETS - 1)
}

fn update_local(update: impl FnOnce(&mut LocalIoMetrics)) {
    if metrics().is_some() {
        LOCAL_IO.with_borrow_mut(update);
    }
}

fn add(counter: &AtomicU64, value: u64) {
    if value != 0 {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}

pub fn record_parallelism_config(initial: usize, maximum: usize) {
    let Some(metrics) = metrics() else { return };
    metrics
        .parallel_initial
        .store(initial as u64, Ordering::Relaxed);
    metrics
        .parallel_limit
        .store(maximum as u64, Ordering::Relaxed);
    metrics
        .parallel_min
        .fetch_min(initial as u64, Ordering::Relaxed);
    metrics
        .parallel_max
        .fetch_max(initial as u64, Ordering::Relaxed);
}

pub fn record_parallelism_sample(target: usize, active: usize, bytes: u64) {
    let Some(metrics) = metrics() else { return };
    let sample = metrics.parallel_samples.fetch_add(1, Ordering::Relaxed) + 1;
    let limit = metrics.parallel_limit.load(Ordering::Relaxed);
    if limit > 0 && target as u64 >= limit {
        metrics
            .parallel_first_limit_sample
            .fetch_min(sample, Ordering::Relaxed);
        metrics
            .parallel_samples_at_limit
            .fetch_add(1, Ordering::Relaxed);
    }
    metrics
        .parallel_min
        .fetch_min(target as u64, Ordering::Relaxed);
    metrics
        .parallel_max
        .fetch_max(target as u64, Ordering::Relaxed);
    metrics
        .parallel_active_sum
        .fetch_add(active as u64, Ordering::Relaxed);
    metrics
        .parallel_active_max
        .fetch_max(active as u64, Ordering::Relaxed);
    metrics
        .tuner_sample_bytes
        .fetch_add(bytes, Ordering::Relaxed);
}

pub fn record_parallelism_change(increased: bool, target: usize) {
    let Some(metrics) = metrics() else { return };
    let counter = if increased {
        &metrics.parallel_increases
    } else {
        &metrics.parallel_decreases
    };
    counter.fetch_add(1, Ordering::Relaxed);
    metrics
        .parallel_min
        .fetch_min(target as u64, Ordering::Relaxed);
    metrics
        .parallel_max
        .fetch_max(target as u64, Ordering::Relaxed);
}

pub fn record_tuner_latency_window(window: &IoWindow) {
    let Some(metrics) = metrics() else { return };
    if window.samples == 0 {
        return;
    }
    metrics
        .tuner_latency_windows
        .fetch_add(1, Ordering::Relaxed);
    metrics
        .tuner_latency_samples
        .fetch_add(window.samples, Ordering::Relaxed);
    metrics
        .tuner_p95_max_ns
        .fetch_max(window.p95_ns, Ordering::Relaxed);
    metrics
        .tuner_p99_max_ns
        .fetch_max(window.p99_ns, Ordering::Relaxed);
}

fn metrics() -> Option<&'static Metrics> {
    SESSION.get()
}

fn with_info(update: impl FnOnce(&mut RunInfo)) {
    let Some(metrics) = metrics() else { return };
    let mut info = metrics
        .info
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    update(&mut info);
}

fn duration_ns(elapsed: Duration) -> u64 {
    elapsed.as_nanos().min(u128::from(u64::MAX)) as u64
}

impl Metrics {
    fn render(&self) -> String {
        let finished = *self
            .finished
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (elapsed, process_end) =
            finished.unwrap_or_else(|| (self.started.elapsed(), ProcessSnapshot::capture()));
        let info = self.info.lock().unwrap_or_else(|error| error.into_inner());
        let mut report = String::new();
        let _ = writeln!(report, "VeriHash Performance Report");
        let _ = writeln!(report, "===========================");
        let _ = writeln!(report, "version: {}", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(
            report,
            "platform: {}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let _ = writeln!(report, "logical_cpus: {}", num_cpus::get());
        write_platform_details(&mut report);
        let _ = writeln!(report, "mode: {}", info.mode);
        let _ = writeln!(report, "input: {}", info.input);
        let _ = writeln!(report, "algorithms: {}", info.algorithms);
        let _ = writeln!(report, "result: {}", info.result);
        let _ = writeln!(report, "wall_time: {}", duration_text(elapsed));

        report.push_str("\nWorkload\n--------\n");
        if let Some(scan) = &info.scan {
            let _ = writeln!(report, "scan_time: {}", duration_text(scan.elapsed));
            let _ = writeln!(report, "matched_files: {}", scan.files);
            let _ = writeln!(
                report,
                "matched_bytes: {} ({})",
                scan.bytes,
                bytes_text(scan.bytes)
            );
            let _ = writeln!(report, "skipped_entries: {}", scan.skipped);
            let _ = writeln!(report, "tiny_files_lt_64k: {}", scan.tiny_files);
            let _ = writeln!(report, "small_files_lt_1m: {}", scan.small_files);
            let _ = writeln!(report, "medium_files_lt_64m: {}", scan.medium_files);
            let _ = writeln!(report, "large_files_ge_64m: {}", scan.large_files);
            let _ = writeln!(
                report,
                "largest_file: {} ({})",
                scan.largest_file,
                bytes_text(scan.largest_file)
            );
        }
        if let Some(processing) = info.processing {
            let _ = writeln!(report, "processing_time: {}", duration_text(processing));
            if let Some(scan) = &info.scan {
                let _ = writeln!(
                    report,
                    "effective_processing_throughput: {}",
                    rate_text(scan.bytes, processing)
                );
            }
        }
        if let Some(output) = &info.output {
            let _ = writeln!(report, "output_time: {}", duration_text(output.elapsed));
            let _ = writeln!(report, "output_files: {}", output.files);
            let _ = writeln!(
                report,
                "output_bytes: {} ({})",
                output.bytes,
                bytes_text(output.bytes)
            );
            let _ = writeln!(
                report,
                "output_throughput: {}",
                rate_text(output.bytes, output.elapsed)
            );
        }
        line_atomic(&mut report, "files_started", &self.files_started);
        line_atomic(&mut report, "files_succeeded", &self.files_succeeded);
        line_atomic(&mut report, "files_failed", &self.files_failed);

        report.push_str("\nProgress rendering\n------------------\n");
        line_atomic(&mut report, "completion_lines", &self.completion_lines);
        line_atomic(&mut report, "completion_draws", &self.completion_draws);
        line_atomic(
            &mut report,
            "largest_completion_batch",
            &self.largest_completion_batch,
        );
        line_atomic(
            &mut report,
            "peak_pending_completions",
            &self.peak_pending_completions,
        );

        report.push_str("\nStorage\n-------\n");
        let storage = self
            .storage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if storage.is_empty() {
            report.push_str("profiles: unavailable\n");
        } else {
            for (index, profile) in storage.iter().enumerate() {
                let _ = writeln!(report, "profile_{}: {}", index + 1, profile);
            }
        }

        write_io_pipeline_heading(&mut report);
        let _ = writeln!(
            report,
            "timing_sample_interval: 1/{TIMING_SAMPLE_INTERVAL} operations"
        );
        report.push_str("counter_aggregation: thread-local, flush-on-worker-exit\n");
        report.push_str("process_snapshots: phase-boundaries-only\n");
        report.push_str("background_metrics_sampler: disabled\n");
        #[cfg(windows)]
        {
            line_atomic(&mut report, "direct_open_operations", &self.direct_open_ops);
        }
        line_atomic(&mut report, "cached_open_operations", &self.cached_open_ops);
        line_atomic(&mut report, "open_errors", &self.open_errors);
        line_atomic(&mut report, "open_timing_samples", &self.open_samples);
        line_duration(&mut report, "open_time_sampled", &self.open_ns);
        write_latency_summary(
            &mut report,
            "open",
            &self.open_samples,
            &self.open_ns,
            &self.open_min_ns,
            &self.open_max_ns,
            &self.open_latency,
        );
        #[cfg(windows)]
        {
            line_atomic(&mut report, "direct_read_operations", &self.direct_read_ops);
            line_bytes(&mut report, "direct_read_bytes", &self.direct_read_bytes);
        }
        line_atomic(&mut report, "cached_read_operations", &self.cached_read_ops);
        line_bytes(&mut report, "cached_read_bytes", &self.cached_read_bytes);
        line_atomic(
            &mut report,
            "zero_length_read_operations",
            &self.zero_length_reads,
        );
        line_atomic(&mut report, "read_errors", &self.read_errors);
        line_atomic(&mut report, "read_timing_samples", &self.read_samples);
        line_duration(&mut report, "io_wait_time_sampled", &self.read_ns);
        let reads = self.direct_read_ops.load(Ordering::Relaxed)
            + self.cached_read_ops.load(Ordering::Relaxed);
        let read_samples = self.read_samples.load(Ordering::Relaxed);
        if read_samples > 0 {
            let min = self.read_min_ns.load(Ordering::Relaxed);
            let max = self.read_max_ns.load(Ordering::Relaxed);
            let avg = self
                .read_ns
                .load(Ordering::Relaxed)
                .checked_div(read_samples)
                .unwrap_or(0);
            let _ = writeln!(report, "read_latency_min: {}", nanos_text(min));
            let _ = writeln!(report, "read_latency_avg: {}", nanos_text(avg));
            let _ = writeln!(
                report,
                "read_latency_p50_approx: {}",
                nanos_text(percentile_ns(&self.read_latency, 50))
            );
            let _ = writeln!(
                report,
                "read_latency_p95_approx: {}",
                nanos_text(percentile_ns(&self.read_latency, 95))
            );
            let _ = writeln!(
                report,
                "read_latency_p99_approx: {}",
                nanos_text(percentile_ns(&self.read_latency, 99))
            );
            let _ = writeln!(report, "read_latency_max: {}", nanos_text(max));
        }
        if reads > 0 {
            let read_bytes = self.direct_read_bytes.load(Ordering::Relaxed)
                + self.cached_read_bytes.load(Ordering::Relaxed);
            let _ = writeln!(
                report,
                "average_read_size: {}",
                bytes_text(read_bytes.checked_div(reads).unwrap_or(0))
            );
            if let Some(processing) = info.processing {
                let _ = writeln!(
                    report,
                    "pipeline_read_throughput: {}",
                    rate_text(read_bytes, processing)
                );
                let _ = writeln!(
                    report,
                    "pipeline_read_iops: {:.2}",
                    reads as f64 / processing.as_secs_f64().max(f64::EPSILON)
                );
            }
        }
        line_atomic(&mut report, "hash_timing_samples", &self.hash_samples);
        line_bytes(&mut report, "hash_sample_bytes", &self.hash_sample_bytes);
        line_duration(&mut report, "hash_update_time_sampled", &self.hash_ns);
        write_latency_summary(
            &mut report,
            "hash_update",
            &self.hash_samples,
            &self.hash_ns,
            &self.hash_min_ns,
            &self.hash_max_ns,
            &self.hash_latency,
        );
        let hash_ns = self.hash_ns.load(Ordering::Relaxed);
        if hash_ns > 0 {
            let _ = writeln!(
                report,
                "hash_update_throughput_sampled: {}",
                rate_text(
                    self.hash_sample_bytes.load(Ordering::Relaxed),
                    Duration::from_nanos(hash_ns)
                )
            );
        }
        #[cfg(windows)]
        {
            line_atomic(&mut report, "direct_io_fallbacks", &self.direct_fallbacks);
        }
        line_atomic(&mut report, "short_reads", &self.short_reads);
        line_atomic(&mut report, "early_eof_events", &self.early_eof_retries);
        #[cfg(windows)]
        {
            line_atomic(
                &mut report,
                "aligned_buffer_allocations",
                &self.buffer_allocations,
            );
            line_bytes(
                &mut report,
                "aligned_buffer_bytes_allocated",
                &self.buffer_bytes,
            );
        }
        #[cfg(not(windows))]
        {
            line_atomic(
                &mut report,
                "read_buffer_allocations",
                &self.buffer_allocations,
            );
            line_bytes(
                &mut report,
                "read_buffer_bytes_allocated",
                &self.buffer_bytes,
            );
        }
        line_atomic_or_na(
            &mut report,
            "request_size_min_bytes",
            &self.request_size_min,
            u64::MAX,
        );
        line_bytes(
            &mut report,
            "request_size_max_bytes",
            &self.request_size_max,
        );
        line_atomic_or_na(
            &mut report,
            "read_ahead_depth_min",
            &self.read_depth_min,
            u64::MAX,
        );
        line_atomic(&mut report, "read_ahead_depth_max", &self.read_depth_max);

        report.push_str("\nAdaptive concurrency\n--------------------\n");
        line_atomic(&mut report, "initial_parallelism", &self.parallel_initial);
        line_atomic(&mut report, "parallelism_limit", &self.parallel_limit);
        line_atomic_or_na(
            &mut report,
            "observed_parallelism_min",
            &self.parallel_min,
            u64::MAX,
        );
        line_atomic(&mut report, "observed_parallelism_max", &self.parallel_max);
        line_atomic(&mut report, "tuner_samples", &self.parallel_samples);
        line_atomic_or_na(
            &mut report,
            "first_limit_sample_400ms",
            &self.parallel_first_limit_sample,
            u64::MAX,
        );
        line_atomic(
            &mut report,
            "tuner_samples_at_limit",
            &self.parallel_samples_at_limit,
        );
        line_atomic(
            &mut report,
            "observed_active_parallelism_max",
            &self.parallel_active_max,
        );
        let samples = self.parallel_samples.load(Ordering::Relaxed);
        if samples > 0 {
            let average = self.parallel_active_sum.load(Ordering::Relaxed) as f64 / samples as f64;
            let _ = writeln!(report, "observed_active_parallelism_avg: {average:.2}");
            let at_limit = self.parallel_samples_at_limit.load(Ordering::Relaxed);
            let percent = at_limit as f64 * 100.0 / samples as f64;
            let _ = writeln!(report, "tuner_time_at_limit: {percent:.2}%");
        }
        line_atomic(&mut report, "tuner_increases", &self.parallel_increases);
        line_atomic(&mut report, "tuner_decreases", &self.parallel_decreases);
        line_bytes(
            &mut report,
            "bytes_observed_by_tuner",
            &self.tuner_sample_bytes,
        );
        line_atomic(
            &mut report,
            "tuner_latency_windows",
            &self.tuner_latency_windows,
        );
        line_atomic(
            &mut report,
            "tuner_latency_samples",
            &self.tuner_latency_samples,
        );
        line_duration(&mut report, "tuner_p95_max", &self.tuner_p95_max_ns);
        line_duration(&mut report, "tuner_p99_max", &self.tuner_p99_max_ns);

        let processing_start = *self
            .processing_start
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let processing_end = *self
            .processing_end
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        report.push_str("\nProcessing process counters\n---------------------------\n");
        if let (Some(start), Some(end), Some(processing_elapsed)) =
            (processing_start, processing_end, info.processing)
        {
            end.write_delta(&start, processing_elapsed, &mut report);
        } else {
            report.push_str("status: processing did not start or finish\n");
        }
        report.push_str("\nWhole-session process counters\n------------------------------\n");
        process_end.write_delta(&self.process_start, elapsed, &mut report);
        report
    }
}

fn percentile_ns(buckets: &[AtomicU64; LATENCY_BUCKETS], percentile: u64) -> u64 {
    let total = buckets
        .iter()
        .map(|bucket| bucket.load(Ordering::Relaxed))
        .sum::<u64>();
    if total == 0 {
        return 0;
    }
    let target = total.saturating_mul(percentile).div_ceil(100);
    let mut cumulative = 0u64;
    for (index, bucket) in buckets.iter().enumerate() {
        cumulative += bucket.load(Ordering::Relaxed);
        if cumulative >= target {
            return (1u64 << index).saturating_mul(1_000);
        }
    }
    1u64 << (LATENCY_BUCKETS - 1)
}

fn write_latency_summary(
    report: &mut String,
    prefix: &str,
    samples: &AtomicU64,
    total_ns: &AtomicU64,
    min_ns: &AtomicU64,
    max_ns: &AtomicU64,
    buckets: &[AtomicU64; LATENCY_BUCKETS],
) {
    let samples = samples.load(Ordering::Relaxed);
    if samples == 0 {
        return;
    }
    let average = total_ns
        .load(Ordering::Relaxed)
        .checked_div(samples)
        .unwrap_or(0);
    let _ = writeln!(
        report,
        "{prefix}_latency_min: {}",
        nanos_text(min_ns.load(Ordering::Relaxed))
    );
    let _ = writeln!(report, "{prefix}_latency_avg: {}", nanos_text(average));
    let _ = writeln!(
        report,
        "{prefix}_latency_p50_approx: {}",
        nanos_text(percentile_ns(buckets, 50))
    );
    let _ = writeln!(
        report,
        "{prefix}_latency_p95_approx: {}",
        nanos_text(percentile_ns(buckets, 95))
    );
    let _ = writeln!(
        report,
        "{prefix}_latency_p99_approx: {}",
        nanos_text(percentile_ns(buckets, 99))
    );
    let _ = writeln!(
        report,
        "{prefix}_latency_max: {}",
        nanos_text(max_ns.load(Ordering::Relaxed))
    );
}

fn line_atomic(report: &mut String, label: &str, value: &AtomicU64) {
    let _ = writeln!(report, "{label}: {}", value.load(Ordering::Relaxed));
}

fn line_atomic_or_na(report: &mut String, label: &str, value: &AtomicU64, sentinel: u64) {
    let value = value.load(Ordering::Relaxed);
    if value == sentinel {
        let _ = writeln!(report, "{label}: n/a");
    } else {
        let _ = writeln!(report, "{label}: {value}");
    }
}

fn line_bytes(report: &mut String, label: &str, value: &AtomicU64) {
    let value = value.load(Ordering::Relaxed);
    let _ = writeln!(report, "{label}: {value} ({})", bytes_text(value));
}

fn line_duration(report: &mut String, label: &str, value: &AtomicU64) {
    let _ = writeln!(
        report,
        "{label}: {}",
        nanos_text(value.load(Ordering::Relaxed))
    );
}

fn duration_text(value: Duration) -> String {
    format!("{:.6} s", value.as_secs_f64())
}

fn nanos_text(value: u64) -> String {
    if value >= 1_000_000_000 {
        format!("{:.6} s", value as f64 / 1_000_000_000.0)
    } else if value >= 1_000_000 {
        format!("{:.3} ms", value as f64 / 1_000_000.0)
    } else {
        format!("{:.3} us", value as f64 / 1_000.0)
    }
}

fn bytes_text(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.3} {}", UNITS[unit])
    }
}

fn rate_text(bytes: u64, elapsed: Duration) -> String {
    let per_second = bytes as f64 / elapsed.as_secs_f64().max(f64::EPSILON);
    format!("{}/s", bytes_text(per_second.min(u64::MAX as f64) as u64))
}

#[cfg(windows)]
fn write_io_pipeline_heading(report: &mut String) {
    report.push_str("\nWindows I/O pipeline\n--------------------\n");
}

#[cfg(target_os = "linux")]
fn write_io_pipeline_heading(report: &mut String) {
    report.push_str("\nLinux async cached I/O pipeline\n-------------------------------\n");
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn write_io_pipeline_heading(report: &mut String) {
    report.push_str("\nPortable cached I/O pipeline\n----------------------------\n");
}

#[cfg(target_os = "linux")]
fn write_platform_details(report: &mut String) {
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let _ = writeln!(report, "kernel_release: {}", release.trim());
    }
    let _ = writeln!(report, "clock_ticks_per_second: {}", linux_clock_ticks());
    let _ = writeln!(report, "page_size: {}", linux_page_size());
}

#[cfg(not(target_os = "linux"))]
fn write_platform_details(_report: &mut String) {}

#[cfg(target_os = "linux")]
fn record_platform_storage(input: &str) {
    if let Some(profile) = linux_storage_profile(input) {
        record_storage(profile);
    }
}

#[cfg(not(target_os = "linux"))]
fn record_platform_storage(_input: &str) {}

#[cfg(target_os = "linux")]
fn linux_storage_profile(input: &str) -> Option<String> {
    let path = linux_probe_path(input);
    let mount_info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut selected: Option<(usize, Vec<&str>, Vec<&str>)> = None;
    for line in mount_info.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left = left.split_whitespace().collect::<Vec<_>>();
        let right = right.split_whitespace().collect::<Vec<_>>();
        if left.len() < 6 || right.len() < 3 {
            continue;
        }
        let mount = PathBuf::from(decode_mount_field(left[4]));
        if path.starts_with(&mount) {
            let depth = mount.as_os_str().len();
            if selected.as_ref().is_none_or(|current| depth > current.0) {
                selected = Some((depth, left, right));
            }
        }
    }
    let (_, left, right) = selected?;
    let device = left[2];
    let mut fields = vec![
        "linux_io=async-buffered".to_string(),
        format!("mount={}", decode_mount_field(left[4])),
        format!("fs={}", right[0]),
        format!("source={}", decode_mount_field(right[1])),
        format!("device={device}"),
        format!("mount_options={}", left[5]),
    ];
    if let Some(queue) = linux_queue_path(device) {
        for (label, name) in [
            ("rotational", "rotational"),
            ("logical_block_size", "logical_block_size"),
            ("physical_block_size", "physical_block_size"),
            ("read_ahead_kb", "read_ahead_kb"),
            ("max_sectors_kb", "max_sectors_kb"),
            ("max_hw_sectors_kb", "max_hw_sectors_kb"),
            ("scheduler", "scheduler"),
        ] {
            if let Ok(value) = std::fs::read_to_string(queue.join(name)) {
                fields.push(format!("{label}={}", value.trim()));
            }
        }
    }
    Some(fields.join(" "))
}

#[cfg(target_os = "linux")]
fn linux_probe_path(input: &str) -> PathBuf {
    let wildcard = input.find(['*', '?', '[']).unwrap_or(input.len());
    let mut path = PathBuf::from(&input[..wildcard]);
    if path.as_os_str().is_empty() {
        path.push(".");
    }
    while !path.exists() && path.pop() {}
    path.canonicalize().unwrap_or(path)
}

#[cfg(target_os = "linux")]
fn decode_mount_field(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(target_os = "linux")]
fn linux_queue_path(device: &str) -> Option<PathBuf> {
    let mut path = std::fs::canonicalize(format!("/sys/dev/block/{device}")).ok()?;
    loop {
        let queue = path.join("queue");
        if queue.is_dir() {
            return Some(queue);
        }
        if !path.pop() {
            return None;
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_clock_ticks() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(value).unwrap_or(100).max(1)
}

#[cfg(target_os = "linux")]
fn linux_page_size() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(value).unwrap_or(4096).max(1)
}

#[cfg(windows)]
#[derive(Clone, Copy, Default)]
struct ProcessSnapshot {
    kernel_100ns: u64,
    user_100ns: u64,
    read_ops: u64,
    write_ops: u64,
    other_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
    other_bytes: u64,
    peak_working_set: u64,
    working_set: u64,
    page_faults: u64,
    peak_pagefile: u64,
}

#[cfg(windows)]
impl ProcessSnapshot {
    fn capture() -> Self {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS,
        };

        let process = unsafe { GetCurrentProcess() };
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let mut io = IO_COUNTERS::default();
        let mut memory = PROCESS_MEMORY_COUNTERS {
            cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        unsafe {
            let _ = GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user);
            let _ = GetProcessIoCounters(process, &mut io);
            let _ = GetProcessMemoryInfo(process, &mut memory, memory.cb);
        }
        Self {
            kernel_100ns: filetime_value(kernel),
            user_100ns: filetime_value(user),
            read_ops: io.ReadOperationCount,
            write_ops: io.WriteOperationCount,
            other_ops: io.OtherOperationCount,
            read_bytes: io.ReadTransferCount,
            write_bytes: io.WriteTransferCount,
            other_bytes: io.OtherTransferCount,
            peak_working_set: memory.PeakWorkingSetSize as u64,
            working_set: memory.WorkingSetSize as u64,
            page_faults: memory.PageFaultCount as u64,
            peak_pagefile: memory.PeakPagefileUsage as u64,
        }
    }

    fn write_delta(self, start: &Self, elapsed: Duration, report: &mut String) {
        let kernel = self.kernel_100ns.saturating_sub(start.kernel_100ns) as f64 / 10_000_000.0;
        let user = self.user_100ns.saturating_sub(start.user_100ns) as f64 / 10_000_000.0;
        let cpu = kernel + user;
        let capacity = elapsed.as_secs_f64() * num_cpus::get().max(1) as f64;
        let _ = writeln!(report, "cpu_kernel_time: {kernel:.6} s");
        let _ = writeln!(report, "cpu_user_time: {user:.6} s");
        let _ = writeln!(report, "cpu_total_time: {cpu:.6} s");
        let _ = writeln!(
            report,
            "cpu_utilization_all_logical: {:.2}%",
            if capacity > 0.0 {
                cpu / capacity * 100.0
            } else {
                0.0
            }
        );
        delta_line(
            report,
            "process_read_operations",
            self.read_ops,
            start.read_ops,
        );
        delta_line(
            report,
            "process_write_operations",
            self.write_ops,
            start.write_ops,
        );
        delta_line(
            report,
            "process_other_operations",
            self.other_ops,
            start.other_ops,
        );
        delta_bytes(
            report,
            "process_read_bytes",
            self.read_bytes,
            start.read_bytes,
        );
        delta_bytes(
            report,
            "process_write_bytes",
            self.write_bytes,
            start.write_bytes,
        );
        delta_bytes(
            report,
            "process_other_bytes",
            self.other_bytes,
            start.other_bytes,
        );
        let _ = writeln!(
            report,
            "working_set: {} ({})",
            self.working_set,
            bytes_text(self.working_set)
        );
        let _ = writeln!(
            report,
            "peak_working_set: {} ({})",
            self.peak_working_set,
            bytes_text(self.peak_working_set)
        );
        let _ = writeln!(
            report,
            "peak_pagefile_usage: {} ({})",
            self.peak_pagefile,
            bytes_text(self.peak_pagefile)
        );
        let _ = writeln!(
            report,
            "page_faults_delta: {}",
            self.page_faults.saturating_sub(start.page_faults)
        );
    }
}

#[cfg(windows)]
fn filetime_value(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn delta_line(report: &mut String, label: &str, end: u64, start: u64) {
    let _ = writeln!(report, "{label}: {}", end.saturating_sub(start));
}

fn delta_bytes(report: &mut String, label: &str, end: u64, start: u64) {
    let value = end.saturating_sub(start);
    let _ = writeln!(report, "{label}: {value} ({})", bytes_text(value));
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Default)]
struct ProcessSnapshot {
    available: bool,
    user_ticks: u64,
    system_ticks: u64,
    minor_faults: u64,
    major_faults: u64,
    logical_read_bytes: u64,
    logical_write_bytes: u64,
    read_syscalls: u64,
    write_syscalls: u64,
    storage_read_bytes: u64,
    storage_write_bytes: u64,
    cancelled_write_bytes: u64,
    resident_memory: u64,
    peak_resident_memory: u64,
    virtual_memory: u64,
    peak_virtual_memory: u64,
    voluntary_context_switches: u64,
    involuntary_context_switches: u64,
    threads: u64,
}

#[cfg(target_os = "linux")]
impl ProcessSnapshot {
    fn capture() -> Self {
        let mut snapshot = Self::default();
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            snapshot.available = snapshot.parse_stat(&stat);
        }
        if let Ok(io) = std::fs::read_to_string("/proc/self/io") {
            for line in io.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let value = value.trim().parse::<u64>().unwrap_or(0);
                match key {
                    "rchar" => snapshot.logical_read_bytes = value,
                    "wchar" => snapshot.logical_write_bytes = value,
                    "syscr" => snapshot.read_syscalls = value,
                    "syscw" => snapshot.write_syscalls = value,
                    "read_bytes" => snapshot.storage_read_bytes = value,
                    "write_bytes" => snapshot.storage_write_bytes = value,
                    "cancelled_write_bytes" => snapshot.cancelled_write_bytes = value,
                    _ => {}
                }
            }
        }
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let value = value.trim();
                match key {
                    "VmRSS" => snapshot.resident_memory = parse_proc_kib(value),
                    "VmHWM" => snapshot.peak_resident_memory = parse_proc_kib(value),
                    "VmSize" => snapshot.virtual_memory = parse_proc_kib(value),
                    "VmPeak" => snapshot.peak_virtual_memory = parse_proc_kib(value),
                    "Threads" => snapshot.threads = parse_proc_number(value),
                    "voluntary_ctxt_switches" => {
                        snapshot.voluntary_context_switches = parse_proc_number(value)
                    }
                    "nonvoluntary_ctxt_switches" => {
                        snapshot.involuntary_context_switches = parse_proc_number(value)
                    }
                    _ => {}
                }
            }
        }
        snapshot
    }

    fn parse_stat(&mut self, stat: &str) -> bool {
        let Some((_, fields)) = stat.rsplit_once(") ") else {
            return false;
        };
        let fields = fields.split_whitespace().collect::<Vec<_>>();
        let parse = |index: usize| {
            fields
                .get(index)
                .and_then(|value| value.parse::<u64>().ok())
        };
        let Some(minor_faults) = parse(7) else {
            return false;
        };
        let Some(major_faults) = parse(9) else {
            return false;
        };
        let Some(user_ticks) = parse(11) else {
            return false;
        };
        let Some(system_ticks) = parse(12) else {
            return false;
        };
        self.minor_faults = minor_faults;
        self.major_faults = major_faults;
        self.user_ticks = user_ticks;
        self.system_ticks = system_ticks;
        true
    }

    fn write_delta(self, start: &Self, elapsed: Duration, report: &mut String) {
        if !self.available || !start.available {
            report.push_str("native_process_counters: unavailable\n");
            return;
        }
        let ticks = linux_clock_ticks() as f64;
        let user = self.user_ticks.saturating_sub(start.user_ticks) as f64 / ticks;
        let kernel = self.system_ticks.saturating_sub(start.system_ticks) as f64 / ticks;
        let cpu = user + kernel;
        let capacity = elapsed.as_secs_f64() * num_cpus::get().max(1) as f64;
        let _ = writeln!(report, "cpu_kernel_time: {kernel:.6} s");
        let _ = writeln!(report, "cpu_user_time: {user:.6} s");
        let _ = writeln!(report, "cpu_total_time: {cpu:.6} s");
        let _ = writeln!(
            report,
            "cpu_utilization_all_logical: {:.2}%",
            if capacity > 0.0 {
                cpu / capacity * 100.0
            } else {
                0.0
            }
        );
        delta_line(
            report,
            "process_read_syscalls",
            self.read_syscalls,
            start.read_syscalls,
        );
        delta_line(
            report,
            "process_write_syscalls",
            self.write_syscalls,
            start.write_syscalls,
        );
        delta_bytes(
            report,
            "process_logical_read_bytes",
            self.logical_read_bytes,
            start.logical_read_bytes,
        );
        delta_bytes(
            report,
            "process_logical_write_bytes",
            self.logical_write_bytes,
            start.logical_write_bytes,
        );
        delta_bytes(
            report,
            "process_storage_read_bytes",
            self.storage_read_bytes,
            start.storage_read_bytes,
        );
        delta_bytes(
            report,
            "process_storage_write_bytes",
            self.storage_write_bytes,
            start.storage_write_bytes,
        );
        delta_bytes(
            report,
            "process_cancelled_write_bytes",
            self.cancelled_write_bytes,
            start.cancelled_write_bytes,
        );
        let logical_read = self
            .logical_read_bytes
            .saturating_sub(start.logical_read_bytes);
        let storage_read = self
            .storage_read_bytes
            .saturating_sub(start.storage_read_bytes);
        let _ = writeln!(
            report,
            "process_logical_read_throughput: {}",
            rate_text(logical_read, elapsed)
        );
        let _ = writeln!(
            report,
            "process_storage_read_throughput: {}",
            rate_text(storage_read, elapsed)
        );
        delta_line(
            report,
            "minor_page_faults",
            self.minor_faults,
            start.minor_faults,
        );
        delta_line(
            report,
            "major_page_faults",
            self.major_faults,
            start.major_faults,
        );
        delta_line(
            report,
            "voluntary_context_switches",
            self.voluntary_context_switches,
            start.voluntary_context_switches,
        );
        delta_line(
            report,
            "involuntary_context_switches",
            self.involuntary_context_switches,
            start.involuntary_context_switches,
        );
        let _ = writeln!(report, "threads_at_end: {}", self.threads);
        write_snapshot_bytes(report, "resident_memory", self.resident_memory);
        write_snapshot_bytes(report, "peak_resident_memory", self.peak_resident_memory);
        write_snapshot_bytes(report, "virtual_memory", self.virtual_memory);
        write_snapshot_bytes(report, "peak_virtual_memory", self.peak_virtual_memory);
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_number(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn parse_proc_kib(value: &str) -> u64 {
    parse_proc_number(value).saturating_mul(1024)
}

#[cfg(target_os = "linux")]
fn write_snapshot_bytes(report: &mut String, label: &str, value: u64) {
    let _ = writeln!(report, "{label}: {value} ({})", bytes_text(value));
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Default)]
struct ProcessSnapshot {
    available: bool,
    user_us: u64,
    system_us: u64,
    peak_resident_memory: u64,
    minor_faults: u64,
    major_faults: u64,
    input_blocks: u64,
    output_blocks: u64,
    voluntary_context_switches: u64,
    involuntary_context_switches: u64,
}

#[cfg(target_os = "macos")]
impl ProcessSnapshot {
    fn capture() -> Self {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        let available = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0;
        if !available {
            return Self::default();
        }
        let usage = unsafe { usage.assume_init() };
        Self {
            available: true,
            user_us: timeval_micros(usage.ru_utime),
            system_us: timeval_micros(usage.ru_stime),
            peak_resident_memory: usage.ru_maxrss.max(0) as u64,
            minor_faults: usage.ru_minflt.max(0) as u64,
            major_faults: usage.ru_majflt.max(0) as u64,
            input_blocks: usage.ru_inblock.max(0) as u64,
            output_blocks: usage.ru_oublock.max(0) as u64,
            voluntary_context_switches: usage.ru_nvcsw.max(0) as u64,
            involuntary_context_switches: usage.ru_nivcsw.max(0) as u64,
        }
    }

    fn write_delta(self, start: &Self, elapsed: Duration, report: &mut String) {
        if !self.available || !start.available {
            report.push_str("native_process_counters: unavailable\n");
            return;
        }
        let user = self.user_us.saturating_sub(start.user_us) as f64 / 1_000_000.0;
        let kernel = self.system_us.saturating_sub(start.system_us) as f64 / 1_000_000.0;
        let cpu = user + kernel;
        let capacity = elapsed.as_secs_f64() * num_cpus::get().max(1) as f64;
        let _ = writeln!(report, "cpu_kernel_time: {kernel:.6} s");
        let _ = writeln!(report, "cpu_user_time: {user:.6} s");
        let _ = writeln!(report, "cpu_total_time: {cpu:.6} s");
        let _ = writeln!(
            report,
            "cpu_utilization_all_logical: {:.2}%",
            if capacity > 0.0 {
                cpu / capacity * 100.0
            } else {
                0.0
            }
        );
        delta_line(
            report,
            "minor_page_faults",
            self.minor_faults,
            start.minor_faults,
        );
        delta_line(
            report,
            "major_page_faults",
            self.major_faults,
            start.major_faults,
        );
        delta_line(
            report,
            "filesystem_input_blocks",
            self.input_blocks,
            start.input_blocks,
        );
        delta_line(
            report,
            "filesystem_output_blocks",
            self.output_blocks,
            start.output_blocks,
        );
        delta_line(
            report,
            "voluntary_context_switches",
            self.voluntary_context_switches,
            start.voluntary_context_switches,
        );
        delta_line(
            report,
            "involuntary_context_switches",
            self.involuntary_context_switches,
            start.involuntary_context_switches,
        );
        let _ = writeln!(
            report,
            "peak_resident_memory: {} ({})",
            self.peak_resident_memory,
            bytes_text(self.peak_resident_memory)
        );
    }
}

#[cfg(target_os = "macos")]
fn timeval_micros(value: libc::timeval) -> u64 {
    (value.tv_sec.max(0) as u64)
        .saturating_mul(1_000_000)
        .saturating_add(value.tv_usec.max(0) as u64)
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
#[derive(Clone, Copy, Default)]
struct ProcessSnapshot;

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
impl ProcessSnapshot {
    fn capture() -> Self {
        Self
    }

    fn write_delta(self, _start: &Self, _elapsed: Duration, report: &mut String) {
        report.push_str("native_process_counters: unavailable on this platform\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_binary_byte_units() {
        assert_eq!(bytes_text(0), "0 B");
        assert_eq!(bytes_text(1024), "1.000 KiB");
    }

    #[test]
    fn renders_diagnostic_sections_without_a_completed_run() {
        let report = Metrics::new("compute").render();
        assert!(report.contains("VeriHash Performance Report"));
        assert!(report.contains("timing_sample_interval: 1/64 operations"));
        assert!(report.contains("Processing process counters"));
        assert!(report.contains("Whole-session process counters"));
        #[cfg(windows)]
        assert!(report.contains("Windows I/O pipeline"));
        #[cfg(target_os = "linux")]
        {
            assert!(report.contains("Linux async cached I/O pipeline"));
            assert!(!report.contains("Windows I/O pipeline"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_stat_with_spaces_in_process_name() {
        let mut fields = vec!["0"; 22];
        fields[0] = "S";
        fields[7] = "11";
        fields[9] = "3";
        fields[11] = "101";
        fields[12] = "29";
        let stat = format!("123 (VeriHash worker) {}", fields.join(" "));
        let mut snapshot = ProcessSnapshot::default();
        assert!(snapshot.parse_stat(&stat));
        assert_eq!(snapshot.minor_faults, 11);
        assert_eq!(snapshot.major_faults, 3);
        assert_eq!(snapshot.user_ticks, 101);
        assert_eq!(snapshot.system_ticks, 29);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn decodes_linux_mountinfo_escapes() {
        assert_eq!(decode_mount_field("/media/My\\040Disk"), "/media/My Disk");
    }
}

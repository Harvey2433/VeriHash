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
    hash_samples: u64,
    hash_sample_bytes: u64,
    hash_ns: u64,
    direct_fallbacks: u64,
    short_reads: u64,
    early_eof_retries: u64,
    buffer_allocations: u64,
    buffer_bytes: u64,
    request_size_min: u64,
    request_size_max: u64,
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
            hash_samples: 0,
            hash_sample_bytes: 0,
            hash_ns: 0,
            direct_fallbacks: 0,
            short_reads: 0,
            early_eof_retries: 0,
            buffer_allocations: 0,
            buffer_bytes: 0,
            request_size_min: u64::MAX,
            request_size_max: 0,
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
    hash_ns: AtomicU64,
    hash_samples: AtomicU64,
    hash_sample_bytes: AtomicU64,
    direct_fallbacks: AtomicU64,
    short_reads: AtomicU64,
    early_eof_retries: AtomicU64,
    buffer_allocations: AtomicU64,
    buffer_bytes: AtomicU64,
    request_size_min: AtomicU64,
    request_size_max: AtomicU64,
    parallel_initial: AtomicU64,
    parallel_limit: AtomicU64,
    parallel_min: AtomicU64,
    parallel_max: AtomicU64,
    parallel_samples: AtomicU64,
    parallel_active_sum: AtomicU64,
    parallel_active_max: AtomicU64,
    parallel_increases: AtomicU64,
    parallel_decreases: AtomicU64,
    tuner_sample_bytes: AtomicU64,
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
            hash_ns: AtomicU64::new(0),
            hash_samples: AtomicU64::new(0),
            hash_sample_bytes: AtomicU64::new(0),
            direct_fallbacks: AtomicU64::new(0),
            short_reads: AtomicU64::new(0),
            early_eof_retries: AtomicU64::new(0),
            buffer_allocations: AtomicU64::new(0),
            buffer_bytes: AtomicU64::new(0),
            request_size_min: AtomicU64::new(u64::MAX),
            request_size_max: AtomicU64::new(0),
            parallel_initial: AtomicU64::new(0),
            parallel_limit: AtomicU64::new(0),
            parallel_min: AtomicU64::new(u64::MAX),
            parallel_max: AtomicU64::new(0),
            parallel_samples: AtomicU64::new(0),
            parallel_active_sum: AtomicU64::new(0),
            parallel_active_max: AtomicU64::new(0),
            parallel_increases: AtomicU64::new(0),
            parallel_decreases: AtomicU64::new(0),
            tuner_sample_bytes: AtomicU64::new(0),
        }
    }
}

pub fn start(mode: &str) {
    let _ = SESSION.set(Metrics::new(mode));
}

pub fn set_input(input: &str) {
    with_info(|info| info.input = input.to_string());
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
            local.open_ns = local.open_ns.saturating_add(duration_ns(elapsed));
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
        }
        let Some(elapsed) = elapsed else { return };
        local.read_samples += 1;
        let nanos = duration_ns(elapsed);
        local.read_ns = local.read_ns.saturating_add(nanos);
        local.read_min_ns = local.read_min_ns.min(nanos);
        local.read_max_ns = local.read_max_ns.max(nanos);
        let micros = elapsed.as_micros().max(1) as u64;
        let bucket = (u64::BITS - micros.leading_zeros() - 1) as usize;
        local.read_latency[bucket.min(LATENCY_BUCKETS - 1)] += 1;
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
            local.hash_ns = local.hash_ns.saturating_add(duration_ns(elapsed));
        });
    }
}

pub fn record_direct_fallback() {
    update_local(|local| local.direct_fallbacks += 1);
}

pub fn record_short_read() {
    update_local(|local| local.short_reads += 1);
}

pub fn record_early_eof_retry() {
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

pub fn flush_thread_metrics() {
    let Some(metrics) = metrics() else { return };
    let local = LOCAL_IO.with(|cell| std::mem::take(&mut *cell.borrow_mut()));
    add(&metrics.direct_open_ops, local.direct_open_ops);
    add(&metrics.cached_open_ops, local.cached_open_ops);
    add(&metrics.open_errors, local.open_errors);
    add(&metrics.open_samples, local.open_samples);
    add(&metrics.open_ns, local.open_ns);
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
    add(&metrics.hash_samples, local.hash_samples);
    add(&metrics.hash_sample_bytes, local.hash_sample_bytes);
    add(&metrics.hash_ns, local.hash_ns);
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
    metrics.parallel_samples.fetch_add(1, Ordering::Relaxed);
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

        report.push_str("\nWindows I/O pipeline\n--------------------\n");
        let _ = writeln!(
            report,
            "timing_sample_interval: 1/{TIMING_SAMPLE_INTERVAL} operations"
        );
        line_atomic(&mut report, "direct_open_operations", &self.direct_open_ops);
        line_atomic(&mut report, "cached_open_operations", &self.cached_open_ops);
        line_atomic(&mut report, "open_errors", &self.open_errors);
        line_atomic(&mut report, "open_timing_samples", &self.open_samples);
        line_duration(&mut report, "open_time_sampled", &self.open_ns);
        line_atomic(&mut report, "direct_read_operations", &self.direct_read_ops);
        line_bytes(&mut report, "direct_read_bytes", &self.direct_read_bytes);
        line_atomic(&mut report, "cached_read_operations", &self.cached_read_ops);
        line_bytes(&mut report, "cached_read_bytes", &self.cached_read_bytes);
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
                nanos_text(self.percentile_ns(50))
            );
            let _ = writeln!(
                report,
                "read_latency_p95_approx: {}",
                nanos_text(self.percentile_ns(95))
            );
            let _ = writeln!(
                report,
                "read_latency_p99_approx: {}",
                nanos_text(self.percentile_ns(99))
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
        line_atomic(&mut report, "direct_io_fallbacks", &self.direct_fallbacks);
        line_atomic(&mut report, "short_reads", &self.short_reads);
        line_atomic(&mut report, "early_eof_retries", &self.early_eof_retries);
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
        line_atomic(
            &mut report,
            "observed_active_parallelism_max",
            &self.parallel_active_max,
        );
        let samples = self.parallel_samples.load(Ordering::Relaxed);
        if samples > 0 {
            let average = self.parallel_active_sum.load(Ordering::Relaxed) as f64 / samples as f64;
            let _ = writeln!(report, "observed_active_parallelism_avg: {average:.2}");
        }
        line_atomic(&mut report, "tuner_increases", &self.parallel_increases);
        line_atomic(&mut report, "tuner_decreases", &self.parallel_decreases);
        line_bytes(
            &mut report,
            "bytes_observed_by_tuner",
            &self.tuner_sample_bytes,
        );

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

    fn percentile_ns(&self, percentile: u64) -> u64 {
        let total = self
            .read_latency
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .sum::<u64>();
        if total == 0 {
            return 0;
        }
        let target = total.saturating_mul(percentile).div_ceil(100);
        let mut cumulative = 0u64;
        for (index, bucket) in self.read_latency.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                return (1u64 << index).saturating_mul(1_000);
            }
        }
        1u64 << (LATENCY_BUCKETS - 1)
    }
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

#[cfg(windows)]
fn delta_line(report: &mut String, label: &str, end: u64, start: u64) {
    let _ = writeln!(report, "{label}: {}", end.saturating_sub(start));
}

#[cfg(windows)]
fn delta_bytes(report: &mut String, label: &str, end: u64, start: u64) {
    let value = end.saturating_sub(start);
    let _ = writeln!(report, "{label}: {value} ({})", bytes_text(value));
}

#[cfg(not(windows))]
#[derive(Clone, Copy, Default)]
struct ProcessSnapshot;

#[cfg(not(windows))]
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
    }
}

use crate::algorithm::Algorithm;
use crate::concurrency::{AdaptiveGate, AdaptiveTuner, FixedGate};
use crate::hashing::{HashWorker, bulk_lane_policy, parallelism_limits};
use crate::progress::{ProgressCounters, ProgressEvent, ProgressRenderer, ProgressResult};
use crate::scanner::{FileEntry, ScanPlan};
use crate::spool::{ComputedFile, ResultSpool, SpoolWriter};
use anyhow::{Context, Result, anyhow};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

const SMALL_FILE_LIMIT: u64 = 1024 * 1024;
const BATCH_FILE_LIMIT: usize = 64;
const BATCH_BYTE_LIMIT: u64 = 8 * 1024 * 1024;
const PROGRESS_BYTE_FLUSH: u64 = 8 * 1024 * 1024;
const PROGRESS_TIME_FLUSH: Duration = Duration::from_millis(50);

struct TaskBatch {
    files: Vec<FileEntry>,
    bulk_gate: Option<Arc<FixedGate>>,
}

enum WorkResult {
    Success(ComputedFile),
    Failure(String),
}

struct WorkerContext {
    results: Sender<WorkResult>,
    events: Sender<ProgressEvent>,
    counters: Arc<ProgressCounters>,
    algorithms: Vec<Algorithm>,
    parallelism: usize,
    gate: Arc<AdaptiveGate>,
}

pub struct ComputeOutcome {
    pub spool: ResultSpool,
    pub display_results: Vec<ComputedFile>,
    pub failures: Vec<String>,
}

pub fn compute(
    plan: &mut ScanPlan,
    probe_path: &std::path::Path,
    algorithms: &[Algorithm],
) -> Result<ComputeOutcome> {
    let summary = plan.summary().clone();
    let file_count = usize::try_from(summary.files).unwrap_or(usize::MAX);
    let (initial_parallelism, worker_count) = parallelism_limits(
        probe_path,
        file_count,
        algorithms.len(),
        Some(&summary.workload),
    );
    let counters = Arc::new(ProgressCounters::default());
    let gate = Arc::new(AdaptiveGate::new(initial_parallelism, worker_count));
    let tuner = AdaptiveTuner::start(Arc::clone(&gate), Arc::clone(&counters));
    let renderer = ProgressRenderer::start(summary.bytes, Arc::clone(&counters));
    let progress_sender = renderer.sender();
    let (task_sender, task_receiver) = bounded::<TaskBatch>(worker_count * 2);
    let (result_sender, result_receiver) = bounded::<WorkResult>(worker_count * 2);
    let algorithms = algorithms.to_vec();
    let keep_display_results = summary.files <= 10;
    crate::performance::record_storage(
        "scheduler_order=per-volume-discovery-order small_batching=adjacent-only".to_string(),
    );

    let writer_algorithms = algorithms.clone();
    let writer_handle = thread::spawn(move || {
        collect_results(result_receiver, &writer_algorithms, keep_display_results)
    });

    let scan_result = thread::scope(|scope| -> Result<()> {
        for _worker in 0..worker_count {
            let tasks = task_receiver.clone();
            let results = result_sender.clone();
            let events = progress_sender.clone();
            let counters = Arc::clone(&counters);
            let gate = Arc::clone(&gate);
            let algorithms = algorithms.clone();
            scope.spawn(move || {
                worker_loop(
                    tasks,
                    WorkerContext {
                        results,
                        events,
                        counters,
                        algorithms,
                        parallelism: worker_count,
                        gate,
                    },
                )
            });
        }
        drop(task_receiver);
        let mut batch = Vec::new();
        let mut batch_bytes = 0u64;
        let mut volume_gates = HashMap::<std::path::PathBuf, Arc<FixedGate>>::new();
        plan.for_each_entry(|file| {
            if file.size >= SMALL_FILE_LIMIT {
                flush_batch(&task_sender, &mut batch, &mut batch_bytes)?;
                let (volume, limit) = bulk_lane_policy(&file.path, algorithms.len());
                let effective_limit = limit.min(worker_count);
                let bulk_gate =
                    Arc::clone(volume_gates.entry(volume.clone()).or_insert_with(|| {
                        crate::performance::record_storage(format!(
                            "scheduler_root={} bulk_stream_limit={effective_limit}",
                            volume.display()
                        ));
                        Arc::new(FixedGate::new(effective_limit))
                    }));
                task_sender
                    .send(TaskBatch {
                        files: vec![file],
                        bulk_gate: Some(bulk_gate),
                    })
                    .map_err(|_| anyhow!("任务队列提前关闭"))?;
                return Ok(());
            }
            batch_bytes += file.size;
            batch.push(file);
            if batch.len() >= BATCH_FILE_LIMIT || batch_bytes >= BATCH_BYTE_LIMIT {
                flush_batch(&task_sender, &mut batch, &mut batch_bytes)?;
            }
            Ok(())
        })?;
        flush_batch(&task_sender, &mut batch, &mut batch_bytes)?;
        drop(task_sender);
        Ok(())
    });
    tuner.finish();
    drop(result_sender);
    let outcome = writer_handle
        .join()
        .map_err(|_| anyhow!("结果写入线程异常退出"))?;
    renderer.finish();
    scan_result?;
    outcome
}

fn flush_batch(
    sender: &Sender<TaskBatch>,
    batch: &mut Vec<FileEntry>,
    batch_bytes: &mut u64,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let files = std::mem::take(batch);
    *batch_bytes = 0;
    sender
        .send(TaskBatch {
            files,
            bulk_gate: None,
        })
        .map_err(|_| anyhow!("任务队列提前关闭"))?;
    Ok(())
}

fn worker_loop(tasks: Receiver<TaskBatch>, context: WorkerContext) {
    let mut hash_worker =
        HashWorker::new(context.parallelism).map_err(|error| format!("{error:#}"));
    let mut pending_bytes = 0u64;
    let mut last_flush = Instant::now();
    for batch in tasks {
        for file in batch.files {
            let _bulk_permit = batch.bulk_gate.as_ref().map(|gate| gate.acquire());
            let _permit = context.gate.acquire();
            if let Ok(worker) = &mut hash_worker {
                worker.set_parallelism(context.gate.target());
            }
            let display_path = file.relative.display().to_string();
            context.counters.active.fetch_add(1, Ordering::Relaxed);
            let hashed = match &mut hash_worker {
                Ok(worker) => {
                    worker.hash_file(&file.path, file.size, &context.algorithms, |bytes| {
                        pending_bytes += bytes;
                        if pending_bytes >= PROGRESS_BYTE_FLUSH
                            || last_flush.elapsed() >= PROGRESS_TIME_FLUSH
                        {
                            context
                                .counters
                                .bytes
                                .fetch_add(pending_bytes, Ordering::Relaxed);
                            pending_bytes = 0;
                            last_flush = Instant::now();
                        }
                    })
                }
                Err(error) => Err(anyhow!(error.clone())),
            };
            if pending_bytes > 0 {
                context
                    .counters
                    .bytes
                    .fetch_add(pending_bytes, Ordering::Relaxed);
                pending_bytes = 0;
                last_flush = Instant::now();
            }
            context.counters.files.fetch_add(1, Ordering::Relaxed);
            let success = match hashed {
                Ok(hashes) => {
                    let _ = context.results.send(WorkResult::Success(ComputedFile {
                        relative: file.relative,
                        size: file.size,
                        hashes,
                    }));
                    true
                }
                Err(error) => {
                    context.counters.failed.fetch_add(1, Ordering::Relaxed);
                    let _ = context
                        .results
                        .send(WorkResult::Failure(format!("{error:#}")));
                    false
                }
            };
            let _ = context.events.send(ProgressEvent::Finished {
                path: display_path,
                result: if success {
                    ProgressResult::Complete
                } else {
                    ProgressResult::Failed
                },
            });
            context.counters.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn collect_results(
    receiver: Receiver<WorkResult>,
    algorithms: &[Algorithm],
    keep_display_results: bool,
) -> Result<ComputeOutcome> {
    let mut writer = SpoolWriter::new(algorithms)?;
    let mut display_results = Vec::new();
    let mut failures = Vec::new();
    for result in receiver {
        match result {
            WorkResult::Success(result) => {
                writer
                    .push(&result)
                    .with_context(|| format!("无法暂存 {}", result.relative.display()))?;
                if keep_display_results {
                    display_results.push(result);
                }
            }
            WorkResult::Failure(error) => failures.push(error),
        }
    }
    Ok(ComputeOutcome {
        spool: writer.finish()?,
        display_results,
        failures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::InputSpec;
    use std::fs;

    #[test]
    fn computes_small_mixed_batch_without_accumulation_errors() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("empty"), []).unwrap();
        fs::write(directory.path().join("hello"), b"hello").unwrap();
        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let mut plan = input.plan().unwrap();
        let mut outcome = compute(
            &mut plan,
            input.probe_path(),
            &[Algorithm::Md5, Algorithm::Sha256],
        )
        .unwrap();
        assert!(outcome.failures.is_empty());
        assert_eq!(outcome.display_results.len(), 2);
        let mut records = 0;
        outcome
            .spool
            .for_each_record(|_| {
                records += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(records, 2);
    }

    #[test]
    #[ignore = "small-file scheduler benchmark"]
    fn benchmarks_ten_thousand_small_files() {
        const FILES: usize = 10_000;
        let directory = tempfile::tempdir().unwrap();
        let contents = [0x5Au8; 4096];
        for index in 0..FILES {
            fs::write(directory.path().join(format!("{index:05}.bin")), contents).unwrap();
        }
        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let scan_started = Instant::now();
        let mut plan = input.plan().unwrap();
        let scan = scan_started.elapsed();
        let compute_started = Instant::now();
        let outcome = compute(&mut plan, input.probe_path(), &[Algorithm::Md5]).unwrap();
        let compute = compute_started.elapsed();
        assert!(outcome.failures.is_empty());
        eprintln!(
            "small_file_scan_seconds={:.6} small_file_compute_seconds={:.6} total_seconds={:.6}",
            scan.as_secs_f64(),
            compute.as_secs_f64(),
            (scan + compute).as_secs_f64()
        );
    }

    #[test]
    #[ignore = "mixed large/small scheduler benchmark"]
    fn benchmarks_mixed_large_and_small_files() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..4 {
            fs::File::create(directory.path().join(format!("large-{index}.bin")))
                .unwrap()
                .set_len(512 * 1024 * 1024)
                .unwrap();
        }
        let contents = [0xA5u8; 4096];
        for index in 0..5_000 {
            fs::write(
                directory.path().join(format!("small-{index:05}.bin")),
                contents,
            )
            .unwrap();
        }
        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let started = Instant::now();
        let mut plan = input.plan().unwrap();
        let outcome = compute(&mut plan, input.probe_path(), &[Algorithm::Md5]).unwrap();
        let elapsed = started.elapsed();
        assert!(outcome.failures.is_empty());
        eprintln!("mixed_total_seconds={:.6}", elapsed.as_secs_f64());
    }

    #[test]
    #[ignore = "parallel large-file scheduler benchmark"]
    fn benchmarks_twelve_parallel_large_files() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..12 {
            fs::File::create(directory.path().join(format!("large-{index:02}.bin")))
                .unwrap()
                .set_len(256 * 1024 * 1024)
                .unwrap();
        }
        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let started = Instant::now();
        let mut plan = input.plan().unwrap();
        let outcome = compute(&mut plan, input.probe_path(), &[Algorithm::Md5]).unwrap();
        let elapsed = started.elapsed();
        assert!(outcome.failures.is_empty());
        eprintln!("parallel_large_total_seconds={:.6}", elapsed.as_secs_f64());
    }
}

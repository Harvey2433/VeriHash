use crate::algorithm::Algorithm;
use crate::concurrency::{AdaptiveGate, AdaptiveTuner};
use crate::hashing::{HashWorker, parallelism_limits};
use crate::progress::{ProgressCounters, ProgressEvent, ProgressRenderer};
use crate::scanner::{FileEntry, InputSpec, ScanSummary};
use crate::spool::{ComputedFile, ResultSpool, SpoolWriter};
use anyhow::{Context, Result, anyhow};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

const SMALL_FILE_LIMIT: u64 = 1024 * 1024;
const BATCH_FILE_LIMIT: usize = 64;
const BATCH_BYTE_LIMIT: u64 = 8 * 1024 * 1024;
const PROGRESS_BYTE_FLUSH: u64 = 8 * 1024 * 1024;
const PROGRESS_TIME_FLUSH: Duration = Duration::from_millis(50);

#[derive(Debug)]
struct TaskBatch {
    files: Vec<FileEntry>,
}

enum WorkResult {
    Success(ComputedFile),
    Failure(String),
}

pub struct ComputeOutcome {
    pub spool: ResultSpool,
    pub display_results: Vec<ComputedFile>,
    pub failures: Vec<String>,
}

pub fn compute(
    input: &InputSpec,
    summary: &ScanSummary,
    algorithms: &[Algorithm],
) -> Result<ComputeOutcome> {
    let file_count = usize::try_from(summary.files).unwrap_or(usize::MAX);
    let (initial_parallelism, worker_count) =
        parallelism_limits(input.probe_path(), file_count, algorithms.len());
    let counters = Arc::new(ProgressCounters::default());
    let gate = Arc::new(AdaptiveGate::new(initial_parallelism, worker_count));
    let tuner = AdaptiveTuner::start(Arc::clone(&gate), Arc::clone(&counters));
    let renderer = ProgressRenderer::start(summary.bytes, Arc::clone(&counters));
    let progress_sender = renderer.sender();
    let (task_sender, task_receiver) = bounded::<TaskBatch>(worker_count * 2);
    let (result_sender, result_receiver) = bounded::<WorkResult>(worker_count * 2);
    let algorithms = algorithms.to_vec();
    let keep_display_results = summary.files <= 10;

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
                    results,
                    events,
                    counters,
                    algorithms,
                    worker_count,
                    gate,
                )
            });
        }
        drop(task_receiver);
        let mut batch = Vec::new();
        let mut batch_bytes = 0u64;
        input.visit_files(|file| {
            if file.size >= SMALL_FILE_LIMIT {
                flush_batch(&task_sender, &mut batch, &mut batch_bytes)?;
                task_sender
                    .send(TaskBatch { files: vec![file] })
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
        .send(TaskBatch { files })
        .map_err(|_| anyhow!("任务队列提前关闭"))?;
    Ok(())
}

fn worker_loop(
    tasks: Receiver<TaskBatch>,
    results: Sender<WorkResult>,
    events: Sender<ProgressEvent>,
    counters: Arc<ProgressCounters>,
    algorithms: Vec<Algorithm>,
    parallelism: usize,
    gate: Arc<AdaptiveGate>,
) {
    let mut hash_worker = HashWorker::new(parallelism).map_err(|error| format!("{error:#}"));
    let mut pending_bytes = 0u64;
    let mut last_flush = Instant::now();
    for batch in tasks {
        for file in batch.files {
            let _permit = gate.acquire();
            if let Ok(worker) = &mut hash_worker {
                worker.set_parallelism(gate.target());
            }
            let display_path = file.relative.display().to_string();
            counters.active.fetch_add(1, Ordering::Relaxed);
            let hashed = match &mut hash_worker {
                Ok(worker) => worker.hash_file(&file.path, file.size, &algorithms, |bytes| {
                    pending_bytes += bytes;
                    if pending_bytes >= PROGRESS_BYTE_FLUSH
                        || last_flush.elapsed() >= PROGRESS_TIME_FLUSH
                    {
                        counters.bytes.fetch_add(pending_bytes, Ordering::Relaxed);
                        pending_bytes = 0;
                        last_flush = Instant::now();
                    }
                }),
                Err(error) => Err(anyhow!(error.clone())),
            };
            if pending_bytes > 0 {
                counters.bytes.fetch_add(pending_bytes, Ordering::Relaxed);
                pending_bytes = 0;
                last_flush = Instant::now();
            }
            counters.files.fetch_add(1, Ordering::Relaxed);
            let success = match hashed {
                Ok(hashes) => {
                    let changed = std::fs::metadata(&file.path)
                        .map(|metadata| metadata.len() != file.size)
                        .unwrap_or(true);
                    if changed {
                        counters.failed.fetch_add(1, Ordering::Relaxed);
                        let _ = results.send(WorkResult::Failure(format!(
                            "文件在计算期间发生变化: {}",
                            file.path.display()
                        )));
                        false
                    } else {
                        let _ = results.send(WorkResult::Success(ComputedFile {
                            relative: file.relative,
                            size: file.size,
                            hashes,
                        }));
                        true
                    }
                }
                Err(error) => {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                    let _ = results.send(WorkResult::Failure(format!("{error:#}")));
                    false
                }
            };
            let _ = events.send(ProgressEvent::Finished {
                path: display_path,
                success,
            });
            counters.active.fetch_sub(1, Ordering::Relaxed);
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
    use std::fs;

    #[test]
    fn computes_small_mixed_batch_without_accumulation_errors() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("empty"), []).unwrap();
        fs::write(directory.path().join("hello"), b"hello").unwrap();
        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let summary = input.inspect().unwrap();
        let mut outcome = compute(&input, &summary, &[Algorithm::Md5, Algorithm::Sha256]).unwrap();
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
}

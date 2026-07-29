use crate::algorithm::{Algorithm, DigestValue};
use crate::concurrency::{AdaptiveGate, AdaptiveTuner};
use crate::format::detect::{self, Manifest};
use crate::hashing::{HashWorker, parallelism_limits};
use crate::progress::{ProgressCounters, ProgressEvent, ProgressRenderer};
use crate::scanner::{FileEntry, InputSpec};
use anyhow::{Result, anyhow, bail};
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

const PROGRESS_BYTE_FLUSH: u64 = 8 * 1024 * 1024;
const PROGRESS_TIME_FLUSH: Duration = Duration::from_millis(50);

#[derive(Clone, Debug)]
struct ExpectedValue {
    digest: DigestValue,
    source: PathBuf,
}

#[derive(Clone, Debug)]
pub struct VerificationJob {
    pub path: PathBuf,
    pub relative: PathBuf,
    pub size: u64,
    expected: BTreeMap<Algorithm, ExpectedValue>,
}

pub struct Discovery {
    pub jobs: Vec<VerificationJob>,
    pub unmatched: Vec<FileEntry>,
    pub unmatched_total: u64,
    pub missing: Vec<PathBuf>,
    pub manifests: usize,
    pub conflicts: Vec<String>,
}

pub struct VerificationOutcome {
    pub passed: u64,
    pub failed: Vec<String>,
    pub errors: Vec<String>,
}

enum CheckResult {
    Passed,
    Failed(String),
    Error(String),
}

pub fn discover(input: &InputSpec) -> Result<Discovery> {
    let direct = input.is_single_file();
    let mut manifests = Vec::new();
    input.visit_files(|file| {
        if detect::is_manifest_candidate(&file.path, direct)
            && let Some(manifest) = detect::detect(&file.path)?
        {
            manifests.push(manifest);
        }
        Ok(())
    })?;

    let mut expected = BTreeMap::<PathBuf, BTreeMap<Algorithm, ExpectedValue>>::new();
    let mut manifest_paths = HashSet::new();
    let mut conflicts = Vec::new();
    for manifest in &manifests {
        manifest_paths.insert(manifest.source.clone());
        merge_manifest(&mut expected, manifest, &mut conflicts);
    }

    let mut jobs = Vec::new();
    let mut scheduled = HashSet::new();
    let mut unmatched = Vec::new();
    let mut unmatched_total = 0u64;
    input.visit_files(|file| {
        if manifest_paths.contains(&file.path) {
            return Ok(());
        }
        if let Some(values) = expected.get(&file.path) {
            scheduled.insert(file.path.clone());
            jobs.push(VerificationJob {
                path: file.path,
                relative: file.relative,
                size: file.size,
                expected: values.clone(),
            });
        } else {
            unmatched_total += 1;
            if unmatched.len() < 100 {
                unmatched.push(file);
            }
        }
        Ok(())
    })?;

    let mut missing = Vec::new();
    for (path, values) in expected {
        if scheduled.contains(&path) {
            continue;
        }
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                jobs.push(VerificationJob {
                    relative: path
                        .file_name()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| path.clone()),
                    path,
                    size: metadata.len(),
                    expected: values,
                });
            }
            _ => missing.push(path),
        }
    }

    Ok(Discovery {
        jobs,
        unmatched,
        unmatched_total,
        missing,
        manifests: manifests.len(),
        conflicts,
    })
}

fn merge_manifest(
    expected: &mut BTreeMap<PathBuf, BTreeMap<Algorithm, ExpectedValue>>,
    manifest: &Manifest,
    conflicts: &mut Vec<String>,
) {
    for entry in &manifest.entries {
        let file_values = expected.entry(entry.target.clone()).or_default();
        for (algorithm, digest) in &entry.hashes {
            if let Some(existing) = file_values.get(algorithm) {
                if existing.digest != *digest {
                    conflicts.push(format!(
                        "{} 的 {} 在 {} 与 {} 中值不一致",
                        entry.target.display(),
                        algorithm,
                        existing.source.display(),
                        manifest.source.display()
                    ));
                }
            } else {
                file_values.insert(
                    algorithm.clone(),
                    ExpectedValue {
                        digest: digest.clone(),
                        source: manifest.source.clone(),
                    },
                );
            }
        }
    }
}

impl Discovery {
    pub fn add_manual(&mut self, file: &FileEntry, algorithm: Algorithm, digest: DigestValue) {
        let mut expected = BTreeMap::new();
        expected.insert(
            algorithm,
            ExpectedValue {
                digest,
                source: PathBuf::from("<manual>"),
            },
        );
        self.jobs.push(VerificationJob {
            path: file.path.clone(),
            relative: file.relative.clone(),
            size: file.size,
            expected,
        });
    }

    pub fn total_bytes(&self) -> u64 {
        self.jobs.iter().map(|job| job.size).sum()
    }

    pub fn algorithms(&self) -> Vec<Algorithm> {
        self.jobs
            .iter()
            .flat_map(|job| job.expected.keys().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

pub fn verify(discovery: &Discovery) -> Result<VerificationOutcome> {
    if !discovery.conflicts.is_empty() {
        bail!("校验清单存在冲突");
    }
    if discovery.jobs.is_empty() {
        bail!("没有可校验的文件");
    }
    let total_bytes = discovery.total_bytes();
    let (initial_parallelism, workers) = parallelism_limits(
        &discovery.jobs[0].path,
        discovery.jobs.len(),
        discovery
            .jobs
            .iter()
            .map(|job| job.expected.len())
            .max()
            .unwrap_or(1),
    );
    let counters = Arc::new(ProgressCounters::default());
    let gate = Arc::new(AdaptiveGate::new(initial_parallelism, workers));
    let tuner = AdaptiveTuner::start(Arc::clone(&gate), Arc::clone(&counters));
    let renderer = ProgressRenderer::start(total_bytes, Arc::clone(&counters));
    let events = renderer.sender();
    let (task_sender, task_receiver) = bounded::<VerificationJob>(workers * 2);
    let (result_sender, result_receiver) = unbounded::<CheckResult>();

    thread::scope(|scope| {
        for _worker in 0..workers {
            let tasks = task_receiver.clone();
            let results = result_sender.clone();
            let events = events.clone();
            let counters = Arc::clone(&counters);
            let gate = Arc::clone(&gate);
            scope.spawn(move || verify_worker(tasks, results, events, counters, workers, gate));
        }
        drop(task_receiver);
        for job in &discovery.jobs {
            if task_sender.send(job.clone()).is_err() {
                break;
            }
        }
        drop(task_sender);
    });
    tuner.finish();
    drop(result_sender);

    let mut outcome = VerificationOutcome {
        passed: 0,
        failed: Vec::new(),
        errors: Vec::new(),
    };
    for result in result_receiver {
        match result {
            CheckResult::Passed => outcome.passed += 1,
            CheckResult::Failed(message) => outcome.failed.push(message),
            CheckResult::Error(message) => outcome.errors.push(message),
        }
    }
    renderer.finish();
    Ok(outcome)
}

fn verify_worker(
    tasks: Receiver<VerificationJob>,
    results: Sender<CheckResult>,
    events: Sender<ProgressEvent>,
    counters: Arc<ProgressCounters>,
    parallelism: usize,
    gate: Arc<AdaptiveGate>,
) {
    let mut hash_worker = HashWorker::new(parallelism).map_err(|error| format!("{error:#}"));
    let mut pending_bytes = 0u64;
    let mut last_flush = Instant::now();
    for job in tasks {
        let _permit = gate.acquire();
        if let Ok(worker) = &mut hash_worker {
            worker.set_parallelism(gate.target());
        }
        let display_path = job.relative.display().to_string();
        counters.active.fetch_add(1, Ordering::Relaxed);
        let algorithms = job.expected.keys().cloned().collect::<Vec<_>>();
        let result = match &mut hash_worker {
            Ok(worker) => worker.hash_file(&job.path, job.size, &algorithms, |bytes| {
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
        let check = match result {
            Ok(hashes) => {
                let mismatches = hashes
                    .iter()
                    .filter_map(|(algorithm, actual)| {
                        let expected = &job.expected.get(algorithm)?.digest;
                        (actual != expected).then(|| {
                            format!(
                                "{}: {} 不匹配（期望 {}，实际 {}）",
                                job.relative.display(),
                                algorithm,
                                expected.to_hex(),
                                actual.to_hex()
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                if mismatches.is_empty() {
                    CheckResult::Passed
                } else {
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                    CheckResult::Failed(mismatches.join("; "))
                }
            }
            Err(error) => {
                counters.failed.fetch_add(1, Ordering::Relaxed);
                CheckResult::Error(format!("{}: {error:#}", job.relative.display()))
            }
        };
        let success = matches!(&check, CheckResult::Passed);
        if results.send(check).is_err() {
            return;
        }
        let _ = events.send(ProgressEvent::Finished {
            path: display_path,
            success,
        });
        counters.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discovers_and_verifies_openwrt_style_directory() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("empty"), []).unwrap();
        fs::write(
            directory.path().join("sha256sums"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *empty\n",
        )
        .unwrap();
        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        assert_eq!(discovery.manifests, 1);
        assert_eq!(discovery.jobs.len(), 1);
        assert_eq!(discovery.unmatched_total, 0);
        let outcome = verify(&discovery).unwrap();
        assert_eq!(outcome.passed, 1);
        assert!(outcome.failed.is_empty());
        assert!(outcome.errors.is_empty());
    }
}

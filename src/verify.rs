use crate::algorithm::{Algorithm, DigestValue};
use crate::concurrency::{AdaptiveGate, AdaptiveTuner};
use crate::format::detect::{self, Manifest};
use crate::format::write_atomic;
use crate::hashing::{HashWorker, parallelism_limits};
use crate::io_feedback::IoFeedback;
use crate::progress::{ProgressCounters, ProgressEvent, ProgressRenderer, ProgressResult};
use crate::scanner::{InputSpec, ScanPlan, ScanSummary};
use anyhow::{Context, Result, anyhow, bail};
use crossbeam_channel::{Receiver, Sender, bounded};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

const PROGRESS_BYTE_FLUSH: u64 = 8 * 1024 * 1024;
const PROGRESS_TIME_FLUSH: Duration = Duration::from_millis(50);
const REPORT_BUFFER_SIZE: usize = 1024 * 1024;
const TERMINAL_DETAIL_LIMIT: usize = 20;

#[derive(Clone, Debug)]
struct ExpectedValue {
    digest: DigestValue,
    source: PathBuf,
}

#[cfg(windows)]
type PathKey = String;
#[cfg(not(windows))]
type PathKey = PathBuf;

#[derive(Clone, Debug)]
struct ExpectedFile {
    target: PathBuf,
    values: BTreeMap<Algorithm, ExpectedValue>,
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
    pub unmatched_total: u64,
    pub missing: Vec<PathBuf>,
    pub manifests: usize,
    pub conflicts: Vec<String>,
    source_root: PathBuf,
    manifest_sources: Vec<PathBuf>,
}

pub struct DiscoveryScan {
    plan: ScanPlan,
    source_root: PathBuf,
    manifests: Vec<Manifest>,
    rejected_candidates: Vec<String>,
}

pub struct VerificationOutcome {
    pub passed: u64,
    pub mismatched: u64,
    pub error_count: u64,
    pub failed: Vec<String>,
    pub errors: Vec<String>,
    report: VerificationReportSpool,
}

enum CheckResult {
    Passed {
        path: PathBuf,
        algorithms: Vec<Algorithm>,
    },
    Failed(String),
    Error(String),
}

struct VerifyWorkerContext {
    results: Sender<CheckResult>,
    events: Sender<ProgressEvent>,
    counters: Arc<ProgressCounters>,
    parallelism: usize,
    total_jobs: u64,
    gate: Arc<AdaptiveGate>,
    feedback: Arc<IoFeedback>,
}

struct VerificationReportSpool {
    file: File,
}

#[cfg(test)]
fn discover(input: &InputSpec) -> Result<Discovery> {
    scan(input)?.finish()
}

pub fn scan(input: &InputSpec) -> Result<DiscoveryScan> {
    let direct = input.is_single_file();
    let source_root = detect::normalize_path(input.probe_path());
    let mut plan = input.plan()?;
    let mut manifests = Vec::new();
    let mut rejected_candidates = Vec::new();
    plan.for_each_entry(|file| {
        if detect::is_manifest_candidate(&file.path, direct) {
            match detect::detect(&file.path) {
                Ok(Some(mut manifest)) => {
                    rebase_manifest_targets(&mut manifest, &source_root, false);
                    if manifest_applies_to_source(&manifest, &source_root) {
                        manifests.push(manifest);
                    } else {
                        rejected_candidates.push(format!(
                            "{}: checksum targets do not match the source directory",
                            file.relative.display()
                        ));
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    rejected_candidates.push(format!("{}: {error:#}", file.relative.display()))
                }
            }
        }
        Ok(())
    })?;

    Ok(DiscoveryScan {
        plan,
        source_root,
        manifests,
        rejected_candidates,
    })
}

impl DiscoveryScan {
    pub fn summary(&self) -> &ScanSummary {
        self.plan.summary()
    }

    pub fn manifest_count(&self) -> usize {
        self.manifests.len()
    }

    pub fn rejected_candidates(&self) -> &[String] {
        &self.rejected_candidates
    }

    pub fn add_manifest_file(&mut self, path: &Path) -> Result<()> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let path = detect::normalize_path(&path);
        if !path.is_file() {
            bail!("校验文件不存在或不是普通文件: {}", path.display());
        }
        let mut manifest = detect::detect(&path)
            .with_context(|| format!("无法解析校验文件 {}", path.display()))?
            .with_context(|| format!("无法识别校验文件格式: {}", path.display()))?;
        rebase_manifest_targets(&mut manifest, &self.source_root, true);
        let source_key = path_key(&manifest.source);
        if !self
            .manifests
            .iter()
            .any(|existing| path_key(&existing.source) == source_key)
        {
            self.manifests.push(manifest);
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<Discovery> {
        let manifests = std::mem::take(&mut self.manifests);
        let manifest_sources = manifests
            .iter()
            .map(|manifest| manifest.source.clone())
            .collect::<Vec<_>>();

        let mut expected = BTreeMap::<PathKey, ExpectedFile>::new();
        let mut manifest_paths = HashSet::new();
        let mut conflicts = Vec::new();
        for manifest in &manifests {
            manifest_paths.insert(path_key(&manifest.source));
        }
        for manifest in &manifests {
            merge_manifest(&mut expected, manifest, &manifest_paths, &mut conflicts);
        }

        let mut jobs = Vec::new();
        let mut scheduled = HashSet::new();
        let mut unmatched_total = 0u64;
        self.plan.for_each_entry(|file| {
            let key = path_key(&file.path);
            if manifest_paths.contains(&key) {
                return Ok(());
            }
            if let Some(expected_file) = expected.get(&key) {
                scheduled.insert(key);
                jobs.push(VerificationJob {
                    path: file.path,
                    relative: file.relative,
                    size: file.size,
                    expected: expected_file.values.clone(),
                });
            } else {
                unmatched_total += 1;
            }
            Ok(())
        })?;

        let mut missing = Vec::new();
        for (key, expected_file) in expected {
            if scheduled.contains(&key) {
                continue;
            }
            let path = expected_file.target;
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => {
                    jobs.push(VerificationJob {
                        relative: path
                            .file_name()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| path.clone()),
                        path,
                        size: metadata.len(),
                        expected: expected_file.values,
                    });
                }
                _ => missing.push(path),
            }
        }

        Ok(Discovery {
            jobs,
            unmatched_total,
            missing,
            manifests: manifests.len(),
            conflicts,
            source_root: self.source_root,
            manifest_sources,
        })
    }
}

fn merge_manifest(
    expected: &mut BTreeMap<PathKey, ExpectedFile>,
    manifest: &Manifest,
    manifest_paths: &HashSet<PathKey>,
    conflicts: &mut Vec<String>,
) {
    for entry in &manifest.entries {
        let target_key = path_key(&entry.target);
        if manifest_paths.contains(&target_key) {
            continue;
        }
        let expected_file = expected.entry(target_key).or_insert_with(|| ExpectedFile {
            target: detect::normalize_path(&entry.target),
            values: BTreeMap::new(),
        });
        for (algorithm, digest) in &entry.hashes {
            if let Some(existing) = expected_file.values.get(algorithm) {
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
                expected_file.values.insert(
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

fn manifest_applies_to_source(manifest: &Manifest, source_root: &Path) -> bool {
    const SAMPLE_LIMIT: usize = 64;
    let source_key = path_key(&manifest.source);
    let eligible = manifest
        .entries
        .iter()
        .filter(|entry| path_key(&entry.target) != source_key)
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return false;
    }
    let sample_count = eligible.len().min(SAMPLE_LIMIT);
    let mut matches = 0usize;
    for sample in 0..sample_count {
        let index = sample * eligible.len() / sample_count;
        let target = &eligible[index].target;
        if path_is_within(target, source_root) && target.is_file() {
            matches += 1;
        }
    }
    matches > 0 && matches.saturating_mul(4) >= sample_count
}

fn rebase_manifest_targets(
    manifest: &mut Manifest,
    source_root: &Path,
    prefer_source_on_tie: bool,
) {
    const SAMPLE_LIMIT: usize = 64;
    let manifest_base = manifest.source.parent().unwrap_or_else(|| Path::new("."));
    let relative = manifest
        .entries
        .iter()
        .filter_map(|entry| entry.relative_target.as_ref())
        .collect::<Vec<_>>();
    if relative.is_empty() {
        return;
    }
    let sample_count = relative.len().min(SAMPLE_LIMIT);
    let score = |base: &Path| {
        (0..sample_count)
            .filter(|sample| {
                let index = *sample * relative.len() / sample_count;
                detect::normalize_path(&base.join(relative[index])).is_file()
            })
            .count()
    };
    let source_score = score(source_root);
    let manifest_score = score(manifest_base);
    let use_source = source_score > manifest_score
        || (prefer_source_on_tie
            && source_score == manifest_score
            && path_key(source_root) != path_key(manifest_base));
    if !use_source {
        return;
    }
    for entry in &mut manifest.entries {
        if let Some(relative) = &entry.relative_target {
            entry.target = detect::normalize_path(&source_root.join(relative));
        }
    }
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = detect::normalize_path(path);
    let root = detect::normalize_path(root);
    #[cfg(windows)]
    {
        let path = path.to_string_lossy().to_lowercase();
        let mut root = root.to_string_lossy().to_lowercase();
        if path == root {
            return true;
        }
        if !root.ends_with(['\\', '/']) {
            root.push('\\');
        }
        path.starts_with(&root)
    }
    #[cfg(not(windows))]
    {
        path.starts_with(root)
    }
}

fn path_key(path: &Path) -> PathKey {
    let normalized = detect::normalize_path(path);
    #[cfg(windows)]
    {
        normalized.to_string_lossy().to_lowercase()
    }
    #[cfg(not(windows))]
    {
        normalized
    }
}

impl Discovery {
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

pub fn write_report(
    outcome: &mut VerificationOutcome,
    discovery: &Discovery,
    path: &Path,
) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("无法创建校验报告目录 {}", parent.display()))?;
    let algorithms = discovery
        .algorithms()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let missing = discovery.missing.len() as u64;
    let failed = outcome.mismatched + outcome.error_count + missing;

    write_atomic(path, |writer| {
        writeln!(writer, "VeriHash Verification Report")?;
        writeln!(writer, "============================")?;
        writeln!(writer, "version: {}", env!("CARGO_PKG_VERSION"))?;
        writeln!(writer, "source: {}", discovery.source_root.display())?;
        writeln!(writer, "algorithms: {algorithms}")?;
        writeln!(writer, "checksum_files: {}", discovery.manifests)?;
        for manifest in &discovery.manifest_sources {
            writeln!(writer, "checksum_file: {}", manifest.display())?;
        }
        writeln!(
            writer,
            "result: {}",
            if failed == 0 { "success" } else { "failed" }
        )?;
        writeln!(writer)?;
        writeln!(writer, "Results")?;
        writeln!(writer, "-------")?;

        outcome.report.file.seek(SeekFrom::Start(0))?;
        let mut body = BufReader::with_capacity(REPORT_BUFFER_SIZE, &mut outcome.report.file);
        std::io::copy(&mut body, writer)?;
        for missing_path in &discovery.missing {
            writeln!(
                writer,
                "MISSING\t{}",
                report_field(&missing_path.display().to_string())
            )?;
        }

        writeln!(writer)?;
        writeln!(writer, "Summary")?;
        writeln!(writer, "-------")?;
        writeln!(writer, "passed: {}", outcome.passed)?;
        writeln!(writer, "mismatched: {}", outcome.mismatched)?;
        writeln!(writer, "errors: {}", outcome.error_count)?;
        writeln!(writer, "missing: {missing}")?;
        Ok(())
    })
    .with_context(|| format!("无法写入校验报告 {}", path.display()))
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
        None,
    );
    let counters = Arc::new(ProgressCounters::default());
    let feedback = Arc::new(IoFeedback::default());
    let gate = Arc::new(AdaptiveGate::new(initial_parallelism, workers));
    let tuner = AdaptiveTuner::start(
        Arc::clone(&gate),
        Arc::clone(&counters),
        Arc::clone(&feedback),
    );
    let renderer = ProgressRenderer::start(total_bytes, Arc::clone(&counters));
    let events = renderer.sender();
    let total_jobs = discovery.jobs.len() as u64;
    let (task_sender, task_receiver) = bounded::<VerificationJob>(workers * 2);
    let (result_sender, result_receiver) = bounded::<CheckResult>(workers * 2);
    let collector = thread::spawn(move || collect_verification_results(result_receiver));

    thread::scope(|scope| {
        for _worker in 0..workers {
            let tasks = task_receiver.clone();
            let results = result_sender.clone();
            let events = events.clone();
            let counters = Arc::clone(&counters);
            let gate = Arc::clone(&gate);
            let feedback = Arc::clone(&feedback);
            scope.spawn(move || {
                verify_worker(
                    tasks,
                    VerifyWorkerContext {
                        results,
                        events,
                        counters,
                        parallelism: workers,
                        total_jobs,
                        gate,
                        feedback,
                    },
                )
            });
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
    let outcome = collector
        .join()
        .map_err(|_| anyhow!("校验结果收集线程异常退出"))
        .and_then(|outcome| outcome);
    renderer.finish();
    outcome
}

fn collect_verification_results(results: Receiver<CheckResult>) -> Result<VerificationOutcome> {
    let file = tempfile::tempfile()?;
    let mut writer = BufWriter::with_capacity(REPORT_BUFFER_SIZE, file);
    let mut passed = 0u64;
    let mut mismatched = 0u64;
    let mut error_count = 0u64;
    let mut failed = Vec::new();
    let mut errors = Vec::new();

    for result in results {
        match result {
            CheckResult::Passed { path, algorithms } => {
                passed += 1;
                writeln!(
                    writer,
                    "VERIFIED\t{}\t{}",
                    report_field(&path.display().to_string()),
                    algorithms
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
            }
            CheckResult::Failed(message) => {
                mismatched += 1;
                writeln!(writer, "MISMATCH\t{}", report_field(&message))?;
                if failed.len() < TERMINAL_DETAIL_LIMIT {
                    failed.push(message);
                }
            }
            CheckResult::Error(message) => {
                error_count += 1;
                writeln!(writer, "ERROR\t{}", report_field(&message))?;
                if errors.len() < TERMINAL_DETAIL_LIMIT {
                    errors.push(message);
                }
            }
        }
    }

    writer.flush()?;
    let mut file = writer.into_inner()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(VerificationOutcome {
        passed,
        mismatched,
        error_count,
        failed,
        errors,
        report: VerificationReportSpool { file },
    })
}

fn report_field(value: &str) -> String {
    value
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn verify_worker(tasks: Receiver<VerificationJob>, context: VerifyWorkerContext) {
    let mut hash_worker =
        HashWorker::with_feedback(context.parallelism, Arc::clone(&context.feedback))
            .map_err(|error| format!("{error:#}"));
    let mut pending_bytes = 0u64;
    let mut last_flush = Instant::now();
    for job in tasks {
        let _permit = context.gate.acquire();
        if let Ok(worker) = &mut hash_worker {
            let remaining = context
                .total_jobs
                .saturating_sub(context.counters.files.load(Ordering::Relaxed));
            let effective = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(context.gate.target())
                .max(context.gate.active())
                .max(1);
            worker.set_parallelism(effective);
        }
        let display_path = job.relative.display().to_string();
        context.counters.active.fetch_add(1, Ordering::Relaxed);
        let algorithms = job.expected.keys().cloned().collect::<Vec<_>>();
        let result = match &mut hash_worker {
            Ok(worker) => worker.hash_file(&job.path, job.size, &algorithms, |bytes| {
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
            }),
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
        let check = match result {
            Ok(hashes) => {
                let mismatches = hashes
                    .iter()
                    .filter_map(|(algorithm, actual)| {
                        let expected = &job.expected.get(algorithm)?.digest;
                        (actual != expected).then(|| {
                            format!(
                                "{}: {} 不匹配 (期望 {}, 实际 {})",
                                job.relative.display(),
                                algorithm,
                                expected.to_hex(),
                                actual.to_hex()
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                if mismatches.is_empty() {
                    CheckResult::Passed {
                        path: job.relative.clone(),
                        algorithms,
                    }
                } else {
                    context.counters.failed.fetch_add(1, Ordering::Relaxed);
                    CheckResult::Failed(mismatches.join("; "))
                }
            }
            Err(error) => {
                context.counters.failed.fetch_add(1, Ordering::Relaxed);
                CheckResult::Error(format!("{}: {error:#}", job.relative.display()))
            }
        };
        let progress_result = match &check {
            CheckResult::Passed { .. } => ProgressResult::Verified,
            CheckResult::Failed(_) => ProgressResult::Mismatch,
            CheckResult::Error(_) => ProgressResult::Error,
        };
        if context.results.send(check).is_err() {
            return;
        }
        let _ = context.events.send(ProgressEvent::Finished {
            path: display_path,
            result: progress_result,
        });
        context.counters.active.fetch_sub(1, Ordering::Relaxed);
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

    #[test]
    fn discovers_and_verifies_mixed_supported_manifests() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("checksums.blazehash"),
            "%%%% HASHDEEP-1.0\n%%%% size,md5,sha256,filename\n3,900150983cd24fb0d6963f7d28e17f72,ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad,./sample.txt\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("checksums.verihash"),
            "#MD5#  900150983cd24fb0d6963f7d28e17f72  ./sample.txt\n\n#SHA256#  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  ./sample.txt\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("checksums.txt"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad *./sample.txt\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        assert_eq!(discovery.manifests, 3);
        assert_eq!(discovery.jobs.len(), 1);
        assert_eq!(discovery.unmatched_total, 0);
        assert!(discovery.missing.is_empty());
        assert!(discovery.conflicts.is_empty());

        let outcome = verify(&discovery).unwrap();
        assert_eq!(outcome.passed, 1);
        assert!(outcome.failed.is_empty());
        assert!(outcome.errors.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn matches_windows_manifest_targets_case_insensitively() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("md5sums"),
            "900150983cd24fb0d6963f7d28e17f72 *SAMPLE.TXT\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        assert_eq!(discovery.jobs.len(), 1);
        assert_eq!(discovery.unmatched_total, 0);
        assert!(discovery.missing.is_empty());
        assert_eq!(verify(&discovery).unwrap().passed, 1);
    }

    #[test]
    fn reports_digest_mismatches_as_failures() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("md5sums"),
            "d41d8cd98f00b204e9800998ecf8427e *sample.txt\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        let outcome = verify(&discovery).unwrap();
        assert_eq!(outcome.passed, 0);
        assert_eq!(outcome.failed.len(), 1);
        assert!(outcome.errors.is_empty());
    }

    #[test]
    fn exports_verification_results_instead_of_computed_hashes() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("good.txt"), b"abc").unwrap();
        fs::write(directory.path().join("bad.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("md5sums"),
            concat!(
                "900150983cd24fb0d6963f7d28e17f72 *good.txt\n",
                "d41d8cd98f00b204e9800998ecf8427e *bad.txt\n",
                "d41d8cd98f00b204e9800998ecf8427e *missing.txt\n"
            ),
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        let mut outcome = verify(&discovery).unwrap();
        let report_path = directory.path().join("verification-report.txt");
        write_report(&mut outcome, &discovery, &report_path).unwrap();
        let report = fs::read_to_string(report_path).unwrap();

        assert!(report.contains("VERIFIED\tgood.txt\tMD5"));
        assert!(report.contains("MISMATCH\tbad.txt: MD5"));
        assert!(report.contains("MISSING\t"));
        assert!(report.contains("missing.txt"));
        assert!(report.contains("passed: 1"));
        assert!(report.contains("mismatched: 1"));
        assert!(report.contains("missing: 1"));
        assert!(!report.contains("#MD5#"));
    }

    #[test]
    fn adds_external_manifest_without_rescanning_source() {
        let source = tempfile::tempdir().unwrap();
        let manifests = tempfile::tempdir().unwrap();
        let target = source.path().join("sample.txt");
        fs::write(&target, b"abc").unwrap();
        let manifest = manifests.path().join("md5sums");
        fs::write(&manifest, "900150983cd24fb0d6963f7d28e17f72 *sample.txt\n").unwrap();

        let input = InputSpec::parse(source.path().to_str().unwrap()).unwrap();
        let mut scan = scan(&input).unwrap();
        assert_eq!(scan.manifest_count(), 0);
        scan.add_manifest_file(&manifest).unwrap();
        let discovery = scan.finish().unwrap();
        assert_eq!(discovery.manifests, 1);
        assert_eq!(discovery.jobs.len(), 1);
        assert_eq!(verify(&discovery).unwrap().passed, 1);
    }

    #[test]
    fn malformed_manifest_does_not_abort_automatic_scan() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("checksums.verihash"),
            "#MD5#  not-a-digest  sample.txt\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let scan = scan(&input).unwrap();
        assert_eq!(scan.manifest_count(), 0);
        assert_eq!(scan.rejected_candidates().len(), 1);
    }

    #[test]
    fn discovers_and_verifies_single_file_sidecar() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("sample.txt.md5"),
            "900150983cd24fb0d6963f7d28e17f72\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        assert_eq!(discovery.manifests, 1);
        assert_eq!(discovery.jobs.len(), 1);
        assert_eq!(discovery.unmatched_total, 0);
        assert_eq!(verify(&discovery).unwrap().passed, 1);
    }

    #[test]
    fn rejects_automatic_manifest_for_another_source_tree() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("md5sums"),
            "900150983cd24fb0d6963f7d28e17f72 *../another-tree/sample.txt\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let scan = scan(&input).unwrap();
        assert_eq!(scan.manifest_count(), 0);
        assert_eq!(scan.rejected_candidates().len(), 1);
    }

    #[test]
    fn ignores_a_manifests_self_digest() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("checksums.verihash"),
            "#MD5#  d41d8cd98f00b204e9800998ecf8427e  checksums.verihash\n#MD5#  900150983cd24fb0d6963f7d28e17f72  sample.txt\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        assert_eq!(discovery.jobs.len(), 1);
        assert_eq!(verify(&discovery).unwrap().passed, 1);
    }

    #[test]
    fn ignores_cross_references_between_manifests() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("sample.txt"), b"abc").unwrap();
        fs::write(
            directory.path().join("checksums.verihash"),
            "#MD5#  d41d8cd98f00b204e9800998ecf8427e  checksums.blazehash\n#MD5#  900150983cd24fb0d6963f7d28e17f72  sample.txt\n",
        )
        .unwrap();
        fs::write(
            directory.path().join("checksums.blazehash"),
            "%%%% HASHDEEP-1.0\n%%%% size,md5,filename\n0,d41d8cd98f00b204e9800998ecf8427e,checksums.verihash\n3,900150983cd24fb0d6963f7d28e17f72,sample.txt\n",
        )
        .unwrap();

        let input = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let discovery = discover(&input).unwrap();
        assert_eq!(discovery.manifests, 2);
        assert_eq!(discovery.jobs.len(), 1);
        assert_eq!(verify(&discovery).unwrap().passed, 1);
    }
}

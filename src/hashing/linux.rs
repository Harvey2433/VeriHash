use super::{Algorithm, DigestValue, MultiHasher, READ_BUFFER_SIZE};
use crate::io_feedback::{self, IoFeedback};
use crate::performance;
use crate::scanner::WorkloadSummary;
use anyhow::{Context, Result, anyhow};
use compio::buf::{BufResult, IoBuf, IoBufMut, SetLen};
use compio::fs::OpenOptions;
use compio::io::AsyncReadAt;
use compio::runtime::{JoinHandle, Runtime, spawn};
use std::collections::VecDeque;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const PIPELINE_FILE_LIMIT: u64 = 4 * 1024 * 1024;
const DEEP_PIPELINE_FILE_LIMIT: u64 = 64 * 1024 * 1024;
const NORMAL_READ_DEPTH: usize = 2;
const DEEP_READ_DEPTH: usize = 4;

pub fn parallelism_limits(
    _path: &Path,
    files: usize,
    algorithm_count: usize,
    _workload: Option<&WorkloadSummary>,
) -> (usize, usize) {
    let cpus = num_cpus::get().max(1);
    let cpu_limit = if algorithm_count >= 4 {
        cpus.div_ceil(2)
    } else {
        cpus
    };
    let maximum = if algorithm_count <= 2 {
        cpu_limit.saturating_mul(2)
    } else {
        cpu_limit
    };
    let maximum = files.min(maximum).max(1);
    let initial = files.min(cpu_limit).min(maximum).max(1);
    performance::record_storage(format!(
        "linux_async_io=compio initial_workers={initial} maximum_workers={maximum}"
    ));
    (initial, maximum)
}

pub fn bulk_lane_policy(path: &Path, algorithm_count: usize) -> (PathBuf, usize) {
    let cpus = num_cpus::get().max(1);
    let limit = if algorithm_count >= 4 {
        cpus.div_ceil(2)
    } else {
        cpus
    };
    (
        path.ancestors()
            .last()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf(),
        limit.max(1),
    )
}

pub struct LinuxHashWorker {
    runtime: Runtime,
    buffers: Vec<ReadBuffer>,
    parallelism: usize,
    feedback: Arc<IoFeedback>,
}

impl LinuxHashWorker {
    pub fn new(parallelism: usize, feedback: Arc<IoFeedback>) -> Result<Self> {
        let runtime = Runtime::new().context("无法创建 Linux 异步 I/O runtime")?;
        performance::record_storage(format!(
            "linux_async_backend={:?} buffered_io=true",
            runtime.driver_type()
        ));
        Ok(Self {
            runtime,
            buffers: Vec::new(),
            parallelism: parallelism.max(1),
            feedback,
        })
    }

    pub fn hash_file<F>(
        &mut self,
        path: &Path,
        size: u64,
        algorithms: &[Algorithm],
        mut on_read: F,
    ) -> Result<Vec<(Algorithm, DigestValue)>>
    where
        F: FnMut(u64),
    {
        if size == 0 {
            return self.runtime.block_on(hash_empty_file(path, algorithms));
        }

        let request_size = request_size(size);
        let read_depth = read_depth(size, request_size, self.parallelism);
        performance::record_request_size(request_size);
        performance::record_read_depth(read_depth);

        self.buffers
            .retain(|buffer| buffer.allocation_capacity() >= request_size);
        while self.buffers.len() < read_depth {
            self.buffers.push(ReadBuffer::new(request_size));
            performance::record_buffer_allocation(request_size);
        }
        let split_at = self.buffers.len() - read_depth;
        let mut buffers = self.buffers.split_off(split_at);
        for buffer in &mut buffers {
            buffer.set_request_size(request_size);
        }
        let attempt = self.runtime.block_on(read_and_hash(
            path,
            size,
            algorithms,
            buffers,
            read_depth,
            Arc::clone(&self.feedback),
            &mut on_read,
        ));
        self.buffers.extend(attempt.buffers);
        attempt.result
    }

    pub fn set_parallelism(&mut self, parallelism: usize) {
        self.parallelism = parallelism.max(1);
    }
}

impl Drop for LinuxHashWorker {
    fn drop(&mut self) {
        performance::flush_thread_metrics();
    }
}

fn request_size(file_size: u64) -> usize {
    usize::try_from(file_size.min(READ_BUFFER_SIZE as u64))
        .unwrap_or(READ_BUFFER_SIZE)
        .max(1)
}

fn read_depth(file_size: u64, request_size: usize, parallelism: usize) -> usize {
    let chunks = file_size.div_ceil(request_size as u64);
    let preferred = if file_size < PIPELINE_FILE_LIMIT || chunks <= 1 {
        1
    } else if file_size >= DEEP_PIPELINE_FILE_LIMIT && parallelism <= 2 {
        DEEP_READ_DEPTH
    } else {
        NORMAL_READ_DEPTH
    };
    preferred.min(usize::try_from(chunks).unwrap_or(usize::MAX))
}

struct ReadAttempt {
    result: Result<Vec<(Algorithm, DigestValue)>>,
    buffers: Vec<ReadBuffer>,
}

type PendingRead = JoinHandle<(io::Result<usize>, ReadBuffer)>;

async fn read_and_hash<F>(
    path: &Path,
    expected_size: u64,
    algorithms: &[Algorithm],
    buffers: Vec<ReadBuffer>,
    read_depth: usize,
    feedback: Arc<IoFeedback>,
    on_read: &mut F,
) -> ReadAttempt
where
    F: FnMut(u64),
{
    let mut idle = buffers;
    let mut pending = VecDeque::<PendingRead>::new();
    let file = match open_hash_file(path).await {
        Ok(file) => file,
        Err(error) => {
            return ReadAttempt {
                result: Err(error).with_context(|| format!("无法打开 {}", path.display())),
                buffers: idle,
            };
        }
    };
    advise_sequential(&file, expected_size);
    let mut hasher = match MultiHasher::new(algorithms) {
        Ok(hasher) => hasher,
        Err(error) => {
            return ReadAttempt {
                result: Err(error),
                buffers: idle,
            };
        }
    };
    let mut processed = 0u64;
    let mut next_submit = 0u64;
    submit_reads(
        &file,
        &mut idle,
        &mut pending,
        &mut next_submit,
        expected_size,
        read_depth,
        &feedback,
    );
    yield_to_runtime().await;

    while processed < expected_size {
        let Some(task) = pending.pop_front() else {
            return ReadAttempt {
                result: Err(anyhow!("Linux I/O 流水线意外耗尽: {}", path.display())),
                buffers: idle,
            };
        };
        let (read, current) = match task.await {
            Ok(result) => result,
            Err(error) => {
                recover_pending(&mut pending, &mut idle).await;
                return ReadAttempt {
                    result: Err(anyhow!("Linux I/O 任务异常退出: {error}")),
                    buffers: idle,
                };
            }
        };
        let count = match read {
            Ok(count) => count,
            Err(error) => {
                idle.push(current);
                recover_pending(&mut pending, &mut idle).await;
                return ReadAttempt {
                    result: Err(error).with_context(|| format!("无法读取 {}", path.display())),
                    buffers: idle,
                };
            }
        };
        if count == 0 {
            idle.push(current);
            recover_pending(&mut pending, &mut idle).await;
            performance::record_early_eof();
            return ReadAttempt {
                result: Err(anyhow!(
                    "文件在读取期间缩短: {} (读取到 {} 字节, 扫描时为 {} 字节)",
                    path.display(),
                    processed,
                    expected_size
                )),
                buffers: idle,
            };
        }

        let remaining = expected_size - processed;
        let accepted = usize::try_from(remaining).unwrap_or(usize::MAX).min(count);
        let next_offset = processed + accepted as u64;
        let short_read = count < current.capacity() && next_offset < expected_size;
        if short_read {
            performance::record_short_read();
            recover_pending(&mut pending, &mut idle).await;
            next_submit = next_offset;
        }

        let hash_started = performance::sample_hash_timing().then(Instant::now);
        hasher.update(&current.as_init()[..accepted]);
        performance::record_hash(accepted, hash_started.map(|started| started.elapsed()));
        processed = next_offset;
        on_read(accepted as u64);
        idle.push(current);

        submit_reads(
            &file,
            &mut idle,
            &mut pending,
            &mut next_submit,
            expected_size,
            read_depth,
            &feedback,
        );
    }

    recover_pending(&mut pending, &mut idle).await;
    let result = match file.metadata().await {
        Ok(metadata) if metadata.len() == expected_size => hasher.finalize(),
        Ok(metadata) => Err(anyhow!(
            "文件在计算期间发生变化: {} (当前 {} 字节, 扫描时为 {} 字节)",
            path.display(),
            metadata.len(),
            expected_size
        )),
        Err(error) => Err(error).with_context(|| format!("无法检查 {}", path.display())),
    };
    ReadAttempt {
        result,
        buffers: idle,
    }
}

fn submit_reads(
    file: &compio::fs::File,
    idle: &mut Vec<ReadBuffer>,
    pending: &mut VecDeque<PendingRead>,
    next_submit: &mut u64,
    expected_size: u64,
    read_depth: usize,
    feedback: &Arc<IoFeedback>,
) {
    while pending.len() < read_depth && *next_submit < expected_size {
        let Some(buffer) = idle.pop() else { break };
        let offset = *next_submit;
        *next_submit = next_submit.saturating_add(buffer.capacity() as u64);
        let file = file.clone();
        let feedback = io_feedback::sample_due().then(|| Arc::clone(feedback));
        pending.push_back(spawn(async move {
            read_owned(file, buffer, offset, feedback).await
        }));
    }
}

async fn recover_pending(pending: &mut VecDeque<PendingRead>, buffers: &mut Vec<ReadBuffer>) {
    while let Some(task) = pending.pop_front() {
        if let Ok((_, buffer)) = task.await {
            buffers.push(buffer);
        }
    }
}

async fn read_owned(
    file: compio::fs::File,
    mut buffer: ReadBuffer,
    offset: u64,
    feedback: Option<Arc<IoFeedback>>,
) -> (io::Result<usize>, ReadBuffer) {
    buffer.clear();
    let report_timing = performance::sample_read_timing();
    let started = (report_timing || feedback.is_some()).then(Instant::now);
    let BufResult(read, buffer) = file.read_at(buffer, offset).await;
    let elapsed = started.map(|started| started.elapsed());
    performance::record_read(
        false,
        read.as_ref().copied().unwrap_or(0),
        read.is_ok(),
        report_timing.then_some(elapsed).flatten(),
    );
    if let (Some(feedback), Some(elapsed)) = (feedback, elapsed) {
        feedback.record(read.as_ref().copied().unwrap_or(0), elapsed);
    }
    (read, buffer)
}

async fn open_hash_file(path: &Path) -> io::Result<compio::fs::File> {
    let started = performance::sample_open_timing().then(Instant::now);
    let result = OpenOptions::new().read(true).open(path).await;
    performance::record_open(
        false,
        result.is_ok(),
        started.map(|started| started.elapsed()),
    );
    result
}

async fn hash_empty_file(
    path: &Path,
    algorithms: &[Algorithm],
) -> Result<Vec<(Algorithm, DigestValue)>> {
    let file = open_hash_file(path)
        .await
        .with_context(|| format!("无法打开 {}", path.display()))?;
    let metadata = file
        .metadata()
        .await
        .with_context(|| format!("无法检查 {}", path.display()))?;
    if metadata.len() != 0 {
        return Err(anyhow!(
            "文件在计算期间发生变化: {} (当前 {} 字节, 扫描时为 0 字节)",
            path.display(),
            metadata.len()
        ));
    }
    MultiHasher::new(algorithms)?.finalize()
}

fn advise_sequential(file: &compio::fs::File, size: u64) {
    if size < PIPELINE_FILE_LIMIT {
        return;
    }
    unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            0,
            i64::try_from(size).unwrap_or(i64::MAX),
            libc::POSIX_FADV_SEQUENTIAL,
        );
    }
}

async fn yield_to_runtime() {
    let mut yielded = false;
    std::future::poll_fn(move |context| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            context.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
}

struct ReadBuffer {
    storage: Box<[MaybeUninit<u8>]>,
    request_size: usize,
    initialized: usize,
}

impl ReadBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            storage: Box::new_uninit_slice(capacity),
            request_size: capacity,
            initialized: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.request_size
    }

    fn allocation_capacity(&self) -> usize {
        self.storage.len()
    }

    fn set_request_size(&mut self, request_size: usize) {
        debug_assert!(request_size <= self.storage.len());
        self.request_size = request_size;
        self.initialized = 0;
    }

    fn clear(&mut self) {
        self.initialized = 0;
    }
}

impl IoBuf for ReadBuffer {
    fn as_init(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast::<u8>(), self.initialized) }
    }
}

impl IoBufMut for ReadBuffer {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        &mut self.storage[..self.request_size]
    }
}

impl SetLen for ReadBuffer {
    unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.storage.len());
        debug_assert!(len <= self.request_size);
        self.initialized = len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_depth_tracks_file_shape_and_parallelism() {
        assert_eq!(read_depth(4096, 4096, 8), 1);
        assert_eq!(read_depth(8 * 1024 * 1024, READ_BUFFER_SIZE, 8), 2);
        assert_eq!(
            read_depth(128 * 1024 * 1024, READ_BUFFER_SIZE, 1),
            DEEP_READ_DEPTH
        );
        assert_eq!(
            read_depth(128 * 1024 * 1024, READ_BUFFER_SIZE, 8),
            NORMAL_READ_DEPTH
        );
    }

    #[test]
    fn larger_buffer_can_serve_smaller_requests_without_exposing_extra_capacity() {
        let mut buffer = ReadBuffer::new(4096);
        buffer.set_request_size(1024);
        assert_eq!(buffer.allocation_capacity(), 4096);
        assert_eq!(buffer.capacity(), 1024);
        assert_eq!(buffer.as_uninit().len(), 1024);
    }

    #[test]
    fn async_reader_hashes_and_rejects_size_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.bin");
        std::fs::write(&path, b"abc").unwrap();
        let mut worker = LinuxHashWorker::new(1, Arc::new(IoFeedback::default())).unwrap();
        let hashes = worker
            .hash_file(&path, 3, &[Algorithm::Sha256], |_| {})
            .unwrap();
        assert_eq!(
            hashes[0].1.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let error = worker
            .hash_file(&path, 4, &[Algorithm::Sha256], |_| {})
            .unwrap_err();
        assert!(error.to_string().contains("缩短"));
    }
}

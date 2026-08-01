use super::{Algorithm, DigestValue, MultiHasher};
use crate::io_feedback::{self, IoFeedback};
use crate::performance;
use crate::scanner::WorkloadSummary;
use anyhow::{Context, Result, anyhow};
use compio::buf::{BufResult, IoBuf, IoBufMut, SetLen};
use compio::fs::OpenOptions;
use compio::io::AsyncReadAt;
use compio::runtime::{JoinHandle, Runtime, spawn};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem::{MaybeUninit, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{NonNull, null, null_mut};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BusType1394, BusTypeAta, BusTypeAtapi, BusTypeFibre, BusTypeFileBackedVirtual, BusTypeMmc,
    BusTypeNvme, BusTypeRAID, BusTypeSCM, BusTypeSas, BusTypeSata, BusTypeScsi, BusTypeSd,
    BusTypeSpaces, BusTypeSsa, BusTypeUfs, BusTypeUnknown, BusTypeUsb, BusTypeVirtual,
    BusTypeiScsi, CreateFileW, FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STORAGE_INFO, FileStorageInfo,
    GetFileInformationByHandleEx, GetFileSizeEx, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    DEVICE_SEEK_PENALTY_DESCRIPTOR, DEVICE_TRIM_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY,
    PropertyStandardQuery, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, STORAGE_ADAPTER_DESCRIPTOR,
    STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_ID, STORAGE_PROPERTY_QUERY,
    StorageAccessAlignmentProperty, StorageAdapterProperty, StorageDeviceProperty,
    StorageDeviceSeekPenaltyProperty, StorageDeviceTrimProperty,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

const FALLBACK_ALIGNMENT: usize = 4096;
const MAX_SECTOR_SIZE: u32 = 1024 * 1024;
const MIN_REQUEST_SIZE: usize = 64 * 1024;
const MAX_REQUEST_SIZE: usize = 8 * 1024 * 1024;
static PROFILE_CACHE: OnceLock<Mutex<Vec<StorageProfile>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MediaKind {
    Nvme,
    Ssd,
    Hdd,
    Flash,
    Optical,
    PersistentMemory,
    Network,
    Virtual,
    Unknown,
}

pub fn parallelism_limits(
    path: &Path,
    files: usize,
    algorithm_count: usize,
    workload: Option<&WorkloadSummary>,
) -> (usize, usize) {
    performance::record_storage("windows_iocp_mode=per-thread".to_string());
    let cpu_limit = if algorithm_count >= 4 {
        num_cpus::get().max(1).div_ceil(2)
    } else {
        num_cpus::get().max(1)
    };
    let profile = cached_profile(path);
    let policy = profile.io_policy(cpu_limit);
    let workload_limit = workload
        .filter(|workload| sequential_dominant(workload, files))
        .map(|_| profile.sequential_stream_limit(cpu_limit))
        .unwrap_or(policy.maximum);
    let maximum = files
        .min(cpu_limit)
        .min(policy.maximum)
        .min(workload_limit)
        .max(1);
    let initial = policy.initial.min(maximum).max(1);
    (initial, maximum)
}

pub fn bulk_lane_policy(path: &Path, algorithm_count: usize) -> (PathBuf, usize) {
    let cpu_limit = if algorithm_count >= 4 {
        num_cpus::get().max(1).div_ceil(2)
    } else {
        num_cpus::get().max(1)
    };
    let profile = cached_profile(path);
    (
        profile.root.clone(),
        profile.sequential_stream_limit(cpu_limit),
    )
}

#[derive(Clone, Debug)]
struct StorageProfile {
    root: PathBuf,
    media: MediaKind,
    bus: Option<i32>,
    queued: bool,
    removable: Option<bool>,
    io_alignment: usize,
    offset_alignment: u64,
    partition_misaligned: bool,
    direct: bool,
}

#[derive(Clone, Copy, Debug)]
struct IoPolicy {
    initial: usize,
    maximum: usize,
    request_size: usize,
}

#[derive(Clone, Debug, Default)]
struct DeviceInfo {
    bus: Option<i32>,
    removable: Option<bool>,
    command_queueing: Option<bool>,
    vendor: Option<String>,
    product: Option<String>,
    revision: Option<String>,
}

impl StorageProfile {
    fn detect(path: &Path) -> Result<Self> {
        let root = volume_root(path).unwrap_or_else(|_| fallback_root(path));
        let filesystem = filesystem_name(&root).unwrap_or_default();
        let is_network = root.as_os_str().encode_wide().take(2).eq(['\\' as u16; 2]);

        let mut logical = FALLBACK_ALIGNMENT as u32;
        let mut physical = FALLBACK_ALIGNMENT as u32;
        let mut sector_offset = None;
        let mut partition_offset = None;
        if let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) {
            let mut info = FILE_STORAGE_INFO::default();
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle() as HANDLE,
                    FileStorageInfo,
                    (&mut info as *mut FILE_STORAGE_INFO).cast(),
                    size_of::<FILE_STORAGE_INFO>() as u32,
                )
            };
            if ok != 0 {
                logical = valid_sector(info.LogicalBytesPerSector).unwrap_or(logical);
                physical = valid_sector(info.PhysicalBytesPerSectorForPerformance)
                    .or_else(|| valid_sector(info.PhysicalBytesPerSectorForAtomicity))
                    .unwrap_or(physical);
                sector_offset = valid_alignment_offset(info.ByteOffsetForSectorAlignment);
                partition_offset = valid_alignment_offset(info.ByteOffsetForPartitionAlignment);
            }
        }

        let mut device = DeviceInfo::default();
        let mut adapter = None;
        let mut incurs_seek = None;
        let mut trim = None;
        if let Ok(handle) = open_volume(&root) {
            if let Some(alignment) = query_property::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>(
                handle.0,
                StorageAccessAlignmentProperty,
            ) {
                logical = valid_sector(alignment.BytesPerLogicalSector).unwrap_or(logical);
                physical = valid_sector(alignment.BytesPerPhysicalSector).unwrap_or(physical);
                if let Some(offset) =
                    valid_alignment_offset(alignment.BytesOffsetForSectorAlignment)
                {
                    sector_offset = Some(offset);
                }
            }
            device = query_device_info(handle.0).unwrap_or_default();
            adapter =
                query_property::<STORAGE_ADAPTER_DESCRIPTOR>(handle.0, StorageAdapterProperty);
            incurs_seek = query_property::<DEVICE_SEEK_PENALTY_DESCRIPTOR>(
                handle.0,
                StorageDeviceSeekPenaltyProperty,
            )
            .map(|descriptor| descriptor.IncursSeekPenalty);
            trim = query_property::<DEVICE_TRIM_DESCRIPTOR>(handle.0, StorageDeviceTrimProperty)
                .map(|descriptor| descriptor.TrimEnabled);
        }

        let bus = device
            .bus
            .or_else(|| adapter.map(|descriptor| i32::from(descriptor.BusType)));
        let queued = device.command_queueing == Some(true)
            || adapter.is_some_and(|descriptor| descriptor.CommandQueueing);
        let virtual_hint = device_looks_virtual(&device);
        let solid_state_hint = device_looks_solid_state(&device);
        let media_removable = if bus == Some(BusTypeUsb) && (queued || solid_state_hint) {
            Some(false)
        } else {
            device.removable
        };
        let detected_media = classify_media(
            is_network,
            bus,
            media_removable,
            incurs_seek,
            trim,
            virtual_hint,
            solid_state_hint,
        );
        let bridge_hdd_fallback = legacy_usb_hdd_fallback(
            detected_media,
            bus,
            queued,
            media_removable,
            incurs_seek,
            trim,
            solid_state_hint,
        );
        let media = if bridge_hdd_fallback {
            MediaKind::Hdd
        } else {
            detected_media
        };
        let max_transfer =
            adapter.and_then(|descriptor| valid_max_transfer(descriptor.MaximumTransferLength));
        let io_alignment = usize::try_from(logical.max(physical))
            .unwrap_or(FALLBACK_ALIGNMENT)
            .max(FALLBACK_ALIGNMENT);
        let partition_misaligned =
            alignment_is_misaligned(physical, sector_offset, partition_offset);
        let direct =
            !is_network && !matches!(filesystem.to_ascii_uppercase().as_str(), "CDFS" | "UDF");

        performance::record_storage(format!(
            "root={} fs={} media={media:?} transport={} virtual_hint={virtual_hint} solid_state_hint={solid_state_hint} bridge_hdd_fallback={bridge_hdd_fallback} queued={queued} \
device_queueing={} adapter_queueing={} removable={} vendor={} product={} revision={} \
max_transfer={} adapter_bus_version={} adapter_srb_type={} adapter_pio={} adapter_accelerated={} \
logical_sector={logical} physical_sector={physical} \
sector_offset={} partition_offset={} io_alignment={io_alignment} \
partition_misaligned={partition_misaligned} direct_io={direct}",
            root.display(),
            if filesystem.is_empty() {
                "unknown"
            } else {
                &filesystem
            },
            transport_text(bus, queued),
            option_bool_text(device.command_queueing),
            option_bool_text(adapter.map(|descriptor| descriptor.CommandQueueing)),
            option_bool_text(device.removable),
            device.vendor.as_deref().unwrap_or("unknown"),
            device.product.as_deref().unwrap_or("unknown"),
            device.revision.as_deref().unwrap_or("unknown"),
            option_usize_text(max_transfer),
            adapter
                .map(|descriptor| {
                    format!(
                        "{}.{}",
                        descriptor.BusMajorVersion, descriptor.BusMinorVersion
                    )
                })
                .unwrap_or_else(|| "unknown".to_string()),
            adapter
                .map(|descriptor| descriptor.SrbType.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            option_bool_text(adapter.map(|descriptor| descriptor.AdapterUsesPio)),
            option_bool_text(adapter.map(|descriptor| descriptor.AcceleratedTransfer)),
            alignment_offset_text(sector_offset),
            alignment_offset_text(partition_offset),
        ));

        Ok(Self {
            root,
            media,
            bus,
            queued,
            removable: device.removable,
            io_alignment,
            offset_alignment: u64::from(logical),
            partition_misaligned,
            direct,
        })
    }

    fn request_size(&self, file_size: u64, parallelism: usize, read_depth: usize) -> usize {
        let target = if file_size <= MIN_REQUEST_SIZE as u64 {
            usize::try_from(file_size).unwrap_or(MIN_REQUEST_SIZE)
        } else {
            self.io_policy(num_cpus::get().max(1)).request_size
        };
        let target = if self.partition_misaligned {
            target.max(1024 * 1024)
        } else {
            target
        };
        let target = usize::try_from(file_size)
            .ok()
            .and_then(|size| round_up(size, self.io_alignment))
            .map_or(target, |file_request| target.min(file_request));
        let per_lane_budget = memory_budget()
            .checked_div(parallelism.max(1).saturating_mul(read_depth.max(1)))
            .unwrap_or(MIN_REQUEST_SIZE)
            .clamp(MIN_REQUEST_SIZE, MAX_REQUEST_SIZE);
        let target = target.min(per_lane_budget);
        round_up(target.max(self.io_alignment), self.io_alignment)
            .unwrap_or(MAX_REQUEST_SIZE)
            .min(MAX_REQUEST_SIZE)
    }

    fn valid_file_offset(&self, offset: u64) -> bool {
        self.offset_alignment != 0 && offset.is_multiple_of(self.offset_alignment)
    }

    fn io_policy(&self, cpu_limit: usize) -> IoPolicy {
        io_policy(self.media, self.bus, self.queued, self.removable, cpu_limit)
    }

    fn sequential_stream_limit(&self, cpu_limit: usize) -> usize {
        let policy = self.io_policy(cpu_limit);
        match self.media {
            MediaKind::Nvme | MediaKind::PersistentMemory => policy.maximum,
            MediaKind::Ssd => policy.maximum,
            MediaKind::Hdd | MediaKind::Optical => 1,
            MediaKind::Flash | MediaKind::Network | MediaKind::Virtual | MediaKind::Unknown => {
                policy.maximum
            }
        }
        .max(1)
    }

    fn read_depth(&self, file_size: u64, parallelism: usize) -> usize {
        if file_size < LARGE_FILE_LIMIT {
            return 2;
        }
        match self.media {
            MediaKind::Nvme | MediaKind::PersistentMemory if parallelism <= 1 => 4,
            MediaKind::Nvme | MediaKind::PersistentMemory => 3,
            MediaKind::Ssd | MediaKind::Virtual if self.queued && parallelism <= 1 => 4,
            MediaKind::Ssd | MediaKind::Virtual if self.queued && parallelism == 2 => 3,
            _ => 2,
        }
    }

    fn fallback(path: &Path) -> Self {
        Self {
            root: fallback_root(path),
            media: MediaKind::Unknown,
            bus: None,
            queued: false,
            removable: None,
            io_alignment: FALLBACK_ALIGNMENT,
            offset_alignment: FALLBACK_ALIGNMENT as u64,
            partition_misaligned: false,
            direct: true,
        }
    }
}

const LARGE_FILE_LIMIT: u64 = 64 * 1024 * 1024;

fn sequential_dominant(workload: &WorkloadSummary, files: usize) -> bool {
    if files == 0 || workload.large_files == 0 {
        return false;
    }
    let small = workload.tiny_files.saturating_add(workload.small_files);
    small.saturating_mul(10) <= files as u64
}

pub struct WindowsHashWorker {
    runtime: Runtime,
    buffers: Vec<AlignedBuffer>,
    profiles: Vec<StorageProfile>,
    parallelism: usize,
    feedback: Arc<IoFeedback>,
}

impl WindowsHashWorker {
    pub fn new(parallelism: usize, feedback: Arc<IoFeedback>) -> Result<Self> {
        Ok(Self {
            runtime: Runtime::new().context("无法创建 Windows IOCP runtime")?,
            buffers: Vec::new(),
            profiles: Vec::new(),
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
            let profile = self.profile_for(path);
            self.runtime.block_on(validate_empty_file(path, &profile))?;
            return MultiHasher::new(algorithms)?.finalize();
        }

        let profile = self.profile_for(path);
        let read_depth = profile.read_depth(size, self.parallelism);
        let pending_limit = read_depth.saturating_sub(1).max(1);
        let request_size = profile.request_size(size, self.parallelism, read_depth);
        performance::record_request_size(request_size);
        performance::record_read_depth(pending_limit);
        self.buffers
            .retain(|buffer| buffer.can_serve(request_size, profile.io_alignment));
        let capacity = buffer_growth_capacity(request_size, profile.io_alignment)
            .context("I/O 缓冲区增长大小溢出")?;
        while self.buffers.len() < read_depth {
            self.buffers
                .push(AlignedBuffer::new(capacity, profile.io_alignment)?);
        }
        let split_at = self.buffers.len() - read_depth;
        let mut buffers = self.buffers.split_off(split_at);
        for buffer in &mut buffers {
            buffer.set_request_size(request_size, profile.io_alignment)?;
        }

        let direct = profile.direct;
        let mut attempt = self.runtime.block_on(read_and_hash(
            path,
            size,
            algorithms,
            &profile,
            ReadPipelineConfig {
                buffers,
                pending_limit,
                direct,
                feedback: Arc::clone(&self.feedback),
            },
            &mut on_read,
        ));

        if direct
            && attempt.bytes == 0
            && attempt.result.as_ref().is_err_and(is_direct_io_unsupported)
        {
            performance::record_direct_fallback();
            attempt = self.runtime.block_on(read_and_hash(
                path,
                size,
                algorithms,
                &profile,
                ReadPipelineConfig {
                    buffers: attempt.buffers,
                    pending_limit,
                    direct: false,
                    feedback: Arc::clone(&self.feedback),
                },
                &mut on_read,
            ));
        }
        self.buffers.extend(attempt.buffers);
        attempt.result
    }

    pub fn set_parallelism(&mut self, parallelism: usize) {
        self.parallelism = parallelism.max(1);
    }

    fn profile_for(&mut self, path: &Path) -> StorageProfile {
        if let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| path.starts_with(&profile.root))
        {
            return profile.clone();
        }
        let profile = cached_profile(path);
        self.profiles.push(profile.clone());
        profile
    }
}

fn cached_profile(path: &Path) -> StorageProfile {
    let cache = PROFILE_CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut profiles = cache.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(profile) = profiles
        .iter()
        .find(|profile| path.starts_with(&profile.root))
    {
        return profile.clone();
    }
    let profile = StorageProfile::detect(path).unwrap_or_else(|_| {
        let profile = StorageProfile::fallback(path);
        performance::record_storage(format!(
            "root={} fs=unknown media=Unknown transport=unknown io_alignment={} direct_io=true detection=fallback",
            profile.root.display(),
            profile.io_alignment
        ));
        profile
    });
    profiles.push(profile.clone());
    profile
}

impl Drop for WindowsHashWorker {
    fn drop(&mut self) {
        performance::flush_thread_metrics();
    }
}

struct ReadAttempt {
    result: Result<Vec<(Algorithm, DigestValue)>>,
    buffers: Vec<AlignedBuffer>,
    bytes: u64,
}

struct ReadPipelineConfig {
    buffers: Vec<AlignedBuffer>,
    pending_limit: usize,
    direct: bool,
    feedback: Arc<IoFeedback>,
}

type PendingRead = JoinHandle<(io::Result<usize>, AlignedBuffer)>;

#[derive(Clone, Copy)]
struct ReadWindow {
    expected_size: u64,
    pending_limit: usize,
}

async fn read_and_hash<F>(
    path: &Path,
    expected_size: u64,
    algorithms: &[Algorithm],
    profile: &StorageProfile,
    config: ReadPipelineConfig,
    on_read: &mut F,
) -> ReadAttempt
where
    F: FnMut(u64),
{
    let ReadPipelineConfig {
        buffers,
        pending_limit,
        direct,
        feedback,
    } = config;
    let mut processed = 0u64;
    let read_window = ReadWindow {
        expected_size,
        pending_limit,
    };
    let mut idle = buffers;
    let mut pending = VecDeque::<PendingRead>::new();
    let mut direct_active = direct;
    let mut file = match open_hash_file(path, direct_active).await {
        Ok(file) => file,
        Err(error) => {
            return ReadAttempt {
                result: Err(error).with_context(|| format!("无法打开 {}", path.display())),
                buffers: idle,
                bytes: processed,
            };
        }
    };
    let mut hasher = match MultiHasher::new(algorithms) {
        Ok(hasher) => hasher,
        Err(error) => {
            return ReadAttempt {
                result: Err(error),
                buffers: idle,
                bytes: processed,
            };
        }
    };

    let mut next_submit = 0u64;
    submit_reads(
        &file,
        &mut idle,
        &mut pending,
        &mut next_submit,
        read_window,
        direct_active,
        &feedback,
    );
    yield_to_runtime().await;
    loop {
        let Some(task) = pending.pop_front() else {
            return ReadAttempt {
                result: Err(anyhow!("Windows I/O 流水线意外耗尽: {}", path.display())),
                buffers: idle,
                bytes: processed,
            };
        };
        let (read, current) = match task.await {
            Ok(result) => result,
            Err(error) => {
                recover_pending(&mut pending, &mut idle).await;
                return ReadAttempt {
                    result: Err(anyhow!("Windows I/O 任务异常退出: {error}")),
                    buffers: idle,
                    bytes: processed,
                };
            }
        };
        let count = match read {
            Ok(count) => count,
            Err(error) if direct_active && is_direct_io_code(error.raw_os_error()) => {
                performance::record_direct_fallback();
                idle.push(current);
                recover_pending(&mut pending, &mut idle).await;
                file = match open_hash_file(path, false).await {
                    Ok(file) => file,
                    Err(open_error) => {
                        return ReadAttempt {
                            result: Err(open_error).with_context(|| {
                                format!("Direct I/O 失败后无法重新打开 {}", path.display())
                            }),
                            buffers: idle,
                            bytes: processed,
                        };
                    }
                };
                direct_active = false;
                next_submit = processed;
                submit_reads(
                    &file,
                    &mut idle,
                    &mut pending,
                    &mut next_submit,
                    read_window,
                    direct_active,
                    &feedback,
                );
                continue;
            }
            Err(error) => {
                idle.push(current);
                recover_pending(&mut pending, &mut idle).await;
                return ReadAttempt {
                    result: Err(error).with_context(|| format!("无法读取 {}", path.display())),
                    buffers: idle,
                    bytes: processed,
                };
            }
        };
        if count == 0 {
            idle.push(current);
            recover_pending(&mut pending, &mut idle).await;
            if direct_active {
                performance::record_early_eof_retry();
                performance::record_direct_fallback();
                file = match open_hash_file(path, false).await {
                    Ok(file) => file,
                    Err(error) => {
                        return ReadAttempt {
                            result: Err(error).with_context(|| {
                                format!("Direct I/O 提前 EOF 后无法重新打开 {}", path.display())
                            }),
                            buffers: idle,
                            bytes: processed,
                        };
                    }
                };
                direct_active = false;
                next_submit = processed;
                submit_reads(
                    &file,
                    &mut idle,
                    &mut pending,
                    &mut next_submit,
                    read_window,
                    direct_active,
                    &feedback,
                );
                continue;
            }
            return ReadAttempt {
                result: Err(anyhow!(
                    "文件在读取期间缩短: {} (读取到 {} 字节, 扫描时为 {} 字节)",
                    path.display(),
                    processed,
                    expected_size
                )),
                buffers: idle,
                bytes: processed,
            };
        }
        let remaining = expected_size - processed;
        let accepted = usize::try_from(remaining).unwrap_or(usize::MAX).min(count);
        let next_offset = processed + accepted as u64;
        let short_read = count < current.request_size() && next_offset < expected_size;
        if short_read {
            performance::record_short_read();
        }

        let can_prefetch = next_offset < expected_size
            && !short_read
            && (!direct_active || profile.valid_file_offset(next_offset));
        if can_prefetch {
            submit_reads(
                &file,
                &mut idle,
                &mut pending,
                &mut next_submit,
                read_window,
                direct_active,
                &feedback,
            );
        }

        let hash_started = performance::sample_hash_timing().then(Instant::now);
        hasher.update(&current.as_init()[..accepted]);
        performance::record_hash(accepted, hash_started.map(|started| started.elapsed()));
        processed = next_offset;
        on_read(accepted as u64);
        idle.push(current);

        if processed >= expected_size {
            recover_pending(&mut pending, &mut idle).await;
            if let Err(error) = validate_open_file_size(&file, expected_size, path) {
                return ReadAttempt {
                    result: Err(error),
                    buffers: idle,
                    bytes: processed,
                };
            }
            return ReadAttempt {
                result: hasher.finalize(),
                buffers: idle,
                bytes: processed,
            };
        }

        if short_read || (direct_active && !profile.valid_file_offset(processed)) {
            recover_pending(&mut pending, &mut idle).await;
            if direct_active {
                performance::record_direct_fallback();
                file = match open_hash_file(path, false).await {
                    Ok(file) => file,
                    Err(error) => {
                        return ReadAttempt {
                            result: Err(error).with_context(|| {
                                format!("无法在短读后重新打开 {}", path.display())
                            }),
                            buffers: idle,
                            bytes: processed,
                        };
                    }
                };
                direct_active = false;
            }
            next_submit = processed;
        }
        submit_reads(
            &file,
            &mut idle,
            &mut pending,
            &mut next_submit,
            read_window,
            direct_active,
            &feedback,
        );
    }
}

fn submit_reads(
    file: &compio::fs::File,
    idle: &mut Vec<AlignedBuffer>,
    pending: &mut VecDeque<PendingRead>,
    next_submit: &mut u64,
    window: ReadWindow,
    direct: bool,
    feedback: &Arc<IoFeedback>,
) {
    while pending.len() < window.pending_limit && *next_submit < window.expected_size {
        let Some(buffer) = idle.pop() else { break };
        let offset = *next_submit;
        *next_submit = next_submit.saturating_add(buffer.request_size() as u64);
        let file = file.clone();
        let feedback = io_feedback::sample_due().then(|| Arc::clone(feedback));
        pending.push_back(spawn(async move {
            read_owned(file, buffer, offset, direct, feedback).await
        }));
    }
}

async fn recover_pending(pending: &mut VecDeque<PendingRead>, buffers: &mut Vec<AlignedBuffer>) {
    while let Some(task) = pending.pop_front() {
        if let Ok((_, buffer)) = task.await {
            buffers.push(buffer);
        }
    }
}

async fn read_owned(
    file: compio::fs::File,
    mut buffer: AlignedBuffer,
    offset: u64,
    direct: bool,
    feedback: Option<Arc<IoFeedback>>,
) -> (io::Result<usize>, AlignedBuffer) {
    unsafe { buffer.set_len(0) };
    let report_timing = performance::sample_read_timing();
    let started = (report_timing || feedback.is_some()).then(Instant::now);
    let BufResult(read, buffer) = file.read_at(buffer, offset).await;
    let elapsed = started.map(|started| started.elapsed());
    performance::record_read(
        direct,
        read.as_ref().copied().unwrap_or(0),
        read.is_ok(),
        report_timing.then_some(elapsed).flatten(),
    );
    if let (Some(feedback), Some(elapsed)) = (feedback, elapsed) {
        feedback.record(read.as_ref().copied().unwrap_or(0), elapsed);
    }
    (read, buffer)
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

async fn open_hash_file(path: &Path, direct: bool) -> io::Result<compio::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    let mut flags = FILE_FLAG_SEQUENTIAL_SCAN;
    if direct {
        flags |= FILE_FLAG_NO_BUFFERING;
    }
    options.custom_flags(flags);
    let started = performance::sample_open_timing().then(Instant::now);
    let result = options.open(path).await;
    performance::record_open(
        direct,
        result.is_ok(),
        started.map(|started| started.elapsed()),
    );
    result
}

async fn validate_empty_file(path: &Path, profile: &StorageProfile) -> Result<()> {
    let mut direct = profile.direct;
    let file = loop {
        match open_hash_file(path, direct).await {
            Ok(file) => break file,
            Err(error) if direct && is_direct_io_code(error.raw_os_error()) => {
                performance::record_direct_fallback();
                direct = false;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("无法打开 {}", path.display()));
            }
        }
    };
    validate_open_file_size(&file, 0, path)
}

fn validate_open_file_size(file: &compio::fs::File, expected_size: u64, path: &Path) -> Result<()> {
    let mut actual_size = 0i64;
    let ok = unsafe { GetFileSizeEx(file.as_raw_handle() as HANDLE, &mut actual_size as *mut i64) };
    if ok == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("无法检查 {}", path.display()));
    }
    let actual_size = u64::try_from(actual_size).context("文件长度无效")?;
    if actual_size != expected_size {
        return Err(anyhow!(
            "文件在计算期间发生变化: {} (当前 {} 字节, 扫描时为 {} 字节)",
            path.display(),
            actual_size,
            expected_size
        ));
    }
    Ok(())
}

struct AlignedBuffer {
    base: NonNull<c_void>,
    ptr: NonNull<u8>,
    allocation_capacity: usize,
    request_size: usize,
    alignment: usize,
    initialized: usize,
}

impl AlignedBuffer {
    fn new(capacity: usize, alignment: usize) -> Result<Self> {
        let capacity = round_up(capacity, alignment).context("I/O 缓冲区大小溢出")?;
        let allocation = capacity
            .checked_add(alignment)
            .context("I/O 缓冲区分配大小溢出")?;
        let base =
            unsafe { VirtualAlloc(null(), allocation, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        let base = NonNull::new(base).ok_or_else(io::Error::last_os_error)?;
        let address = round_up(base.as_ptr() as usize, alignment)
            .ok_or_else(|| anyhow!("I/O 缓冲区地址溢出"))?;
        let ptr = NonNull::new(address as *mut u8).expect("aligned address is non-null");
        performance::record_buffer_allocation(allocation);
        Ok(Self {
            base,
            ptr,
            allocation_capacity: capacity,
            request_size: capacity,
            alignment,
            initialized: 0,
        })
    }

    fn allocation_capacity(&self) -> usize {
        self.allocation_capacity
    }

    fn request_size(&self) -> usize {
        self.request_size
    }

    fn can_serve(&self, request_size: usize, alignment: usize) -> bool {
        self.allocation_capacity() >= request_size
            && self.alignment >= alignment
            && self.alignment.is_multiple_of(alignment)
    }

    fn set_request_size(&mut self, request_size: usize, required_alignment: usize) -> Result<()> {
        if request_size == 0
            || request_size > self.allocation_capacity()
            || !self.can_serve(request_size, required_alignment)
            || !request_size.is_multiple_of(required_alignment)
        {
            return Err(anyhow!(
                "无效的 Direct I/O 请求大小 {request_size} (容量 {}, 缓冲区对齐 {}, 所需对齐 {required_alignment})",
                self.allocation_capacity(),
                self.alignment
            ));
        }
        self.request_size = request_size;
        self.initialized = 0;
        Ok(())
    }
}

impl IoBuf for AlignedBuffer {
    fn as_init(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.initialized) }
    }
}

impl IoBufMut for AlignedBuffer {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.ptr.as_ptr().cast::<MaybeUninit<u8>>(),
                self.request_size,
            )
        }
    }
}

impl SetLen for AlignedBuffer {
    unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.request_size);
        self.initialized = len;
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.base.as_ptr(), 0, MEM_RELEASE);
        }
    }
}

fn round_up(value: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 {
        return None;
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
}

fn buffer_growth_capacity(request_size: usize, alignment: usize) -> Option<usize> {
    let target = request_size.max(MIN_REQUEST_SIZE).max(alignment);
    let target = target.checked_next_power_of_two()?;
    round_up(target, alignment)
}

fn valid_sector(value: u32) -> Option<u32> {
    ((512..=MAX_SECTOR_SIZE).contains(&value) && value.is_power_of_two()).then_some(value)
}

fn valid_alignment_offset(value: u32) -> Option<u32> {
    (value != u32::MAX).then_some(value)
}

fn alignment_is_misaligned(
    physical_sector: u32,
    sector_offset: Option<u32>,
    partition_offset: Option<u32>,
) -> bool {
    physical_sector > 0
        && [sector_offset, partition_offset]
            .into_iter()
            .flatten()
            .any(|offset| !offset.is_multiple_of(physical_sector))
}

fn alignment_offset_text(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn valid_max_transfer(value: u32) -> Option<usize> {
    const MAX_ADAPTER_TRANSFER: u32 = 64 * 1024 * 1024;
    ((4096..=MAX_ADAPTER_TRANSFER).contains(&value))
        .then(|| usize::try_from(value).ok())
        .flatten()
}

fn option_bool_text(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn option_usize_text(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn memory_budget() -> usize {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    let available = if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
        usize::try_from(status.ullAvailPhys).unwrap_or(usize::MAX)
    } else {
        256 * 1024 * 1024
    };
    available
        .checked_div(32)
        .unwrap_or(128 * 1024 * 1024)
        .clamp(128 * 1024 * 1024, 1024 * 1024 * 1024)
}

fn volume_root(path: &Path) -> Result<PathBuf> {
    let path = wide_null(path.as_os_str());
    let mut root = vec![0u16; 32_768];
    let ok = unsafe { GetVolumePathNameW(path.as_ptr(), root.as_mut_ptr(), root.len() as u32) };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    root.truncate(
        root.iter()
            .position(|value| *value == 0)
            .unwrap_or(root.len()),
    );
    Ok(PathBuf::from(OsString::from_wide(&root)))
}

fn fallback_root(path: &Path) -> PathBuf {
    path.ancestors()
        .last()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn filesystem_name(root: &Path) -> Result<String> {
    let root = wide_null(root.as_os_str());
    let mut filesystem = [0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let len = filesystem
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(filesystem.len());
    Ok(String::from_utf16_lossy(&filesystem[..len]))
}

fn open_volume(root: &Path) -> Result<OwnedHandle> {
    let root = wide_null(root.as_os_str());
    let mut volume = [0u16; 128];
    let ok = unsafe {
        GetVolumeNameForVolumeMountPointW(root.as_ptr(), volume.as_mut_ptr(), volume.len() as u32)
    };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut len = volume
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(volume.len());
    while len > 0 && volume[len - 1] == '\\' as u16 {
        len -= 1;
    }
    volume[len] = 0;
    let handle = unsafe {
        CreateFileW(
            volume.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    Ok(OwnedHandle(handle))
}

fn query_property<T: Copy>(handle: HANDLE, property: STORAGE_PROPERTY_ID) -> Option<T> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: property,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let mut output = MaybeUninit::<T>::zeroed();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&query as *const STORAGE_PROPERTY_QUERY).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            output.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            &mut returned,
            null_mut(),
        )
    };
    (ok != 0 && returned as usize >= size_of::<T>()).then(|| unsafe { output.assume_init() })
}

fn query_device_info(handle: HANDLE) -> Option<DeviceInfo> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let mut output = [0u64; 128];
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&query as *const STORAGE_PROPERTY_QUERY).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            output.as_mut_ptr().cast(),
            size_of_val(&output) as u32,
            &mut returned,
            null_mut(),
        )
    };
    if ok == 0 || (returned as usize) < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
        return None;
    }
    let descriptor = unsafe { &*output.as_ptr().cast::<STORAGE_DEVICE_DESCRIPTOR>() };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            output.as_ptr().cast::<u8>(),
            (returned as usize).min(size_of_val(&output)),
        )
    };
    Some(DeviceInfo {
        bus: Some(descriptor.BusType),
        removable: Some(descriptor.RemovableMedia),
        command_queueing: Some(descriptor.CommandQueueing),
        vendor: descriptor_text(bytes, descriptor.VendorIdOffset),
        product: descriptor_text(bytes, descriptor.ProductIdOffset),
        revision: descriptor_text(bytes, descriptor.ProductRevisionOffset),
    })
}

fn descriptor_text(buffer: &[u8], offset: u32) -> Option<String> {
    let offset = usize::try_from(offset).ok()?;
    if offset == 0 || offset >= buffer.len() {
        return None;
    }
    let tail = &buffer[offset..];
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    let value = String::from_utf8_lossy(&tail[..length]).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn device_looks_virtual(device: &DeviceInfo) -> bool {
    let identity = format!(
        "{} {}",
        device.vendor.as_deref().unwrap_or_default(),
        device.product.as_deref().unwrap_or_default()
    )
    .to_ascii_uppercase();
    [
        "VIRTUAL",
        "VBOX",
        "VMWARE",
        "QEMU",
        "VIRTIO",
        "XEN",
        "HYPER-V",
        "MSFT VIRTUAL",
        "RED HAT",
        "PARALLELS",
    ]
    .iter()
    .any(|marker| identity.contains(marker))
}

fn device_looks_solid_state(device: &DeviceInfo) -> bool {
    let identity = format!(
        "{} {}",
        device.vendor.as_deref().unwrap_or_default(),
        device.product.as_deref().unwrap_or_default()
    )
    .to_ascii_uppercase();
    ["NVME", "SSD", "SOLID STATE", "SOLID-STATE"]
        .iter()
        .any(|marker| identity.contains(marker))
}

fn classify_media(
    network: bool,
    bus: Option<i32>,
    removable: Option<bool>,
    seek: Option<bool>,
    trim: Option<bool>,
    virtual_hint: bool,
    solid_state_hint: bool,
) -> MediaKind {
    if network {
        return MediaKind::Network;
    }
    if virtual_hint
        || bus.is_some_and(|value| value == BusTypeVirtual || value == BusTypeFileBackedVirtual)
    {
        return match (seek, trim) {
            (Some(true), _) => MediaKind::Hdd,
            (_, Some(true)) | (Some(false), _) => MediaKind::Ssd,
            _ => MediaKind::Virtual,
        };
    }
    match bus {
        Some(value) if value == BusTypeNvme => MediaKind::Nvme,
        Some(value) if value == BusTypeSCM => MediaKind::PersistentMemory,
        Some(value) if value == BusTypeSd || value == BusTypeMmc || value == BusTypeUfs => {
            MediaKind::Flash
        }
        Some(value) if (value == BusTypeiScsi || value == BusTypeFibre) && seek == Some(true) => {
            MediaKind::Hdd
        }
        Some(value)
            if (value == BusTypeiScsi || value == BusTypeFibre)
                && (trim == Some(true) || seek == Some(false)) =>
        {
            MediaKind::Ssd
        }
        Some(value) if value == BusTypeiScsi || value == BusTypeFibre => MediaKind::Network,
        Some(value) if value == BusTypeAtapi && trim != Some(true) => MediaKind::Optical,
        _ if seek == Some(true) => MediaKind::Hdd,
        _ if solid_state_hint => MediaKind::Ssd,
        _ if bus == Some(BusTypeUsb) && removable == Some(true) && trim != Some(true) => {
            MediaKind::Flash
        }
        _ if trim == Some(true) || seek == Some(false) => MediaKind::Ssd,
        _ if bus == Some(BusTypeUsb) && removable == Some(true) => MediaKind::Flash,
        _ => MediaKind::Unknown,
    }
}

fn legacy_usb_hdd_fallback(
    media: MediaKind,
    bus: Option<i32>,
    queued: bool,
    removable: Option<bool>,
    seek: Option<bool>,
    trim: Option<bool>,
    solid_state_hint: bool,
) -> bool {
    media == MediaKind::Unknown
        && bus == Some(BusTypeUsb)
        && !queued
        && removable == Some(false)
        && seek.is_none()
        && trim != Some(true)
        && !solid_state_hint
}

fn io_policy(
    media: MediaKind,
    bus: Option<i32>,
    queued: bool,
    removable: Option<bool>,
    cpu_limit: usize,
) -> IoPolicy {
    let cpu_limit = cpu_limit.max(1);
    let usb = bus == Some(BusTypeUsb);
    let (initial, maximum, request_size) = match media {
        MediaKind::Nvme => (4, cpu_limit, 2 * 1024 * 1024),
        MediaKind::PersistentMemory => (4, cpu_limit, 4 * 1024 * 1024),
        MediaKind::Ssd if usb && queued => (2, cpu_limit.min(8), 2 * 1024 * 1024),
        MediaKind::Ssd if usb => (2, cpu_limit.min(4), 1024 * 1024),
        MediaKind::Ssd
            if queued
                && bus.is_some_and(|value| {
                    value == BusTypeSas
                        || value == BusTypeScsi
                        || value == BusTypeRAID
                        || value == BusTypeSpaces
                }) =>
        {
            (4, cpu_limit.min(8), 2 * 1024 * 1024)
        }
        MediaKind::Ssd => (2, cpu_limit.min(8), 1024 * 1024),
        MediaKind::Hdd => (1, cpu_limit.min(2), 4 * 1024 * 1024),
        MediaKind::Flash if bus == Some(BusTypeUfs) => (2, cpu_limit.min(4), 1024 * 1024),
        MediaKind::Flash if usb && queued => (2, cpu_limit.min(4), 1024 * 1024),
        MediaKind::Flash => (1, cpu_limit.min(2), 512 * 1024),
        MediaKind::Optical => (1, 1, 256 * 1024),
        MediaKind::Network => (2, cpu_limit.min(4), 1024 * 1024),
        MediaKind::Virtual if queued => (2, cpu_limit.min(8), 2 * 1024 * 1024),
        MediaKind::Virtual => (2, cpu_limit.min(4), 1024 * 1024),
        MediaKind::Unknown if usb && queued => (2, cpu_limit.min(4), 1024 * 1024),
        MediaKind::Unknown if usb && removable == Some(true) => (1, cpu_limit.min(2), 512 * 1024),
        MediaKind::Unknown => (2, cpu_limit.min(8), 1024 * 1024),
    };
    IoPolicy {
        initial: initial.min(maximum.max(1)),
        maximum: maximum.max(1),
        request_size,
    }
}

fn transport_text(bus: Option<i32>, queued: bool) -> String {
    let name = match bus {
        Some(value) if value == BusTypeNvme => "NVMe/PCIe-native-or-tunneled",
        Some(value) if value == BusTypeSata => "SATA",
        Some(value) if value == BusTypeAta => "ATA/IDE",
        Some(value) if value == BusTypeAtapi => "ATAPI",
        Some(value) if value == BusTypeSas => "SAS",
        Some(value) if value == BusTypeScsi => "SCSI",
        Some(value) if value == BusTypeUsb && queued => "USB/queued-UASP-capable",
        Some(value) if value == BusTypeUsb => "USB/legacy-BOT-or-unreported",
        Some(value) if value == BusTypeRAID => "RAID",
        Some(value) if value == BusTypeSpaces => "Storage-Spaces",
        Some(value) if value == BusTypeiScsi => "iSCSI",
        Some(value) if value == BusTypeFibre => "Fibre-Channel",
        Some(value) if value == BusType1394 => "IEEE-1394",
        Some(value) if value == BusTypeSsa => "SSA",
        Some(value) if value == BusTypeSd => "SD",
        Some(value) if value == BusTypeMmc => "MMC",
        Some(value) if value == BusTypeUfs => "UFS",
        Some(value) if value == BusTypeSCM => "Persistent-Memory/SCM",
        Some(value) if value == BusTypeVirtual => "Virtual",
        Some(value) if value == BusTypeFileBackedVirtual => "File-backed-Virtual",
        Some(value) if value == BusTypeUnknown => "unknown",
        Some(_) => "unrecognized",
        None => "unknown",
    };
    name.to_string()
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn is_direct_io_unsupported(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|code| is_direct_io_code(Some(code)))
    })
}

fn is_direct_io_code(code: Option<i32>) -> bool {
    code.is_some_and(|code| matches!(code, 1 | 50 | 87))
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;

    #[test]
    fn rounds_buffers_to_runtime_alignment() {
        assert_eq!(round_up(1, 4096), Some(4096));
        assert_eq!(round_up(4096, 4096), Some(4096));
        assert_eq!(round_up(4097, 4096), Some(8192));
        assert_eq!(buffer_growth_capacity(1, 4096), Some(64 * 1024));
        assert_eq!(buffer_growth_capacity(65_537, 4096), Some(128 * 1024));
        assert_eq!(
            buffer_growth_capacity(2 * 1024 * 1024, 4096),
            Some(2 * 1024 * 1024)
        );
    }

    #[test]
    fn rejects_invalid_driver_alignment_values() {
        assert_eq!(valid_sector(0), None);
        assert_eq!(valid_sector(u32::MAX), None);
        assert_eq!(valid_sector(2 * 1024 * 1024), None);
        assert_eq!(valid_sector(4096), Some(4096));
        assert_eq!(valid_alignment_offset(u32::MAX), None);
        assert_eq!(valid_alignment_offset(0), Some(0));
    }

    #[test]
    fn unknown_offsets_do_not_claim_the_partition_is_misaligned() {
        assert!(!alignment_is_misaligned(4096, None, None));
        assert!(!alignment_is_misaligned(4096, Some(0), None));
        assert!(!alignment_is_misaligned(4096, Some(4096), Some(0)));
        assert!(alignment_is_misaligned(4096, Some(1), None));
        assert_eq!(alignment_offset_text(None), "unknown");
    }

    #[test]
    fn classifies_transports_by_media_capabilities() {
        assert_eq!(
            classify_media(
                false,
                Some(BusTypeNvme),
                Some(false),
                None,
                None,
                false,
                false,
            ),
            MediaKind::Nvme
        );
        assert_eq!(
            classify_media(
                false,
                Some(BusTypeUsb),
                Some(true),
                Some(false),
                Some(false),
                false,
                false,
            ),
            MediaKind::Flash
        );
        assert_eq!(
            classify_media(
                false,
                Some(BusTypeUsb),
                Some(false),
                Some(false),
                Some(true),
                false,
                false,
            ),
            MediaKind::Ssd
        );
        assert_eq!(
            classify_media(
                false,
                Some(BusTypeAta),
                Some(false),
                Some(true),
                Some(false),
                false,
                false,
            ),
            MediaKind::Hdd
        );
        assert!(legacy_usb_hdd_fallback(
            MediaKind::Unknown,
            Some(BusTypeUsb),
            false,
            Some(false),
            None,
            None,
            false,
        ));
        assert!(!legacy_usb_hdd_fallback(
            MediaKind::Unknown,
            Some(BusTypeUsb),
            true,
            Some(false),
            None,
            None,
            false,
        ));
        assert_eq!(
            classify_media(
                false,
                Some(BusTypeScsi),
                None,
                Some(true),
                None,
                true,
                false,
            ),
            MediaKind::Hdd
        );
        assert_eq!(
            classify_media(false, Some(BusTypeScsi), None, None, None, true, false,),
            MediaKind::Virtual
        );
        assert_eq!(
            classify_media(
                false,
                Some(BusTypeUsb),
                Some(false),
                None,
                None,
                false,
                true,
            ),
            MediaKind::Ssd
        );
        assert_eq!(
            classify_media(
                false,
                Some(BusTypeUsb),
                Some(false),
                Some(true),
                None,
                false,
                true,
            ),
            MediaKind::Hdd
        );
    }

    #[test]
    fn policies_preserve_native_defaults_and_split_usb_media() {
        let nvme = io_policy(MediaKind::Nvme, Some(BusTypeNvme), true, Some(false), 12);
        assert_eq!(
            (nvme.initial, nvme.maximum, nvme.request_size),
            (4, 12, 2 * 1024 * 1024)
        );

        let flash = io_policy(MediaKind::Flash, Some(BusTypeUsb), false, Some(true), 12);
        assert_eq!(
            (flash.initial, flash.maximum, flash.request_size),
            (1, 2, 512 * 1024)
        );

        let usb_ssd = io_policy(MediaKind::Ssd, Some(BusTypeUsb), true, Some(false), 12);
        assert_eq!(
            (usb_ssd.initial, usb_ssd.maximum, usb_ssd.request_size),
            (2, 8, 2 * 1024 * 1024)
        );

        let native_profile = StorageProfile {
            root: PathBuf::from("G:\\"),
            media: MediaKind::Nvme,
            bus: Some(BusTypeNvme),
            queued: true,
            removable: Some(false),
            io_alignment: 4096,
            offset_alignment: 512,
            partition_misaligned: false,
            direct: true,
        };
        assert_eq!(native_profile.sequential_stream_limit(12), 12);
        assert_eq!(native_profile.read_depth(LARGE_FILE_LIMIT, 1), 4);
        assert_eq!(native_profile.read_depth(LARGE_FILE_LIMIT, 2), 3);
        assert_eq!(native_profile.read_depth(LARGE_FILE_LIMIT, 3), 3);
        assert_eq!(native_profile.read_depth(LARGE_FILE_LIMIT, 12), 3);

        let usb_profile = StorageProfile {
            media: MediaKind::Ssd,
            bus: Some(BusTypeUsb),
            ..native_profile.clone()
        };
        assert_eq!(usb_profile.sequential_stream_limit(12), 8);

        let hdd_profile = StorageProfile {
            media: MediaKind::Hdd,
            bus: Some(BusTypeSata),
            queued: true,
            ..native_profile
        };
        assert_eq!(hdd_profile.sequential_stream_limit(12), 1);
    }

    #[test]
    fn request_size_respects_file_size_without_hard_capping_to_adapter_srb() {
        let profile = StorageProfile {
            root: PathBuf::from("M:\\"),
            media: MediaKind::Ssd,
            bus: Some(BusTypeUsb),
            queued: true,
            removable: Some(false),
            io_alignment: 4096,
            offset_alignment: 512,
            partition_misaligned: false,
            direct: true,
        };
        assert_eq!(profile.request_size(100_000, 2, 2), 102_400);
        assert_eq!(profile.request_size(8 * 1024 * 1024, 2, 2), 2 * 1024 * 1024);
        assert_eq!(valid_max_transfer(u32::MAX), None);
    }

    #[test]
    fn recognizes_common_virtual_disk_identities() {
        let device = DeviceInfo {
            vendor: Some("Msft".to_string()),
            product: Some("Virtual Disk".to_string()),
            ..DeviceInfo::default()
        };
        assert!(device_looks_virtual(&device));
        assert!(!device_looks_virtual(&DeviceInfo {
            vendor: Some("KINGBANK".to_string()),
            product: Some("KP320".to_string()),
            ..DeviceInfo::default()
        }));
    }

    #[test]
    fn virtual_alloc_buffer_has_requested_alignment() {
        let mut buffer = AlignedBuffer::new(128 * 1024, 4096).unwrap();
        assert_eq!(buffer.allocation_capacity() % 4096, 0);
        assert_eq!(buffer.ptr.as_ptr() as usize % 4096, 0);
        buffer.set_request_size(4096, 4096).unwrap();
        assert_eq!(buffer.allocation_capacity(), 128 * 1024);
        assert_eq!(buffer.request_size(), 4096);
        assert_eq!(buffer.as_uninit().len(), 4096);
    }

    #[test]
    fn over_aligned_buffer_can_serve_a_smaller_volume_alignment() {
        let mut buffer = AlignedBuffer::new(128 * 1024, 64 * 1024).unwrap();
        assert!(buffer.can_serve(4096, 4096));
        buffer.set_request_size(4096, 4096).unwrap();
        assert_eq!(buffer.request_size(), 4096);
    }

    #[test]
    fn direct_io_hashes_unaligned_file_tails() {
        let directory = tempfile::tempdir().unwrap();
        let sizes = [1usize, 511, 512, 4095, 4096, 4097, 65_537, 2_097_155];
        let mut worker = WindowsHashWorker::new(1, Arc::new(IoFeedback::default())).unwrap();
        for size in sizes {
            let bytes = (0..size)
                .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
                .collect::<Vec<_>>();
            let path = directory.path().join(format!("tail-{size}.bin"));
            fs::write(&path, &bytes).unwrap();

            let mut expected = MultiHasher::new(&[Algorithm::Sha256]).unwrap();
            expected.update(&bytes);
            let expected = expected.finalize().unwrap();
            let mut progress = 0u64;
            let actual = worker
                .hash_file(&path, size as u64, &[Algorithm::Sha256], |read| {
                    progress += read;
                })
                .unwrap();
            assert_eq!(actual, expected, "size {size}");
            assert_eq!(progress, size as u64, "size {size}");
        }
    }

    #[test]
    fn early_eof_is_reported_after_buffered_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shortened.bin");
        fs::write(&path, vec![0x5A; 4096]).unwrap();
        let mut progress = 0u64;
        let error = WindowsHashWorker::new(1, Arc::new(IoFeedback::default()))
            .unwrap()
            .hash_file(&path, 8192, &[Algorithm::Sha256], |read| progress += read)
            .unwrap_err();
        assert!(format!("{error:#}").contains("文件在读取期间缩短"));
        assert_eq!(progress, 4096);
    }

    #[test]
    #[ignore = "large Windows sparse-file integration test"]
    fn direct_io_hashes_file_larger_than_four_gibibytes() {
        const SIZE: u64 = 5 * 1024 * 1024 * 1024 + 4097;
        const ZERO_BLOCK_SIZE: usize = 4 * 1024 * 1024;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("five-gib-sparse.bin");
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut returned = 0u32;
        let sparse = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as HANDLE,
                FSCTL_SET_SPARSE,
                null(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        assert_ne!(
            sparse,
            0,
            "FSCTL_SET_SPARSE failed: {}",
            io::Error::last_os_error()
        );
        file.set_len(SIZE).unwrap();
        drop(file);

        let profile = StorageProfile::detect(&path).unwrap();
        let depth = profile.read_depth(SIZE, 1);
        eprintln!(
            "test_io_policy media={:?} request_size={} read_depth={}",
            profile.media,
            profile.request_size(SIZE, 1, depth),
            depth
        );

        let zeros = vec![0u8; ZERO_BLOCK_SIZE];
        let expected_started = Instant::now();
        let mut expected = MultiHasher::new(&[Algorithm::Blake3]).unwrap();
        let mut remaining = SIZE;
        while remaining > 0 {
            let count = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(zeros.len());
            expected.update(&zeros[..count]);
            remaining -= count as u64;
        }
        let expected = expected.finalize().unwrap();
        eprintln!(
            "reference_hash_seconds={:.6}",
            expected_started.elapsed().as_secs_f64()
        );

        let mut progress = 0u64;
        let actual_started = Instant::now();
        let actual = WindowsHashWorker::new(1, Arc::new(IoFeedback::default()))
            .unwrap()
            .hash_file(&path, SIZE, &[Algorithm::Blake3], |read| progress += read)
            .unwrap();
        eprintln!(
            "direct_io_hash_seconds={:.6}",
            actual_started.elapsed().as_secs_f64()
        );
        assert_eq!(actual, expected);
        assert_eq!(progress, SIZE);
    }
}

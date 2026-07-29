use super::{Algorithm, DigestValue, MultiHasher};
use crate::performance;
use anyhow::{Context, Result, anyhow};
use compio::buf::{BufResult, IoBuf, IoBufMut, SetLen};
use compio::fs::OpenOptions;
use compio::io::AsyncReadAt;
use compio::runtime::{Runtime, spawn};
use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::mem::{MaybeUninit, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{NonNull, null, null_mut};
use std::time::Instant;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BusTypeNvme, BusTypeSata, BusTypeScsi, BusTypeUsb, CreateFileW, FILE_FLAG_NO_BUFFERING,
    FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STORAGE_INFO, FileStorageInfo, GetFileInformationByHandleEx, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    DEVICE_SEEK_PENALTY_DESCRIPTOR, DEVICE_TRIM_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY,
    PropertyStandardQuery, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_PROPERTY_ID, STORAGE_PROPERTY_QUERY, StorageAccessAlignmentProperty,
    StorageDeviceProperty, StorageDeviceSeekPenaltyProperty, StorageDeviceTrimProperty,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

const FALLBACK_ALIGNMENT: usize = 4096;
const MIN_REQUEST_SIZE: usize = 64 * 1024;
const MAX_REQUEST_SIZE: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageKind {
    Nvme,
    SataSsd,
    Hdd,
    Usb,
    Network,
    Unknown,
}

pub fn parallelism_limits(path: &Path, files: usize, algorithm_count: usize) -> (usize, usize) {
    let cpu_limit = if algorithm_count >= 4 {
        num_cpus::get().max(1).div_ceil(2)
    } else {
        num_cpus::get().max(1)
    };
    let kind = StorageProfile::detect(path)
        .map(|profile| profile.kind)
        .unwrap_or(StorageKind::Unknown);
    let storage_limit = match kind {
        StorageKind::Nvme => cpu_limit,
        StorageKind::SataSsd => 8,
        StorageKind::Hdd => 2,
        StorageKind::Usb => 4,
        StorageKind::Network => 4,
        StorageKind::Unknown => cpu_limit.min(8),
    };
    let maximum = files.min(cpu_limit).min(storage_limit).max(1);
    let initial = match kind {
        StorageKind::Nvme => 4,
        StorageKind::SataSsd => 2,
        StorageKind::Hdd | StorageKind::Usb => 1,
        StorageKind::Network | StorageKind::Unknown => 2,
    }
    .min(maximum)
    .max(1);
    (initial, maximum)
}

#[derive(Clone, Debug)]
struct StorageProfile {
    root: PathBuf,
    kind: StorageKind,
    io_alignment: usize,
    offset_alignment: u64,
    partition_misaligned: bool,
    direct: bool,
}

impl StorageProfile {
    fn detect(path: &Path) -> Result<Self> {
        let root = volume_root(path).unwrap_or_else(|_| fallback_root(path));
        let filesystem = filesystem_name(&root).unwrap_or_default();
        let is_network = root.as_os_str().encode_wide().take(2).eq(['\\' as u16; 2]);

        let mut logical = FALLBACK_ALIGNMENT as u32;
        let mut physical = FALLBACK_ALIGNMENT as u32;
        let mut sector_offset = 0u32;
        let mut partition_offset = 0u32;
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
                sector_offset = info.ByteOffsetForSectorAlignment;
                partition_offset = info.ByteOffsetForPartitionAlignment;
            }
        }

        let mut bus = None;
        let mut incurs_seek = None;
        let mut trim = None;
        if let Ok(handle) = open_volume(&root) {
            if let Some(alignment) = query_property::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>(
                handle.0,
                StorageAccessAlignmentProperty,
            ) {
                logical = valid_sector(alignment.BytesPerLogicalSector).unwrap_or(logical);
                physical = valid_sector(alignment.BytesPerPhysicalSector).unwrap_or(physical);
                sector_offset = alignment.BytesOffsetForSectorAlignment;
            }
            bus = query_bus_type(handle.0);
            incurs_seek = query_property::<DEVICE_SEEK_PENALTY_DESCRIPTOR>(
                handle.0,
                StorageDeviceSeekPenaltyProperty,
            )
            .map(|descriptor| descriptor.IncursSeekPenalty);
            trim = query_property::<DEVICE_TRIM_DESCRIPTOR>(handle.0, StorageDeviceTrimProperty)
                .map(|descriptor| descriptor.TrimEnabled);
        }

        let kind = classify_storage(is_network, bus, incurs_seek, trim);
        let io_alignment = usize::try_from(logical.max(physical))
            .unwrap_or(FALLBACK_ALIGNMENT)
            .max(FALLBACK_ALIGNMENT);
        let partition_misaligned = physical > 0
            && (!sector_offset.is_multiple_of(physical)
                || !partition_offset.is_multiple_of(physical));
        let direct = kind != StorageKind::Network
            && !matches!(filesystem.to_ascii_uppercase().as_str(), "CDFS" | "UDF");

        performance::record_storage(format!(
            "root={} fs={} kind={kind:?} logical_sector={logical} physical_sector={physical} \
sector_offset={sector_offset} partition_offset={partition_offset} io_alignment={io_alignment} \
partition_misaligned={partition_misaligned} direct_io={direct}",
            root.display(),
            if filesystem.is_empty() {
                "unknown"
            } else {
                &filesystem
            },
        ));

        Ok(Self {
            root,
            kind,
            io_alignment,
            offset_alignment: u64::from(logical),
            partition_misaligned,
            direct,
        })
    }

    fn request_size(&self, file_size: u64, parallelism: usize) -> usize {
        let target = if file_size <= MIN_REQUEST_SIZE as u64 {
            usize::try_from(file_size).unwrap_or(MIN_REQUEST_SIZE)
        } else {
            match self.kind {
                StorageKind::Nvme => 2 * 1024 * 1024,
                StorageKind::SataSsd => 1024 * 1024,
                StorageKind::Hdd => 4 * 1024 * 1024,
                StorageKind::Usb => 512 * 1024,
                StorageKind::Network => 1024 * 1024,
                StorageKind::Unknown => 1024 * 1024,
            }
        };
        let target = if self.partition_misaligned {
            target.max(1024 * 1024)
        } else {
            target
        };
        let per_lane_budget = memory_budget()
            .checked_div(parallelism.max(1).saturating_mul(2))
            .unwrap_or(MIN_REQUEST_SIZE)
            .clamp(MIN_REQUEST_SIZE, MAX_REQUEST_SIZE);
        round_up(
            target.min(per_lane_budget).max(self.io_alignment),
            self.io_alignment,
        )
        .unwrap_or(MAX_REQUEST_SIZE)
        .min(MAX_REQUEST_SIZE)
    }

    fn valid_file_offset(&self, offset: u64) -> bool {
        self.offset_alignment != 0 && offset.is_multiple_of(self.offset_alignment)
    }
}

pub struct WindowsHashWorker {
    runtime: Runtime,
    buffers: Option<(AlignedBuffer, AlignedBuffer)>,
    profiles: Vec<StorageProfile>,
    parallelism: usize,
}

impl WindowsHashWorker {
    pub fn new(parallelism: usize) -> Result<Self> {
        Ok(Self {
            runtime: Runtime::new().context("无法创建 Windows IOCP runtime")?,
            buffers: None,
            profiles: Vec::new(),
            parallelism: parallelism.max(1),
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
            return MultiHasher::new(algorithms)?.finalize();
        }

        let profile = self.profile_for(path);
        let request_size = profile.request_size(size, self.parallelism);
        performance::record_request_size(request_size);
        let mut buffers = match self.buffers.take() {
            Some((first, second))
                if first.can_serve(request_size, profile.io_alignment)
                    && second.can_serve(request_size, profile.io_alignment) =>
            {
                (first, second)
            }
            _ => {
                let capacity = buffer_growth_capacity(request_size, profile.io_alignment)
                    .context("I/O 缓冲区增长大小溢出")?;
                (
                    AlignedBuffer::new(capacity, profile.io_alignment)?,
                    AlignedBuffer::new(capacity, profile.io_alignment)?,
                )
            }
        };
        buffers
            .0
            .set_request_size(request_size, profile.io_alignment)?;
        buffers
            .1
            .set_request_size(request_size, profile.io_alignment)?;

        let direct = profile.direct;
        let mut attempt = self.runtime.block_on(read_and_hash(
            path,
            size,
            algorithms,
            &profile,
            buffers,
            direct,
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
                attempt.buffers,
                false,
                &mut on_read,
            ));
        }
        self.buffers = Some(attempt.buffers);
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
        let profile = StorageProfile::detect(path).unwrap_or_else(|_| {
            let profile = StorageProfile {
                root: fallback_root(path),
                kind: StorageKind::Unknown,
                io_alignment: FALLBACK_ALIGNMENT,
                offset_alignment: FALLBACK_ALIGNMENT as u64,
                partition_misaligned: false,
                direct: true,
            };
            performance::record_storage(format!(
                "root={} fs=unknown kind=Unknown io_alignment={} direct_io=true detection=fallback",
                profile.root.display(),
                profile.io_alignment
            ));
            profile
        });
        self.profiles.push(profile.clone());
        profile
    }
}

impl Drop for WindowsHashWorker {
    fn drop(&mut self) {
        performance::flush_thread_metrics();
    }
}

struct ReadAttempt {
    result: Result<Vec<(Algorithm, DigestValue)>>,
    buffers: (AlignedBuffer, AlignedBuffer),
    bytes: u64,
}

async fn read_and_hash<F>(
    path: &Path,
    expected_size: u64,
    algorithms: &[Algorithm],
    profile: &StorageProfile,
    buffers: (AlignedBuffer, AlignedBuffer),
    direct: bool,
    on_read: &mut F,
) -> ReadAttempt
where
    F: FnMut(u64),
{
    let mut processed = 0u64;
    let (mut current, mut spare) = buffers;
    let mut direct_active = direct;
    let mut file = match open_hash_file(path, direct_active).await {
        Ok(file) => file,
        Err(error) => {
            return ReadAttempt {
                result: Err(error).with_context(|| format!("无法打开 {}", path.display())),
                buffers: (current, spare),
                bytes: processed,
            };
        }
    };
    let mut hasher = match MultiHasher::new(algorithms) {
        Ok(hasher) => hasher,
        Err(error) => {
            return ReadAttempt {
                result: Err(error),
                buffers: (current, spare),
                bytes: processed,
            };
        }
    };

    let (mut read, returned) = read_owned(file.clone(), current, processed, direct_active).await;
    current = returned;
    loop {
        let count = match read {
            Ok(count) => count,
            Err(error) if direct_active && is_direct_io_code(error.raw_os_error()) => {
                performance::record_direct_fallback();
                file = match open_hash_file(path, false).await {
                    Ok(file) => file,
                    Err(open_error) => {
                        return ReadAttempt {
                            result: Err(open_error).with_context(|| {
                                format!("Direct I/O 失败后无法重新打开 {}", path.display())
                            }),
                            buffers: (current, spare),
                            bytes: processed,
                        };
                    }
                };
                direct_active = false;
                (read, current) = read_owned(file.clone(), current, processed, direct_active).await;
                continue;
            }
            Err(error) => {
                return ReadAttempt {
                    result: Err(error).with_context(|| format!("无法读取 {}", path.display())),
                    buffers: (current, spare),
                    bytes: processed,
                };
            }
        };
        if count == 0 {
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
                            buffers: (current, spare),
                            bytes: processed,
                        };
                    }
                };
                direct_active = false;
                (read, current) = read_owned(file.clone(), current, processed, direct_active).await;
                continue;
            }
            return ReadAttempt {
                result: Err(anyhow!(
                    "文件在读取期间缩短: {}（读取到 {} 字节，扫描时为 {} 字节）",
                    path.display(),
                    processed,
                    expected_size
                )),
                buffers: (current, spare),
                bytes: processed,
            };
        }
        let remaining = expected_size - processed;
        let accepted = usize::try_from(remaining).unwrap_or(usize::MAX).min(count);
        let next_offset = processed + accepted as u64;
        if count < current.request_size() && next_offset < expected_size {
            performance::record_short_read();
        }

        if direct_active && next_offset < expected_size && !profile.valid_file_offset(next_offset) {
            performance::record_direct_fallback();
            file = match open_hash_file(path, false).await {
                Ok(file) => file,
                Err(error) => {
                    return ReadAttempt {
                        result: Err(error)
                            .with_context(|| format!("无法在短读后重新打开 {}", path.display())),
                        buffers: (current, spare),
                        bytes: processed,
                    };
                }
            };
            direct_active = false;
        }

        if next_offset >= expected_size {
            let hash_started = performance::sample_hash_timing().then(Instant::now);
            hasher.update(&current.as_init()[..accepted]);
            performance::record_hash(accepted, hash_started.map(|started| started.elapsed()));
            processed = next_offset;
            on_read(accepted as u64);
            return ReadAttempt {
                result: hasher.finalize(),
                buffers: (current, spare),
                bytes: processed,
            };
        }

        let next_file = file.clone();
        let pending_direct = direct_active;
        let pending =
            spawn(async move { read_owned(next_file, spare, next_offset, pending_direct).await });
        yield_to_runtime().await;
        let hash_started = performance::sample_hash_timing().then(Instant::now);
        hasher.update(&current.as_init()[..accepted]);
        performance::record_hash(accepted, hash_started.map(|started| started.elapsed()));
        processed = next_offset;
        on_read(accepted as u64);

        let (next_read, next_buffer) = pending
            .await
            .expect("Compio read-ahead task must run to completion");
        spare = current;
        current = next_buffer;
        read = next_read;
    }
}

async fn read_owned(
    file: compio::fs::File,
    mut buffer: AlignedBuffer,
    offset: u64,
    direct: bool,
) -> (io::Result<usize>, AlignedBuffer) {
    unsafe { buffer.set_len(0) };
    let started = performance::sample_read_timing().then(Instant::now);
    let BufResult(read, buffer) = file.read_at(buffer, offset).await;
    performance::record_read(
        direct,
        read.as_ref().copied().unwrap_or(0),
        read.is_ok(),
        started.map(|started| started.elapsed()),
    );
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
                "无效的 Direct I/O 请求大小 {request_size}（容量 {}，缓冲区对齐 {}，所需对齐 {required_alignment}）",
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
    (value >= 512 && value.is_power_of_two()).then_some(value)
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

fn query_bus_type(handle: HANDLE) -> Option<i32> {
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
    Some(descriptor.BusType)
}

fn classify_storage(
    network: bool,
    bus: Option<i32>,
    seek: Option<bool>,
    trim: Option<bool>,
) -> StorageKind {
    if network {
        return StorageKind::Network;
    }
    match bus {
        Some(value) if value == BusTypeNvme => StorageKind::Nvme,
        Some(value) if value == BusTypeUsb => StorageKind::Usb,
        Some(value) if (value == BusTypeSata || value == BusTypeScsi) && seek == Some(true) => {
            StorageKind::Hdd
        }
        Some(value)
            if (value == BusTypeSata || value == BusTypeScsi)
                && (trim == Some(true) || seek == Some(false)) =>
        {
            StorageKind::SataSsd
        }
        _ if seek == Some(true) => StorageKind::Hdd,
        _ if trim == Some(true) || seek == Some(false) => StorageKind::SataSsd,
        _ => StorageKind::Unknown,
    }
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
        let mut worker = WindowsHashWorker::new(1).unwrap();
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
        let error = WindowsHashWorker::new(1)
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

        let zeros = vec![0u8; ZERO_BLOCK_SIZE];
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

        let mut progress = 0u64;
        let actual = WindowsHashWorker::new(1)
            .unwrap()
            .hash_file(&path, SIZE, &[Algorithm::Blake3], |read| progress += read)
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(progress, SIZE);
    }
}

use anyhow::{Context, Result, bail};
use glob::glob;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::path::Component;

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FIND_FIRST_EX_LARGE_FETCH, FindClose,
    FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, WIN32_FIND_DATAW,
};

#[derive(Clone, Debug)]
pub struct InputSpec {
    raw: String,
    kind: InputKind,
    base: PathBuf,
}

#[derive(Clone, Debug)]
enum InputKind {
    Path(PathBuf),
    Glob(String),
}

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub path: PathBuf,
    pub relative: PathBuf,
    pub size: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ScanSummary {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub workload: WorkloadSummary,
}

#[derive(Clone, Debug, Default)]
pub struct WorkloadSummary {
    pub tiny_files: u64,
    pub small_files: u64,
    pub medium_files: u64,
    pub large_files: u64,
    pub largest_file: u64,
}

pub struct ScanPlan {
    summary: ScanSummary,
    base: PathBuf,
    entries: Vec<(File, u64)>,
}

const PLAN_BUFFER_SIZE: usize = 1024 * 1024;
const TINY_FILE_LIMIT: u64 = 64 * 1024;
const SMALL_FILE_LIMIT: u64 = 1024 * 1024;
const LARGE_FILE_LIMIT: u64 = 64 * 1024 * 1024;

impl WorkloadSummary {
    fn record(&mut self, size: u64) {
        self.largest_file = self.largest_file.max(size);
        if size < TINY_FILE_LIMIT {
            self.tiny_files += 1;
        } else if size < SMALL_FILE_LIMIT {
            self.small_files += 1;
        } else if size < LARGE_FILE_LIMIT {
            self.medium_files += 1;
        } else {
            self.large_files += 1;
        }
    }
}

impl ScanPlan {
    pub fn summary(&self) -> &ScanSummary {
        &self.summary
    }

    pub fn for_each_entry<F>(&mut self, mut visitor: F) -> Result<()>
    where
        F: FnMut(FileEntry) -> Result<()>,
    {
        replay_plan_partitions(&mut self.entries, &self.base, &mut visitor)
    }
}

impl InputSpec {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            bail!("路径不能为空");
        }
        let path = PathBuf::from(raw);
        if path.exists() {
            let absolute = absolute_path(&path)?;
            let base = if absolute.is_dir() {
                absolute.clone()
            } else {
                absolute
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf()
            };
            return Ok(Self {
                raw: raw.into(),
                kind: InputKind::Path(absolute),
                base,
            });
        }
        if contains_glob(raw) {
            return Ok(Self {
                raw: raw.into(),
                kind: InputKind::Glob(raw.into()),
                base: std::env::current_dir()?,
            });
        }
        bail!("路径不存在, 且不是有效通配符: {raw}")
    }

    pub fn describe(&self) -> &str {
        &self.raw
    }

    pub fn is_single_file(&self) -> bool {
        matches!(&self.kind, InputKind::Path(path) if path.is_file())
    }

    pub fn probe_path(&self) -> &Path {
        match &self.kind {
            InputKind::Path(path) => path,
            InputKind::Glob(_) => &self.base,
        }
    }

    pub fn plan(&self) -> Result<ScanPlan> {
        let mut entries = HashMap::<PathBuf, (BufWriter<File>, u64)>::new();
        let summary = self.visit_files(|entry| {
            let volume = volume_key(&entry.path);
            if !entries.contains_key(&volume) {
                entries.insert(
                    volume.clone(),
                    (
                        BufWriter::with_capacity(PLAN_BUFFER_SIZE, tempfile::tempfile()?),
                        0,
                    ),
                );
            }
            let (writer, records) = entries
                .get_mut(&volume)
                .expect("plan partition was inserted");
            *records += 1;
            write_plan_entry(writer, &entry)
        })?;
        let mut plan_entries = Vec::with_capacity(entries.len());
        for (volume, (mut writer, records)) in entries {
            writer.flush()?;
            let mut file = writer.into_inner()?;
            file.seek(SeekFrom::Start(0))?;
            plan_entries.push((volume, file, records));
        }
        plan_entries.sort_by(|left, right| left.0.cmp(&right.0));
        let entries = plan_entries
            .into_iter()
            .map(|(_, file, records)| (file, records))
            .collect();
        Ok(ScanPlan {
            summary,
            base: self.base.clone(),
            entries,
        })
    }

    pub fn visit_files<F>(&self, mut visitor: F) -> Result<ScanSummary>
    where
        F: FnMut(FileEntry) -> Result<()>,
    {
        let mut summary = ScanSummary::default();
        match &self.kind {
            InputKind::Path(path) => {
                visit_path(path, &self.base, &mut summary, &mut visitor)?;
            }
            InputKind::Glob(pattern) => {
                let mut seen = HashSet::new();
                for matched in glob(pattern).with_context(|| format!("通配符无效: {pattern}"))?
                {
                    match matched {
                        Ok(path) => {
                            let absolute = absolute_path(&path)?;
                            if seen.insert(absolute.clone()) {
                                visit_path(&absolute, &self.base, &mut summary, &mut visitor)?;
                            }
                        }
                        Err(_) => summary.skipped += 1,
                    }
                }
            }
        }
        Ok(summary)
    }
}

fn visit_path<F>(path: &Path, base: &Path, summary: &mut ScanSummary, visitor: &mut F) -> Result<()>
where
    F: FnMut(FileEntry) -> Result<()>,
{
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            summary.skipped += 1;
            return Ok(());
        }
    };
    if metadata.is_file() {
        let relative = path.strip_prefix(base).unwrap_or(path).to_path_buf();
        summary.files += 1;
        summary.bytes = summary.bytes.saturating_add(metadata.len());
        summary.workload.record(metadata.len());
        visitor(FileEntry {
            path: path.to_path_buf(),
            relative,
            size: metadata.len(),
        })?;
        return Ok(());
    }
    if !metadata.is_dir() {
        summary.skipped += 1;
        return Ok(());
    }

    let mut stack = vec![path.to_path_buf()];
    while let Some(directory) = stack.pop() {
        #[cfg(windows)]
        {
            visit_windows_directory(&directory, base, summary, visitor, &mut stack)?;
            continue;
        }
        #[cfg(not(windows))]
        {
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(_) => {
                    summary.skipped += 1;
                    continue;
                }
            };
            let mut entries = entries.filter_map(Result::ok).collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries.into_iter().rev() {
                visit_directory_entry(entry, base, summary, visitor, &mut stack)?;
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn visit_directory_entry<F>(
    entry: fs::DirEntry,
    base: &Path,
    summary: &mut ScanSummary,
    visitor: &mut F,
    stack: &mut Vec<PathBuf>,
) -> Result<()>
where
    F: FnMut(FileEntry) -> Result<()>,
{
    let file_type = match entry.file_type() {
        Ok(file_type) => file_type,
        Err(_) => {
            summary.skipped += 1;
            return Ok(());
        }
    };
    let child = entry.path();
    if file_type.is_symlink() {
        if child.is_file() {
            add_file(&child, base, summary, visitor)?;
        } else {
            summary.skipped += 1;
        }
    } else if file_type.is_dir() {
        stack.push(child);
    } else if file_type.is_file() {
        add_file(&child, base, summary, visitor)?;
    }
    Ok(())
}

#[cfg(windows)]
fn visit_windows_directory<F>(
    directory: &Path,
    base: &Path,
    summary: &mut ScanSummary,
    visitor: &mut F,
    stack: &mut Vec<PathBuf>,
) -> Result<()>
where
    F: FnMut(FileEntry) -> Result<()>,
{
    let mut pattern = directory.as_os_str().encode_wide().collect::<Vec<_>>();
    if !pattern
        .last()
        .is_some_and(|value| *value == '\\' as u16 || *value == '/' as u16)
    {
        pattern.push('\\' as u16);
    }
    pattern.extend(['*' as u16, 0]);
    let mut data = WIN32_FIND_DATAW::default();
    let handle = unsafe {
        FindFirstFileExW(
            pattern.as_ptr(),
            FindExInfoBasic,
            (&mut data as *mut WIN32_FIND_DATAW).cast(),
            FindExSearchNameMatch,
            std::ptr::null(),
            FIND_FIRST_EX_LARGE_FETCH,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        summary.skipped += 1;
        return Ok(());
    }
    let handle = FindHandle(handle);

    loop {
        let name_len = data
            .cFileName
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(data.cFileName.len());
        let name = &data.cFileName[..name_len];
        let is_dot = name == ['.' as u16] || name == ['.' as u16, '.' as u16];
        if !is_dot {
            let child = directory.join(std::ffi::OsString::from_wide(name));
            let attributes = data.dwFileAttributes;
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                if child.is_file() {
                    add_file(&child, base, summary, visitor)?;
                } else {
                    summary.skipped += 1;
                }
            } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                stack.push(child);
            } else {
                let size = (u64::from(data.nFileSizeHigh) << 32) | u64::from(data.nFileSizeLow);
                summary.files += 1;
                summary.bytes = summary.bytes.saturating_add(size);
                summary.workload.record(size);
                visitor(FileEntry {
                    relative: child.strip_prefix(base).unwrap_or(&child).to_path_buf(),
                    path: child,
                    size,
                })?;
            }
        }

        let next = unsafe { FindNextFileW(handle.0, &mut data) };
        if next == 0 {
            break;
        }
    }
    Ok(())
}

#[cfg(windows)]
struct FindHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for FindHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = FindClose(self.0);
        }
    }
}

fn add_file<F>(path: &Path, base: &Path, summary: &mut ScanSummary, visitor: &mut F) -> Result<()>
where
    F: FnMut(FileEntry) -> Result<()>,
{
    match fs::metadata(path) {
        Ok(metadata) => {
            summary.files += 1;
            summary.bytes = summary.bytes.saturating_add(metadata.len());
            summary.workload.record(metadata.len());
            visitor(FileEntry {
                path: path.to_path_buf(),
                relative: path.strip_prefix(base).unwrap_or(path).to_path_buf(),
                size: metadata.len(),
            })?;
        }
        Err(_) => summary.skipped += 1,
    }
    Ok(())
}

fn contains_glob(value: &str) -> bool {
    value.contains(['*', '?', '['])
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn write_plan_entry(writer: &mut impl Write, entry: &FileEntry) -> Result<()> {
    writer.write_all(&entry.size.to_le_bytes())?;
    write_plan_path(writer, &entry.relative)?;
    Ok(())
}

fn replay_plan_partitions<F>(
    partitions: &mut [(File, u64)],
    base: &Path,
    visitor: &mut F,
) -> Result<()>
where
    F: FnMut(FileEntry) -> Result<()>,
{
    for (file, _) in partitions.iter_mut() {
        file.seek(SeekFrom::Start(0))?;
    }
    let mut readers = partitions
        .iter_mut()
        .map(|(file, records)| (BufReader::with_capacity(PLAN_BUFFER_SIZE, file), *records))
        .collect::<Vec<_>>();
    loop {
        let mut progressed = false;
        for (reader, remaining) in &mut readers {
            if *remaining == 0 {
                continue;
            }
            visitor(read_plan_entry(reader, base)?)?;
            *remaining -= 1;
            progressed = true;
        }
        if !progressed {
            return Ok(());
        }
    }
}

fn volume_key(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let mut components = path.components();
        if let Some(Component::Prefix(prefix)) = components.next() {
            let mut root = PathBuf::from(prefix.as_os_str());
            root.push("\\");
            return root;
        }
    }
    path.ancestors()
        .last()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn read_plan_entry(reader: &mut impl Read, base: &Path) -> Result<FileEntry> {
    let mut size = [0u8; 8];
    reader.read_exact(&mut size).context("临时任务清单不完整")?;
    let relative = read_plan_path(reader)?;
    let path = if relative.is_absolute() {
        relative.clone()
    } else {
        base.join(&relative)
    };
    Ok(FileEntry {
        size: u64::from_le_bytes(size),
        path,
        relative,
    })
}

fn write_plan_path(writer: &mut impl Write, path: &Path) -> Result<()> {
    let bytes = encode_path(path);
    let len = u32::try_from(bytes.len()).context("任务清单中的文件路径过长")?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&bytes)?;
    Ok(())
}

fn read_plan_path(reader: &mut impl Read) -> Result<PathBuf> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).context("临时任务路径不完整")?;
    let mut bytes = vec![0u8; u32::from_le_bytes(len) as usize];
    reader
        .read_exact(&mut bytes)
        .context("临时任务路径不完整")?;
    decode_path(bytes)
}

#[cfg(unix)]
fn encode_path(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(unix)]
fn decode_path(bytes: Vec<u8>) -> Result<PathBuf> {
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(windows)]
fn encode_path(path: &Path) -> Vec<u8> {
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(windows)]
fn decode_path(bytes: Vec<u8>) -> Result<PathBuf> {
    if !bytes.len().is_multiple_of(2) {
        bail!("临时任务路径的 UTF-16 数据不完整");
    }
    let wide = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    Ok(PathBuf::from(OsString::from_wide(&wide)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn scans_directories_recursively() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("nested")).unwrap();
        fs::File::create(directory.path().join("a"))
            .unwrap()
            .write_all(b"abc")
            .unwrap();
        fs::File::create(directory.path().join("nested/b"))
            .unwrap()
            .write_all(b"12345")
            .unwrap();
        let spec = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let plan = spec.plan().unwrap();
        let summary = plan.summary();
        assert_eq!(summary.files, 2);
        assert_eq!(summary.bytes, 8);
    }

    #[test]
    fn scan_plan_replays_entries_without_rescanning() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("a"), b"abc").unwrap();
        fs::write(directory.path().join("b"), vec![0u8; 70 * 1024]).unwrap();
        let spec = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let mut plan = spec.plan().unwrap();
        assert_eq!(plan.summary().files, 2);
        assert_eq!(plan.summary().workload.tiny_files, 1);
        assert_eq!(plan.summary().workload.small_files, 1);
        let mut entries = Vec::new();
        plan.for_each_entry(|entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
        entries.sort_by(|left, right| left.relative.cmp(&right.relative));
        assert_eq!(entries[0].relative, PathBuf::from("a"));
        assert_eq!(entries[0].size, 3);
        assert_eq!(entries[1].relative, PathBuf::from("b"));
    }

    #[test]
    fn scan_plan_keeps_all_sizes_in_the_same_volume_partition() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("a-small"), b"small").unwrap();
        fs::write(directory.path().join("z-bulk"), vec![0u8; 1024 * 1024]).unwrap();
        let spec = InputSpec::parse(directory.path().to_str().unwrap()).unwrap();
        let mut plan = spec.plan().unwrap();
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].1, 2);
        let mut paths = Vec::new();
        plan.for_each_entry(|entry| {
            paths.push(entry.relative);
            Ok(())
        })
        .unwrap();
        paths.sort();
        assert_eq!(paths, [PathBuf::from("a-small"), PathBuf::from("z-bulk")]);
    }

    #[test]
    fn bulk_partitions_are_replayed_round_robin() {
        let mut first = tempfile::tempfile().unwrap();
        let mut second = tempfile::tempfile().unwrap();
        for name in ["a", "c"] {
            write_plan_entry(
                &mut first,
                &FileEntry {
                    path: PathBuf::from(name),
                    relative: PathBuf::from(name),
                    size: SMALL_FILE_LIMIT,
                },
            )
            .unwrap();
        }
        write_plan_entry(
            &mut second,
            &FileEntry {
                path: PathBuf::from("b"),
                relative: PathBuf::from("b"),
                size: SMALL_FILE_LIMIT,
            },
        )
        .unwrap();
        let mut partitions = vec![(first, 2), (second, 1)];
        let mut order = Vec::new();
        replay_plan_partitions(&mut partitions, Path::new("."), &mut |entry| {
            order.push(entry.relative);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            order,
            [PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")]
        );
    }

    #[cfg(windows)]
    #[test]
    fn volume_key_keeps_windows_drive_roots_separate() {
        assert_eq!(volume_key(Path::new("C:\\one")), PathBuf::from("C:\\"));
        assert_eq!(volume_key(Path::new("D:\\two")), PathBuf::from("D:\\"));
    }
}

use anyhow::{Context, Result, bail};
use glob::glob;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

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

    pub fn inspect(&self) -> Result<ScanSummary> {
        self.visit_files(|_| Ok(()))
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
        let summary = spec.inspect().unwrap();
        assert_eq!(summary.files, 2);
        assert_eq!(summary.bytes, 8);
    }
}

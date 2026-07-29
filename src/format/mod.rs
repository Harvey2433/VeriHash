mod blazehash;
pub mod detect;
mod gnu;
mod tagged;

use crate::spool::ResultSpool;
use anyhow::{Context, Result, bail};
use std::fmt;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    BlazeHash,
    VeriHash,
    GnuSumfiles,
}

impl OutputFormat {
    pub const ALL: [Self; 3] = [Self::BlazeHash, Self::VeriHash, Self::GnuSumfiles];
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BlazeHash => "BlazeHash Compatible",
            Self::VeriHash => "VeriHash Grouped",
            Self::GnuSumfiles => "GNU sumfiles",
        })
    }
}

pub fn write_outputs(
    spool: &mut ResultSpool,
    formats: &[OutputFormat],
    destination: &Path,
) -> Result<Vec<PathBuf>> {
    if formats.is_empty() {
        bail!("至少选择一种输出格式");
    }
    fs::create_dir_all(destination)
        .with_context(|| format!("无法创建输出目录 {}", destination.display()))?;
    let mut written = Vec::new();
    for format in formats {
        match format {
            OutputFormat::BlazeHash => {
                let path = destination.join("checksums.blazehash");
                write_atomic(&path, |writer| blazehash::write(spool, writer))?;
                written.push(path);
            }
            OutputFormat::VeriHash => {
                let path = destination.join("checksums.verihash");
                write_atomic(&path, |writer| tagged::write(spool, writer))?;
                written.push(path);
            }
            OutputFormat::GnuSumfiles => {
                for algorithm in spool.algorithms().to_vec() {
                    let path = destination.join(algorithm.sumfile_name());
                    write_atomic(&path, |writer| gnu::write(spool, &algorithm, writer))?;
                    written.push(path);
                }
            }
        }
    }
    Ok(written)
}

pub fn output_paths(
    algorithms: &[crate::algorithm::Algorithm],
    formats: &[OutputFormat],
    destination: &Path,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for format in formats {
        match format {
            OutputFormat::BlazeHash => paths.push(destination.join("checksums.blazehash")),
            OutputFormat::VeriHash => paths.push(destination.join("checksums.verihash")),
            OutputFormat::GnuSumfiles => paths.extend(
                algorithms
                    .iter()
                    .map(|algorithm| destination.join(algorithm.sumfile_name())),
            ),
        }
    }
    paths
}

fn write_atomic<F>(path: &Path, write: F) -> Result<()>
where
    F: FnOnce(&mut dyn Write) -> Result<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)?;
    {
        let mut writer = BufWriter::with_capacity(1024 * 1024, temp.as_file_mut());
        write(&mut writer)?;
        writer.flush()?;
    }
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("无法保存 {}", path.display()))?;
    Ok(())
}

pub(crate) fn path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{Algorithm, DigestValue};
    use crate::format::detect;
    use crate::spool::{ComputedFile, SpoolWriter};

    fn sample_spool() -> Result<ResultSpool> {
        let algorithms = [Algorithm::Md5, Algorithm::Sha256];
        let mut writer = SpoolWriter::new(&algorithms)?;
        writer.push(&ComputedFile {
            relative: PathBuf::from("folder/a,b.txt"),
            size: 0,
            hashes: vec![
                (
                    Algorithm::Md5,
                    DigestValue::from_hex("d41d8cd98f00b204e9800998ecf8427e", 16)?,
                ),
                (
                    Algorithm::Sha256,
                    DigestValue::from_hex(
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        32,
                    )?,
                ),
            ],
        })?;
        writer.finish()
    }

    #[test]
    fn writes_and_detects_all_output_formats() {
        let directory = tempfile::tempdir().unwrap();
        let mut spool = sample_spool().unwrap();
        let formats = OutputFormat::ALL;
        let written = write_outputs(&mut spool, &formats, directory.path()).unwrap();
        assert_eq!(written.len(), 4);

        let blaze = detect::detect(&directory.path().join("checksums.blazehash"))
            .unwrap()
            .unwrap();
        assert_eq!(blaze.entries.len(), 1);
        assert_eq!(blaze.entries[0].hashes.len(), 2);
        assert!(blaze.entries[0].target.ends_with("folder/a,b.txt"));

        let gnu = detect::detect(&directory.path().join("sha256sums"))
            .unwrap()
            .unwrap();
        assert_eq!(gnu.entries[0].hashes[0].0, Algorithm::Sha256);

        let tagged = fs::read_to_string(directory.path().join("checksums.verihash")).unwrap();
        assert!(tagged.contains("#MD5#"));
        assert!(tagged.contains("\n\n#SHA256#"));

        write_outputs(&mut spool, &formats, directory.path()).unwrap();
    }
}

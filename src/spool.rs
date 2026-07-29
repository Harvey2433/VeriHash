use crate::algorithm::{Algorithm, DigestValue};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

const SPOOL_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ComputedFile {
    pub relative: PathBuf,
    pub size: u64,
    pub hashes: Vec<(Algorithm, DigestValue)>,
}

pub struct SpoolWriter {
    algorithms: Vec<Algorithm>,
    metadata: BufWriter<File>,
    digests: BTreeMap<Algorithm, BufWriter<File>>,
    records: u64,
}

pub struct ResultSpool {
    algorithms: Vec<Algorithm>,
    metadata: File,
    digests: BTreeMap<Algorithm, File>,
    records: u64,
}

impl SpoolWriter {
    pub fn new(algorithms: &[Algorithm]) -> Result<Self> {
        let mut algorithms = algorithms.to_vec();
        algorithms.sort();
        algorithms.dedup();
        let metadata = BufWriter::with_capacity(SPOOL_BUFFER_SIZE, tempfile::tempfile()?);
        let mut digests = BTreeMap::new();
        for algorithm in &algorithms {
            digests.insert(
                algorithm.clone(),
                BufWriter::with_capacity(SPOOL_BUFFER_SIZE, tempfile::tempfile()?),
            );
        }
        Ok(Self {
            algorithms,
            metadata,
            digests,
            records: 0,
        })
    }

    pub fn push(&mut self, result: &ComputedFile) -> Result<()> {
        self.metadata.write_all(&result.size.to_le_bytes())?;
        let path_bytes = encode_path(&result.relative);
        let path_len = u32::try_from(path_bytes.len()).context("文件路径过长")?;
        self.metadata.write_all(&path_len.to_le_bytes())?;
        self.metadata.write_all(&path_bytes)?;

        for algorithm in &self.algorithms {
            let (_, digest) = result
                .hashes
                .iter()
                .find(|(candidate, _)| candidate == algorithm)
                .with_context(|| {
                    format!("{} 缺少 {} 结果", result.relative.display(), algorithm)
                })?;
            self.digests
                .get_mut(algorithm)
                .expect("algorithm spool exists")
                .write_all(digest.as_bytes())?;
        }
        self.records += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<ResultSpool> {
        self.metadata.flush()?;
        let mut metadata = self.metadata.into_inner()?;
        metadata.seek(SeekFrom::Start(0))?;
        let mut digests = BTreeMap::new();
        for (algorithm, mut writer) in self.digests {
            writer.flush()?;
            let mut file = writer.into_inner()?;
            file.seek(SeekFrom::Start(0))?;
            digests.insert(algorithm, file);
        }
        Ok(ResultSpool {
            algorithms: self.algorithms,
            metadata,
            digests,
            records: self.records,
        })
    }
}

impl ResultSpool {
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    pub fn for_each_record<F>(&mut self, mut visitor: F) -> Result<()>
    where
        F: FnMut(ComputedFile) -> Result<()>,
    {
        self.metadata.seek(SeekFrom::Start(0))?;
        for file in self.digests.values_mut() {
            file.seek(SeekFrom::Start(0))?;
        }
        let mut metadata = BufReader::with_capacity(SPOOL_BUFFER_SIZE, &mut self.metadata);
        for _ in 0..self.records {
            let (size, relative) = read_metadata(&mut metadata)?;
            let mut hashes = Vec::with_capacity(self.algorithms.len());
            for algorithm in &self.algorithms {
                let mut bytes = vec![0; algorithm.digest_len()];
                self.digests
                    .get_mut(algorithm)
                    .expect("algorithm spool exists")
                    .read_exact(&mut bytes)?;
                hashes.push((algorithm.clone(), DigestValue::from_slice(&bytes)?));
            }
            visitor(ComputedFile {
                relative,
                size,
                hashes,
            })?;
        }
        Ok(())
    }

    pub fn for_each_algorithm_record<F>(
        &mut self,
        algorithm: &Algorithm,
        mut visitor: F,
    ) -> Result<()>
    where
        F: FnMut(u64, &PathBuf, DigestValue) -> Result<()>,
    {
        self.metadata.seek(SeekFrom::Start(0))?;
        let digest_file = self
            .digests
            .get_mut(algorithm)
            .with_context(|| format!("临时结果中没有 {algorithm}"))?;
        digest_file.seek(SeekFrom::Start(0))?;
        let mut metadata = BufReader::with_capacity(SPOOL_BUFFER_SIZE, &mut self.metadata);
        for _ in 0..self.records {
            let (size, relative) = read_metadata(&mut metadata)?;
            let mut bytes = vec![0; algorithm.digest_len()];
            digest_file.read_exact(&mut bytes)?;
            visitor(size, &relative, DigestValue::from_slice(&bytes)?)?;
        }
        Ok(())
    }
}

fn read_metadata(reader: &mut impl Read) -> Result<(u64, PathBuf)> {
    let mut size = [0; 8];
    if let Err(error) = reader.read_exact(&mut size) {
        if error.kind() == ErrorKind::UnexpectedEof {
            bail!("临时结果元数据不完整");
        }
        return Err(error.into());
    }
    let mut path_len = [0; 4];
    reader.read_exact(&mut path_len)?;
    let path_len = u32::from_le_bytes(path_len) as usize;
    let mut path = vec![0; path_len];
    reader.read_exact(&mut path)?;
    Ok((u64::from_le_bytes(size), decode_path(path)?))
}

#[cfg(unix)]
fn encode_path(path: &std::path::Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(unix)]
fn decode_path(bytes: Vec<u8>) -> Result<PathBuf> {
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(windows)]
fn encode_path(path: &std::path::Path) -> Vec<u8> {
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(windows)]
fn decode_path(bytes: Vec<u8>) -> Result<PathBuf> {
    if !bytes.len().is_multiple_of(2) {
        bail!("临时路径的 UTF-16 数据不完整");
    }
    let wide = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    Ok(PathBuf::from(OsString::from_wide(&wide)))
}

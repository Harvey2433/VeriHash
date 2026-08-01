use crate::algorithm::{Algorithm, DigestValue};
use crate::io_feedback::IoFeedback;
use crate::scanner::WorkloadSummary;
#[cfg(not(windows))]
use anyhow::Context;
use anyhow::Result;
use rayon::prelude::*;
use sha2::digest::Digest;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
#[cfg(not(windows))]
use std::fs::{File, OpenOptions};
#[cfg(not(windows))]
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub const READ_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const PARALLEL_HASHER_THRESHOLD: usize = 4;

pub struct MultiHasher {
    states: Vec<(Algorithm, HasherState)>,
}

enum HasherState {
    Md5(fast_md5::Md5),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512_224(Sha512_224),
    Sha512_256(Sha512_256),
    Sha3_224(Sha3_224),
    Sha3_256(Sha3_256),
    Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
    Blake2s(blake2s_simd::State),
    Blake2b(blake2b_simd::State),
    Blake3(Box<blake3::Hasher>),
}

impl MultiHasher {
    pub fn new(algorithms: &[Algorithm]) -> Result<Self> {
        let mut algorithms = algorithms.to_vec();
        algorithms.sort();
        algorithms.dedup();
        let states = algorithms
            .into_iter()
            .map(|algorithm| {
                let state = HasherState::new(&algorithm)?;
                Ok((algorithm, state))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { states })
    }

    pub fn update(&mut self, bytes: &[u8]) {
        if self.states.len() >= PARALLEL_HASHER_THRESHOLD {
            self.states
                .par_iter_mut()
                .for_each(|(_, state)| state.update(bytes));
        } else {
            for (_, state) in &mut self.states {
                state.update(bytes);
            }
        }
    }

    pub fn finalize(self) -> Result<Vec<(Algorithm, DigestValue)>> {
        self.states
            .into_iter()
            .map(|(algorithm, state)| Ok((algorithm, state.finalize()?)))
            .collect()
    }
}

impl HasherState {
    fn new(algorithm: &Algorithm) -> Result<Self> {
        Ok(match algorithm {
            Algorithm::Md5 => Self::Md5(fast_md5::Md5::new()),
            Algorithm::Sha224 => Self::Sha224(Sha224::new()),
            Algorithm::Sha256 => Self::Sha256(Sha256::new()),
            Algorithm::Sha384 => Self::Sha384(Sha384::new()),
            Algorithm::Sha512 => Self::Sha512(Sha512::new()),
            Algorithm::Sha512_224 => Self::Sha512_224(Sha512_224::new()),
            Algorithm::Sha512_256 => Self::Sha512_256(Sha512_256::new()),
            Algorithm::Sha3_224 => Self::Sha3_224(Sha3_224::new()),
            Algorithm::Sha3_256 => Self::Sha3_256(Sha3_256::new()),
            Algorithm::Sha3_384 => Self::Sha3_384(Sha3_384::new()),
            Algorithm::Sha3_512 => Self::Sha3_512(Sha3_512::new()),
            Algorithm::Blake2s(bytes) => Self::Blake2s(
                blake2s_simd::Params::new()
                    .hash_length(usize::from(*bytes))
                    .to_state(),
            ),
            Algorithm::Blake2b(bytes) => Self::Blake2b(
                blake2b_simd::Params::new()
                    .hash_length(usize::from(*bytes))
                    .to_state(),
            ),
            Algorithm::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
        })
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Md5(value) => value.update(bytes),
            Self::Sha224(value) => Digest::update(value, bytes),
            Self::Sha256(value) => Digest::update(value, bytes),
            Self::Sha384(value) => Digest::update(value, bytes),
            Self::Sha512(value) => Digest::update(value, bytes),
            Self::Sha512_224(value) => Digest::update(value, bytes),
            Self::Sha512_256(value) => Digest::update(value, bytes),
            Self::Sha3_224(value) => Digest::update(value, bytes),
            Self::Sha3_256(value) => Digest::update(value, bytes),
            Self::Sha3_384(value) => Digest::update(value, bytes),
            Self::Sha3_512(value) => Digest::update(value, bytes),
            Self::Blake2s(value) => {
                value.update(bytes);
            }
            Self::Blake2b(value) => {
                value.update(bytes);
            }
            Self::Blake3(value) => {
                value.update(bytes);
            }
        }
    }

    fn finalize(self) -> Result<DigestValue> {
        macro_rules! fixed {
            ($value:expr) => {{
                let output = Digest::finalize($value);
                DigestValue::from_slice(output.as_slice())
            }};
        }
        match self {
            Self::Md5(value) => DigestValue::from_slice(&value.finalize()),
            Self::Sha224(value) => fixed!(value),
            Self::Sha256(value) => fixed!(value),
            Self::Sha384(value) => fixed!(value),
            Self::Sha512(value) => fixed!(value),
            Self::Sha512_224(value) => fixed!(value),
            Self::Sha512_256(value) => fixed!(value),
            Self::Sha3_224(value) => fixed!(value),
            Self::Sha3_256(value) => fixed!(value),
            Self::Sha3_384(value) => fixed!(value),
            Self::Sha3_512(value) => fixed!(value),
            Self::Blake2s(value) => DigestValue::from_slice(value.finalize().as_bytes()),
            Self::Blake2b(value) => DigestValue::from_slice(value.finalize().as_bytes()),
            Self::Blake3(value) => DigestValue::from_slice(value.finalize().as_bytes()),
        }
    }
}

pub struct HashWorker {
    #[cfg(not(windows))]
    buffer: Vec<u8>,
    #[cfg(windows)]
    inner: windows::WindowsHashWorker,
}

impl HashWorker {
    pub fn with_feedback(parallelism: usize, feedback: Arc<IoFeedback>) -> Result<Self> {
        #[cfg(not(windows))]
        let _ = (parallelism, feedback);
        Ok(Self {
            #[cfg(not(windows))]
            buffer: Vec::new(),
            #[cfg(windows)]
            inner: windows::WindowsHashWorker::new(parallelism, feedback)?,
        })
    }

    pub fn hash_file<F>(
        &mut self,
        path: &Path,
        size: u64,
        algorithms: &[Algorithm],
        on_read: F,
    ) -> Result<Vec<(Algorithm, DigestValue)>>
    where
        F: FnMut(u64),
    {
        #[cfg(windows)]
        {
            self.inner.hash_file(path, size, algorithms, on_read)
        }
        #[cfg(not(windows))]
        {
            hash_file_portable(path, size, algorithms, &mut self.buffer, on_read)
        }
    }

    pub fn set_parallelism(&mut self, parallelism: usize) {
        #[cfg(windows)]
        self.inner.set_parallelism(parallelism);
        #[cfg(not(windows))]
        let _ = parallelism;
    }
}

pub fn parallelism_limits(
    path: &Path,
    files: usize,
    algorithm_count: usize,
    workload: Option<&WorkloadSummary>,
) -> (usize, usize) {
    #[cfg(windows)]
    {
        windows::parallelism_limits(path, files, algorithm_count, workload)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, algorithm_count, workload);
        let workers = files.min(num_cpus::get().max(1)).max(1);
        (workers, workers)
    }
}

pub fn bulk_lane_policy(path: &Path, algorithm_count: usize) -> (std::path::PathBuf, usize) {
    #[cfg(windows)]
    {
        windows::bulk_lane_policy(path, algorithm_count)
    }
    #[cfg(not(windows))]
    {
        let _ = algorithm_count;
        (
            path.ancestors()
                .last()
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf(),
            num_cpus::get().max(1),
        )
    }
}

#[cfg(not(windows))]
fn hash_file_portable<F>(
    path: &Path,
    expected_size: u64,
    algorithms: &[Algorithm],
    buffer: &mut Vec<u8>,
    mut on_read: F,
) -> Result<Vec<(Algorithm, DigestValue)>>
where
    F: FnMut(u64),
{
    if buffer.len() != READ_BUFFER_SIZE {
        buffer.resize(READ_BUFFER_SIZE, 0);
    }
    let mut file =
        open_for_sequential_read(path).with_context(|| format!("无法打开 {}", path.display()))?;
    let mut hasher = MultiHasher::new(algorithms)?;
    loop {
        let count = file
            .read(buffer)
            .with_context(|| format!("无法读取 {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        on_read(count as u64);
    }
    let actual_size = file
        .metadata()
        .with_context(|| format!("无法检查 {}", path.display()))?
        .len();
    if actual_size != expected_size {
        anyhow::bail!("文件在计算期间发生变化: {}", path.display());
    }
    hasher.finalize()
}

#[cfg(not(windows))]
fn open_for_sequential_read(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_empty_input_with_multiple_algorithms() {
        let hasher =
            MultiHasher::new(&[Algorithm::Md5, Algorithm::Sha256, Algorithm::Blake3]).unwrap();
        let values = hasher.finalize().unwrap();
        let get = |algorithm: Algorithm| {
            values
                .iter()
                .find(|(candidate, _)| candidate == &algorithm)
                .unwrap()
                .1
                .to_hex()
        };
        assert_eq!(get(Algorithm::Md5), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            get(Algorithm::Sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            get(Algorithm::Blake3),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn updates_multiple_hashers_in_parallel() {
        let algorithms = [
            Algorithm::Md5,
            Algorithm::Sha256,
            Algorithm::Sha3_256,
            Algorithm::Blake3,
        ];
        let mut hasher = MultiHasher::new(&algorithms).unwrap();
        hasher.update(b"abc");
        let values = hasher.finalize().unwrap();
        let get = |algorithm: Algorithm| {
            values
                .iter()
                .find(|(candidate, _)| candidate == &algorithm)
                .unwrap()
                .1
                .to_hex()
        };
        assert_eq!(get(Algorithm::Md5), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            get(Algorithm::Sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            get(Algorithm::Sha3_256),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            get(Algorithm::Blake3),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn matches_known_answers_for_algorithm_families() {
        let algorithms = [
            Algorithm::Sha224,
            Algorithm::Sha384,
            Algorithm::Sha3_256,
            Algorithm::Blake2s(32),
            Algorithm::Blake2b(64),
        ];
        let values = MultiHasher::new(&algorithms).unwrap().finalize().unwrap();
        let get = |algorithm: Algorithm| {
            values
                .iter()
                .find(|(candidate, _)| candidate == &algorithm)
                .unwrap()
                .1
                .to_hex()
        };
        assert_eq!(
            get(Algorithm::Sha224),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            get(Algorithm::Sha384),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            get(Algorithm::Sha3_256),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            get(Algorithm::Blake2s(32)),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
        assert_eq!(
            get(Algorithm::Blake2b(64)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }
}

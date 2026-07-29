use crate::algorithm::{Algorithm, DigestValue};
use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ManifestEntry {
    pub target: PathBuf,
    pub hashes: Vec<(Algorithm, DigestValue)>,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub source: PathBuf,
    pub entries: Vec<ManifestEntry>,
}

pub fn is_manifest_candidate(path: &Path, direct_input: bool) -> bool {
    if direct_input {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with("sums")
        || name.contains("checksum")
        || name.contains("hashes")
        || matches!(
            extension.as_str(),
            "md5"
                | "sha224"
                | "sha256"
                | "sha384"
                | "sha512"
                | "sha3"
                | "b2"
                | "b3"
                | "blake2"
                | "blake3"
                | "blazehash"
                | "verihash"
        )
}

pub fn detect(path: &Path) -> Result<Option<Manifest>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let mut reader = BufReader::new(file);
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return Ok(None);
    }
    if first
        .trim_start_matches('\u{feff}')
        .starts_with("%%%% HASHDEEP")
    {
        return parse_blazehash(path).map(Some);
    }
    if parse_tagged_prefix(&first).is_some() {
        return parse_tagged(path).map(Some);
    }
    if let Some(algorithm) = algorithm_from_filename(path) {
        return parse_gnu(path, &algorithm).map(Some);
    }
    Ok(None)
}

fn parse_blazehash(path: &Path) -> Result<Manifest> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut first = String::new();
    let mut columns = String::new();
    reader.read_line(&mut first)?;
    reader.read_line(&mut columns)?;
    if !first
        .trim_start_matches('\u{feff}')
        .starts_with("%%%% HASHDEEP")
    {
        bail!("不是 BlazeHash 兼容清单");
    }
    let columns = columns
        .trim_end_matches(['\r', '\n'])
        .strip_prefix("%%%% size,")
        .context("BlazeHash 清单缺少算法列")?;
    let mut names = columns.split(',').collect::<Vec<_>>();
    if names.pop() != Some("filename") {
        bail!("BlazeHash 清单缺少 filename 列");
    }
    let algorithms = names
        .into_iter()
        .map(str::parse)
        .collect::<Result<Vec<Algorithm>>>()?;
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .comment(Some(b'#'))
        .flexible(false)
        .from_reader(reader);
    let mut entries = Vec::new();
    for record in csv.records() {
        let record = record?;
        if record.len() != algorithms.len() + 2 {
            bail!("BlazeHash 记录列数不匹配");
        }
        let target = resolve_target(path, &record[record.len() - 1]);
        let mut hashes = Vec::with_capacity(algorithms.len());
        for (index, algorithm) in algorithms.iter().enumerate() {
            hashes.push((
                algorithm.clone(),
                DigestValue::from_hex(&record[index + 1], algorithm.digest_len())?,
            ));
        }
        entries.push(ManifestEntry { target, hashes });
    }
    Ok(Manifest {
        source: path.to_path_buf(),
        entries,
    })
}

fn parse_tagged(path: &Path) -> Result<Manifest> {
    let reader = BufReader::new(File::open(path)?);
    let mut entries = Vec::<ManifestEntry>::new();
    for line in reader.lines() {
        let line = line?;
        let Some((algorithm, rest)) = parse_tagged_prefix(&line) else {
            if line.trim().is_empty() {
                continue;
            }
            bail!("VeriHash 行缺少算法标签: {line}");
        };
        let rest = rest.trim_start();
        let split = rest
            .find(char::is_whitespace)
            .context("VeriHash 行缺少文件路径")?;
        let digest = &rest[..split];
        let target_text = rest[split..].trim_start();
        let target = resolve_target(path, target_text);
        let digest = DigestValue::from_hex(digest, algorithm.digest_len())?;
        if let Some(entry) = entries.iter_mut().find(|entry| entry.target == target) {
            entry.hashes.push((algorithm, digest));
        } else {
            entries.push(ManifestEntry {
                target,
                hashes: vec![(algorithm, digest)],
            });
        }
    }
    Ok(Manifest {
        source: path.to_path_buf(),
        entries,
    })
}

fn parse_tagged_prefix(line: &str) -> Option<(Algorithm, &str)> {
    let line = line.trim_start_matches('\u{feff}');
    let rest = line.strip_prefix('#')?;
    let end = rest.find('#')?;
    let algorithm = rest[..end].parse().ok()?;
    Some((algorithm, &rest[end + 1..]))
}

fn parse_gnu(path: &Path, algorithm: &Algorithm) -> Result<Manifest> {
    let reader = BufReader::new(File::open(path)?);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let mut line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let escaped = line.starts_with('\\');
        if escaped {
            line.remove(0);
        }
        let Some(separator) = line.find(' ') else {
            return parse_sidecar(path, algorithm, &line);
        };
        let digest = DigestValue::from_hex(&line[..separator], algorithm.digest_len())?;
        let remainder = &line[separator + 1..];
        let mut characters = remainder.chars();
        let mode = characters.next().context("GNU 清单缺少模式标记")?;
        if mode != ' ' && mode != '*' {
            bail!("GNU 清单模式标记无效");
        }
        let filename = characters.as_str();
        let filename = if escaped {
            unescape_gnu_path(filename)?
        } else {
            filename.to_string()
        };
        entries.push(ManifestEntry {
            target: resolve_target(path, &filename),
            hashes: vec![(algorithm.clone(), digest)],
        });
    }
    Ok(Manifest {
        source: path.to_path_buf(),
        entries,
    })
}

fn parse_sidecar(path: &Path, algorithm: &Algorithm, digest: &str) -> Result<Manifest> {
    let digest = DigestValue::from_hex(digest.trim(), algorithm.digest_len())?;
    let target = path.with_extension("");
    Ok(Manifest {
        source: path.to_path_buf(),
        entries: vec![ManifestEntry {
            target,
            hashes: vec![(algorithm.clone(), digest)],
        }],
    })
}

fn unescape_gnu_path(value: &str) -> Result<String> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match chars.next().context("GNU 路径转义不完整")? {
            '\\' => output.push('\\'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            other => bail!("GNU 路径包含未知转义: \\{other}"),
        }
    }
    Ok(output)
}

fn resolve_target(manifest: &Path, target: &str) -> PathBuf {
    let target = PathBuf::from(target.replace('/', std::path::MAIN_SEPARATOR_STR));
    if target.is_absolute() {
        target
    } else {
        manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(target)
    }
}

fn algorithm_from_filename(path: &Path) -> Option<Algorithm> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    for suffix in ["sums", "sum"] {
        if let Some(slug) = name.strip_suffix(suffix)
            && let Ok(algorithm) = slug.parse()
        {
            return Some(algorithm);
        }
    }
    if let Some(extension) = path.extension().and_then(|value| value.to_str())
        && let Ok(algorithm) = extension.parse()
    {
        return Some(algorithm);
    }
    let candidates = [
        "sha512-256",
        "sha512-224",
        "sha3-512",
        "sha3-384",
        "sha3-256",
        "sha3-224",
        "blake2b-512",
        "blake2s-256",
        "blake3",
        "sha512",
        "sha384",
        "sha256",
        "sha224",
        "md5",
    ];
    candidates
        .into_iter()
        .find(|candidate| name.contains(candidate))
        .and_then(|candidate| candidate.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_openwrt_style_sumfile() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sha256sums");
        writeln!(
            File::create(&path).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *empty"
        )
        .unwrap();
        let manifest = detect(&path).unwrap().unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].hashes[0].0, Algorithm::Sha256);
        assert_eq!(manifest.entries[0].target, directory.path().join("empty"));
    }
}

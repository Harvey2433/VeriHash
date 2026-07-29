use anyhow::{Result, bail};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Algorithm {
    Md5,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Blake2s(u8),
    Blake2b(u8),
    Blake3,
}

impl Algorithm {
    pub fn standard_choices() -> Vec<Self> {
        vec![
            Self::Md5,
            Self::Sha224,
            Self::Sha256,
            Self::Sha384,
            Self::Sha512,
            Self::Sha512_224,
            Self::Sha512_256,
            Self::Sha3_224,
            Self::Sha3_256,
            Self::Sha3_384,
            Self::Sha3_512,
            Self::Blake2s(32),
            Self::Blake2b(64),
            Self::Blake3,
        ]
    }

    pub fn digest_len(&self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha512_256 | Self::Sha3_256 | Self::Blake3 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
            Self::Blake2s(bytes) | Self::Blake2b(bytes) => usize::from(*bytes),
        }
    }

    pub fn slug(&self) -> String {
        match self {
            Self::Md5 => "md5".into(),
            Self::Sha224 => "sha224".into(),
            Self::Sha256 => "sha256".into(),
            Self::Sha384 => "sha384".into(),
            Self::Sha512 => "sha512".into(),
            Self::Sha512_224 => "sha512-224".into(),
            Self::Sha512_256 => "sha512-256".into(),
            Self::Sha3_224 => "sha3-224".into(),
            Self::Sha3_256 => "sha3-256".into(),
            Self::Sha3_384 => "sha3-384".into(),
            Self::Sha3_512 => "sha3-512".into(),
            Self::Blake2s(bytes) => format!("blake2s-{}", u16::from(*bytes) * 8),
            Self::Blake2b(bytes) => format!("blake2b-{}", u16::from(*bytes) * 8),
            Self::Blake3 => "blake3".into(),
        }
    }

    pub fn label(&self) -> String {
        self.slug().to_ascii_uppercase()
    }

    pub fn sumfile_name(&self) -> String {
        format!("{}sums", self.slug())
    }

    pub fn parse_with_digest_len(name: &str, digest_hex_len: Option<usize>) -> Result<Self> {
        let normalized = name.trim().to_ascii_lowercase().replace(['_', '/'], "-");
        let compact = normalized.replace('-', "");
        let algorithm = match compact.as_str() {
            "md5" => Self::Md5,
            "sha224" => Self::Sha224,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            "sha512224" => Self::Sha512_224,
            "sha512256" => Self::Sha512_256,
            "sha3224" => Self::Sha3_224,
            "sha3256" => Self::Sha3_256,
            "sha3384" => Self::Sha3_384,
            "sha3512" => Self::Sha3_512,
            "blake3" | "b3" => Self::Blake3,
            "blake2s" => Self::Blake2s(32),
            "blake2b" | "blake2" => Self::Blake2b(64),
            _ if compact.starts_with("blake2s") => {
                Self::Blake2s(parse_blake2_len(&compact[7..], 32, "BLAKE2s")?)
            }
            _ if compact.starts_with("blake2b") => {
                Self::Blake2b(parse_blake2_len(&compact[7..], 64, "BLAKE2b")?)
            }
            _ => bail!("不支持的算法: {name}"),
        };

        if let Some(hex_len) = digest_hex_len
            && algorithm.digest_len() * 2 != hex_len
        {
            bail!(
                "{} 摘要长度应为 {} 个十六进制字符，实际为 {hex_len}",
                algorithm.label(),
                algorithm.digest_len() * 2
            );
        }
        Ok(algorithm)
    }
}

fn parse_blake2_len(bits: &str, max_bytes: u8, family: &str) -> Result<u8> {
    if bits.is_empty() {
        return Ok(max_bytes);
    }
    let bits: u16 = bits.parse()?;
    if bits == 0 || !bits.is_multiple_of(8) || bits > u16::from(max_bytes) * 8 {
        bail!(
            "{family} 输出长度必须为 8 的倍数，且不超过 {} 位",
            max_bytes as u16 * 8
        );
    }
    Ok((bits / 8) as u8)
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse_with_digest_len(s, None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestValue {
    bytes: [u8; 64],
    len: u8,
}

impl DigestValue {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 64 {
            bail!("摘要长度超过 64 字节");
        }
        let mut value = Self {
            bytes: [0; 64],
            len: bytes.len() as u8,
        };
        value.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(value)
    }

    pub fn from_hex(hex: &str, expected_len: usize) -> Result<Self> {
        let hex = hex.trim();
        if hex.len() != expected_len * 2 {
            bail!("摘要长度应为 {} 个十六进制字符", expected_len * 2);
        }
        let mut bytes = [0u8; 64];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self {
            bytes,
            len: expected_len as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(self.as_bytes().len() * 2);
        for byte in self.as_bytes() {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("摘要包含非法十六进制字符"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_algorithm_aliases_and_blake2_lengths() {
        assert_eq!(
            "sha3_256".parse::<Algorithm>().unwrap(),
            Algorithm::Sha3_256
        );
        assert_eq!(
            "SHA-512/224".parse::<Algorithm>().unwrap(),
            Algorithm::Sha512_224
        );
        assert_eq!(
            "blake2b-256".parse::<Algorithm>().unwrap(),
            Algorithm::Blake2b(32)
        );
        assert!("blake2s-264".parse::<Algorithm>().is_err());
    }

    #[test]
    fn digest_hex_is_case_insensitive_and_canonical() {
        let digest = DigestValue::from_hex("A0ff", 2).unwrap();
        assert_eq!(digest.to_hex(), "a0ff");
    }
}

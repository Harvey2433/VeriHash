use crate::algorithm::Algorithm;
use crate::format::path_text;
use crate::spool::ResultSpool;
use anyhow::Result;
use std::io::Write;

pub fn write(spool: &mut ResultSpool, algorithm: &Algorithm, writer: &mut dyn Write) -> Result<()> {
    spool.for_each_algorithm_record(algorithm, |_, path, digest| {
        let path = path_text(path);
        let escaped = path.contains(['\\', '\n', '\r']);
        if escaped {
            write!(writer, "\\")?;
        }
        write!(writer, "{} *", digest.to_hex())?;
        if escaped {
            for character in path.chars() {
                match character {
                    '\\' => write!(writer, "\\\\")?,
                    '\n' => write!(writer, "\\n")?,
                    '\r' => write!(writer, "\\r")?,
                    _ => write!(writer, "{character}")?,
                }
            }
        } else {
            write!(writer, "{path}")?;
        }
        writeln!(writer)?;
        Ok(())
    })
}

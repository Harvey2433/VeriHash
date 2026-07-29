use crate::format::path_text;
use crate::spool::ResultSpool;
use anyhow::Result;
use std::io::Write;

pub fn write(spool: &mut ResultSpool, writer: &mut dyn Write) -> Result<()> {
    let algorithms = spool.algorithms().to_vec();
    for (index, algorithm) in algorithms.iter().enumerate() {
        if index > 0 {
            writeln!(writer)?;
        }
        spool.for_each_algorithm_record(algorithm, |_, path, digest| {
            writeln!(
                writer,
                "#{}#  {}  {}",
                algorithm.label(),
                digest.to_hex(),
                path_text(path)
            )?;
            Ok(())
        })?;
    }
    Ok(())
}

# VeriHash

VeriHash is a cross-platform interactive CLI for calculating and verifying file
checksums on Windows, Linux, and macOS.

## Features

- Interactive calculate and verify workflows powered by `dialoguer` and `indicatif`.
- One-pass multi-hashing: every selected digest consumes the same file read buffer.
- MD5, the fixed-output SHA-2 and SHA-3 families, variable-length BLAKE2s/BLAKE2b,
  and BLAKE3.
- Files, recursive directories, relative or absolute paths, and glob patterns.
- Single-scan disk-backed task plans, bounded worker queues, small-file batches,
  reusable read buffers, atomic progress counters, and a single result writer.
- Windows Direct I/O through per-thread IOCP, aligned buffers, adaptive ordered
  read-ahead, per-volume stream limits, and cached storage capability detection.
- GNU sumfiles such as `sha256sums`, grouped VeriHash output, and BlazeHash-compatible
  manifests.
- Verification starts from a source directory, automatically discovers GNU/sidecar,
  VeriHash, and BlazeHash manifests, and requests an external manifest only when none
  are found. Unreferenced source files are ignored.
- Verification results can be exported as a dedicated report containing every
  verified, mismatched, errored, and missing target. This is separate from the
  optional performance diagnostics report.
- GNU-style `checksums.txt` files can be inferred from their digest width; malformed
  or false-positive candidates do not abort the directory scan.

## Interactive defaults

Running `verihash` with no arguments starts the interactive workflow. Pressing Enter
through the calculate workflow selects MD5 and SHA-256, scans the current directory,
confirms calculation, and selects BlazeHash-compatible output.

For ten files or fewer, results are printed by algorithm before the save prompt. For
larger jobs, VeriHash proceeds directly to the multi-select output format prompt.

## Output formats

- **BlazeHash Compatible**: `%%%% HASHDEEP-1.0` header followed by size, digest
  columns, and filename.
- **VeriHash Grouped**: tagged records grouped by algorithm with a blank line between
  groups.
- **GNU sumfiles**: one binary-mode sumfile per algorithm, such as `md5sums` and
  `sha256sums`.

## Architecture

- `algorithm`: algorithm identities, aliases, lengths, and digest values.
- `hashing`: streaming one-pass multi-hasher.
- `scanner`: recursive/glob discovery and disk-backed, per-volume task plans.
- `scheduler`: discovery-order per-volume lanes, adjacent small-file batching, worker
  lifecycle, and result collection.
- `progress`: atomic counters and the terminal renderer.
- `spool`: bounded-memory temporary metadata and per-algorithm digest streams.
- `format`: GNU, VeriHash, BlazeHash writing and manifest detection.
- `verify`: manifest merging, conflict detection, and parallel verification.
- `app`: interactive orchestration only.

## License

ISC License. Copyright (c) 2026 Maple Bamboo Team.

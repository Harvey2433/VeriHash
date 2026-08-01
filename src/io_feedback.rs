#![cfg_attr(not(windows), allow(dead_code))]

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const LATENCY_OCTAVES: usize = 32;
const SUB_BUCKETS: usize = 4;
const LATENCY_BUCKETS: usize = LATENCY_OCTAVES * SUB_BUCKETS;
const SAMPLE_INTERVAL: u64 = 16;

thread_local! {
    static SAMPLE_SEQUENCE: Cell<u64> = const { Cell::new(0) };
}

pub struct IoFeedback {
    bytes: AtomicU64,
    latency_ns: AtomicU64,
    latency: [AtomicU64; LATENCY_BUCKETS],
}

impl Default for IoFeedback {
    fn default() -> Self {
        Self {
            bytes: AtomicU64::new(0),
            latency_ns: AtomicU64::new(0),
            latency: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

#[derive(Clone)]
pub struct IoSnapshot {
    bytes: u64,
    latency_ns: u64,
    latency: [u64; LATENCY_BUCKETS],
}

impl Default for IoSnapshot {
    fn default() -> Self {
        Self {
            bytes: 0,
            latency_ns: 0,
            latency: [0; LATENCY_BUCKETS],
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IoWindow {
    pub samples: u64,
    pub bytes: u64,
    pub average_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

pub fn sample_due() -> bool {
    SAMPLE_SEQUENCE.with(|sequence| {
        let next = sequence.get().wrapping_add(1);
        sequence.set(next);
        next == 1 || next.is_multiple_of(SAMPLE_INTERVAL)
    })
}

impl IoFeedback {
    pub fn record(&self, bytes: usize, elapsed: Duration) {
        let nanos = elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
        let micros = elapsed.as_micros().max(1).min(u128::from(u64::MAX)) as u64;
        let bucket = latency_bucket(micros);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.latency_ns.fetch_add(nanos, Ordering::Relaxed);
        self.latency[bucket.min(LATENCY_BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> IoSnapshot {
        IoSnapshot {
            bytes: self.bytes.load(Ordering::Relaxed),
            latency_ns: self.latency_ns.load(Ordering::Relaxed),
            latency: std::array::from_fn(|index| self.latency[index].load(Ordering::Relaxed)),
        }
    }

    pub fn window_since(&self, previous: &mut IoSnapshot) -> IoWindow {
        let current = self.snapshot();
        let latency = std::array::from_fn(|index| {
            current.latency[index].saturating_sub(previous.latency[index])
        });
        let samples = latency.iter().sum::<u64>();
        let window = IoWindow {
            samples,
            bytes: current.bytes.saturating_sub(previous.bytes),
            average_ns: current
                .latency_ns
                .saturating_sub(previous.latency_ns)
                .checked_div(samples)
                .unwrap_or(0),
            p50_ns: percentile_ns(&latency, samples, 50),
            p95_ns: percentile_ns(&latency, samples, 95),
            p99_ns: percentile_ns(&latency, samples, 99),
        };
        *previous = current;
        window
    }
}

fn percentile_ns(latency: &[u64; LATENCY_BUCKETS], samples: u64, percentile: u64) -> u64 {
    if samples == 0 {
        return 0;
    }
    let target = samples.saturating_mul(percentile).div_ceil(100);
    let mut cumulative = 0u64;
    for (index, count) in latency.iter().enumerate() {
        cumulative = cumulative.saturating_add(*count);
        if cumulative >= target {
            return bucket_micros(index).saturating_mul(1_000);
        }
    }
    bucket_micros(LATENCY_BUCKETS - 1).saturating_mul(1_000)
}

fn latency_bucket(micros: u64) -> usize {
    let octave = (u64::BITS - micros.leading_zeros() - 1) as usize;
    let base = 1u64 << octave;
    let sub_bucket = micros
        .saturating_sub(base)
        .saturating_mul(SUB_BUCKETS as u64)
        .checked_div(base)
        .unwrap_or(0)
        .min(SUB_BUCKETS as u64 - 1) as usize;
    octave
        .saturating_mul(SUB_BUCKETS)
        .saturating_add(sub_bucket)
        .min(LATENCY_BUCKETS - 1)
}

fn bucket_micros(index: usize) -> u64 {
    let octave = index / SUB_BUCKETS;
    let sub_bucket = index % SUB_BUCKETS;
    let base = 1u64 << octave;
    base.saturating_add(
        base.saturating_mul(sub_bucket as u64)
            .checked_div(SUB_BUCKETS as u64)
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_latency_for_only_the_latest_window() {
        let feedback = IoFeedback::default();
        let mut previous = feedback.snapshot();
        for millis in [1, 2, 4, 8, 16] {
            feedback.record(4096, Duration::from_millis(millis));
        }
        let first = feedback.window_since(&mut previous);
        assert_eq!(first.samples, 5);
        assert_eq!(first.bytes, 5 * 4096);
        assert!((3_000_000..=4_000_000).contains(&first.p50_ns));
        assert!((14_000_000..=16_000_000).contains(&first.p95_ns));

        feedback.record(8192, Duration::from_millis(2));
        let second = feedback.window_since(&mut previous);
        assert_eq!(second.samples, 1);
        assert_eq!(second.bytes, 8192);
        assert!((1_750_000..=2_000_000).contains(&second.p99_ns));
    }
}

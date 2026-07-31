use crate::performance;
use crate::progress::ProgressCounters;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct AdaptiveGate {
    active: AtomicUsize,
    target: AtomicUsize,
    maximum: usize,
}

pub struct FixedGate {
    active: AtomicUsize,
    limit: usize,
}

impl FixedGate {
    pub fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit: limit.max(1),
        }
    }

    pub fn acquire(&self) -> FixedPermit<'_> {
        let mut spins = 0usize;
        loop {
            let active = self.active.load(Ordering::Relaxed);
            if active < self.limit
                && self
                    .active
                    .compare_exchange_weak(active, active + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return FixedPermit { gate: self };
            }
            if spins < 32 {
                std::hint::spin_loop();
                spins += 1;
            } else {
                thread::sleep(Duration::from_micros(100));
            }
        }
    }
}

pub struct FixedPermit<'a> {
    gate: &'a FixedGate,
}

impl Drop for FixedPermit<'_> {
    fn drop(&mut self) {
        self.gate.active.fetch_sub(1, Ordering::Release);
    }
}

impl AdaptiveGate {
    pub fn new(initial: usize, maximum: usize) -> Self {
        let maximum = maximum.max(1);
        let initial = initial.clamp(1, maximum);
        performance::record_parallelism_config(initial, maximum);
        Self {
            active: AtomicUsize::new(0),
            target: AtomicUsize::new(initial),
            maximum,
        }
    }

    pub fn acquire(&self) -> AdaptivePermit<'_> {
        let mut spins = 0usize;
        loop {
            let active = self.active.load(Ordering::Relaxed);
            let target = self.target.load(Ordering::Relaxed);
            if active < target
                && self
                    .active
                    .compare_exchange_weak(active, active + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return AdaptivePermit { gate: self };
            }
            if spins < 32 {
                std::hint::spin_loop();
                spins += 1;
            } else {
                thread::sleep(Duration::from_micros(100));
            }
        }
    }

    pub fn target(&self) -> usize {
        self.target.load(Ordering::Relaxed)
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    fn increase(&self) {
        let current = self.target();
        if current < self.maximum {
            let target = current + 1;
            self.target.store(target, Ordering::Relaxed);
            performance::record_parallelism_change(true, target);
        }
    }

    fn decrease(&self) {
        let current = self.target();
        if current > 1 {
            let target = current - 1;
            self.target.store(target, Ordering::Relaxed);
            performance::record_parallelism_change(false, target);
        }
    }
}

pub struct AdaptivePermit<'a> {
    gate: &'a AdaptiveGate,
}

impl Drop for AdaptivePermit<'_> {
    fn drop(&mut self) {
        self.gate.active.fetch_sub(1, Ordering::Release);
    }
}

pub struct AdaptiveTuner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl AdaptiveTuner {
    pub fn start(gate: Arc<AdaptiveGate>, counters: Arc<ProgressCounters>) -> Self {
        if gate.maximum <= 1 || gate.target() == gate.maximum {
            return Self {
                stop: Arc::new(AtomicBool::new(true)),
                handle: None,
            };
        }
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut previous_bytes = counters.bytes.load(Ordering::Relaxed);
            let mut previous_delta = 0u64;
            let mut regressions = 0u8;
            while !thread_stop.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(400));
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                let bytes = counters.bytes.load(Ordering::Relaxed);
                let delta = bytes.saturating_sub(previous_bytes);
                previous_bytes = bytes;
                performance::record_parallelism_sample(gate.target(), gate.active(), delta);
                if delta == 0 {
                    continue;
                }

                if previous_delta > 0
                    && delta.saturating_mul(100) < previous_delta.saturating_mul(75)
                {
                    regressions = regressions.saturating_add(1);
                    if regressions >= 2 {
                        gate.decrease();
                        regressions = 0;
                    }
                } else {
                    regressions = 0;
                    if gate.active() >= gate.target()
                        && (previous_delta == 0
                            || delta.saturating_mul(100) >= previous_delta.saturating_mul(95))
                    {
                        gate.increase();
                    }
                }
                previous_delta = delta;
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permit_tracks_active_work() {
        let gate = AdaptiveGate::new(1, 4);
        let permit = gate.acquire();
        assert_eq!(gate.active(), 1);
        drop(permit);
        assert_eq!(gate.active(), 0);
    }

    #[test]
    fn fixed_gate_tracks_active_work() {
        let gate = FixedGate::new(2);
        let first = gate.acquire();
        let second = gate.acquire();
        assert_eq!(gate.active.load(Ordering::Relaxed), 2);
        drop((first, second));
        assert_eq!(gate.active.load(Ordering::Relaxed), 0);
    }
}

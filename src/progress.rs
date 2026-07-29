use console::style;
use crossbeam_channel::{Receiver, Sender, bounded};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SPEED_WINDOW: Duration = Duration::from_millis(750);
const SPEED_SAMPLE_INTERVAL: Duration = Duration::from_millis(80);

#[derive(Debug)]
pub enum ProgressEvent {
    Finished { path: String, success: bool },
    Stop,
}

#[derive(Default)]
pub struct ProgressCounters {
    pub bytes: AtomicU64,
    pub files: AtomicU64,
    pub failed: AtomicU64,
    pub active: AtomicU64,
}

pub struct ProgressRenderer {
    sender: Sender<ProgressEvent>,
    handle: Option<JoinHandle<()>>,
}

impl ProgressRenderer {
    pub fn start(total_bytes: u64, counters: Arc<ProgressCounters>) -> Self {
        let (sender, receiver) = bounded(8192);
        let handle = thread::spawn(move || render_loop(total_bytes, counters, receiver));
        Self {
            sender,
            handle: Some(handle),
        }
    }

    pub fn sender(&self) -> Sender<ProgressEvent> {
        self.sender.clone()
    }

    pub fn finish(mut self) {
        let _ = self.sender.send(ProgressEvent::Stop);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn render_loop(
    total_bytes: u64,
    counters: Arc<ProgressCounters>,
    receiver: Receiver<ProgressEvent>,
) {
    let total = total_bytes.max(1);
    let overall = ProgressBar::new(total);
    let window_rate = Arc::new(AtomicU64::new(0));
    overall.set_style(progress_style(Arc::clone(&window_rate)));
    overall.set_prefix(
        style(format!("{:>12}", "Processing"))
            .cyan()
            .bold()
            .to_string(),
    );
    overall.set_message(parallel_message(0));
    overall.enable_steady_tick(Duration::from_millis(80));
    let mut speed = ShortWindowRate::new(SPEED_WINDOW, SPEED_SAMPLE_INTERVAL);

    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(ProgressEvent::Finished { path, success }) => {
                overall.println(completion_line(path, success));
                overall.tick();
            }
            Ok(ProgressEvent::Stop) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
        let bytes = counters.bytes.load(Ordering::Relaxed).min(total);
        window_rate.store(speed.observe(Instant::now(), bytes), Ordering::Relaxed);
        overall.set_position(bytes);
        overall.set_message(parallel_message(counters.active.load(Ordering::Relaxed)));
    }

    overall.disable_steady_tick();
    overall.set_prefix(
        style(format!("{:>12}", "Finished"))
            .green()
            .bold()
            .to_string(),
    );
    overall.set_position(total);
    overall.finish_with_message(parallel_message(0));
    if !overall.is_hidden() {
        let stderr = io::stderr();
        let mut stderr = stderr.lock();
        let _ = writeln!(stderr);
        let _ = stderr.flush();
    }
}

fn completion_line(path: String, success: bool) -> String {
    let label = if success {
        style(format!("{:>12}", "Complete")).green().bold()
    } else {
        style(format!("{:>12}", "Failed")).red().bold()
    };
    format!("{label} {}", style(path).white())
}

fn progress_style(window_rate: Arc<AtomicU64>) -> ProgressStyle {
    let open = style("[").white().to_string();
    let close = style("]").white().to_string();
    let eta = style("ETA:").cyan().bold().to_string();
    ProgressStyle::with_template(&format!(
        "{{prefix}} {open}{{bar:40.white/white}}{close} {{percent:.white}}%  {{window_rate:.white}}  {eta}{{eta_hours:.white}}  {{msg}}"
    ))
    .unwrap_or_else(|_| ProgressStyle::default_bar())
    .with_key(
        "window_rate",
        move |_state: &ProgressState, writer: &mut dyn std::fmt::Write| {
            let _ = write!(
                writer,
                "{}",
                format_rate(window_rate.load(Ordering::Relaxed))
            );
        },
    )
    .with_key(
        "eta_hours",
        |state: &ProgressState, writer: &mut dyn std::fmt::Write| {
            let _ = write!(writer, "{}", format_eta(state.eta()));
        },
    )
    .progress_chars("=> ")
}

struct ShortWindowRate {
    window: Duration,
    sample_interval: Duration,
    samples: VecDeque<(Instant, u64)>,
    current: u64,
}

impl ShortWindowRate {
    fn new(window: Duration, sample_interval: Duration) -> Self {
        Self {
            window,
            sample_interval,
            samples: VecDeque::new(),
            current: 0,
        }
    }

    fn observe(&mut self, now: Instant, bytes: u64) -> u64 {
        if self
            .samples
            .back()
            .is_some_and(|(sampled, _)| now.duration_since(*sampled) < self.sample_interval)
        {
            return self.current;
        }
        self.samples.push_back((now, bytes));
        while self.samples.len() > 2
            && self
                .samples
                .get(1)
                .is_some_and(|(sampled, _)| now.duration_since(*sampled) >= self.window)
        {
            self.samples.pop_front();
        }
        let Some((started, started_bytes)) = self.samples.front().copied() else {
            return self.current;
        };
        let elapsed = now.duration_since(started).as_secs_f64();
        if elapsed > 0.0 {
            self.current =
                (bytes.saturating_sub(started_bytes) as f64 / elapsed).min(u64::MAX as f64) as u64;
        }
        self.current
    }
}

fn format_rate(bytes_per_second: u64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
    let mut value = bytes_per_second as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes_per_second} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn parallel_message(count: u64) -> String {
    format!(
        "{} {}",
        style(count).white(),
        style("parallel").cyan().bold()
    )
}

fn format_eta(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eta_keeps_unbounded_total_hours() {
        assert_eq!(
            format_eta(Duration::from_secs(100 * 3600 + 62)),
            "100:01:02"
        );
        assert_eq!(format_eta(Duration::from_secs(1000 * 3600)), "1000:00:00");
    }

    #[test]
    fn short_window_rate_reacts_without_using_lifetime_average() {
        let start = Instant::now();
        let mut rate = ShortWindowRate::new(Duration::from_millis(750), Duration::from_millis(80));
        assert_eq!(rate.observe(start, 0), 0);
        assert_eq!(
            rate.observe(start + Duration::from_millis(100), 100 * 1024 * 1024),
            1000 * 1024 * 1024
        );
        assert_eq!(
            format_rate(rate.observe(start + Duration::from_millis(900), 900 * 1024 * 1024)),
            "1000.00 MiB/s"
        );
    }
}

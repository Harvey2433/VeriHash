mod algorithm;
mod app;
mod concurrency;
mod format;
mod hashing;
mod interaction;
mod performance;
mod progress;
mod scanner;
mod scheduler;
mod spool;
mod verify;

use anyhow::Result;

fn main() -> Result<()> {
    app::run()
}

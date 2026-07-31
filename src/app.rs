use crate::algorithm::Algorithm;
use crate::format::{OutputFormat, output_paths, write_outputs};
use crate::interaction::CliTheme;
use crate::performance;
use crate::scanner::InputSpec;
use crate::scheduler;
use crate::spool::ComputedFile;
use crate::verify;
use anyhow::{Result, bail};
use console::{Style, Term, style};
use dialoguer::{Input, MultiSelect, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Mode {
    Compute,
    Verify,
}

const ASCII_ART: &str = r#"
 __  __                     __  __                    __         
/\ \ /\ \                 __/\ \/\ \                  /\ \        
\ \ \ \ \     __   _ __ /\_\ \ \_\ \     __      ____\ \ \___    
 \ \ \ \ \  /'__`\/\`'__\/\ \ \  _  \  /'__`\   /',__\\ \  _ `\  
  \ \ \_/ \/\  __/\ \ \/ \ \ \ \ \ \ \/\ \L\.\_/\__, `\\ \ \ \ \ 
   \ `\___/\ \____\\ \_\  \ \_\ \_\ \_\ \__/.\_\/\____/ \ \_\ \_\
    `\/__/  \/____/ \/_/   \/_/\/_/\/_/\/__/\/_/\/___/   \/_/\/_/
                                                                 
                                                                 
"#;
const SPINNER_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";

pub fn run() -> Result<()> {
    Term::stderr().set_title("VeriHash");
    display_banner();
    let theme = CliTheme;
    let mode = select_mode(&theme)?;
    performance::start(match mode {
        Mode::Compute => "compute",
        Mode::Verify => "verify",
    });
    let operation = match mode {
        Mode::Compute => run_compute(&theme),
        Mode::Verify => run_verify(&theme),
    };
    performance::finish(&operation);
    let report = maybe_write_performance_report(&theme);
    match (operation, report) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn maybe_write_performance_report(theme: &CliTheme) -> Result<()> {
    eprintln!();
    if !ask_confirm(theme, "是否输出性能报告?", false)? {
        return Ok(());
    }
    let path = performance::write_report(PathBuf::from(".").as_path())?;
    print_status(
        "Report",
        path.display().to_string(),
        Style::new().green().bold(),
    );
    Ok(())
}

fn select_mode(theme: &CliTheme) -> Result<Mode> {
    let modes = [Mode::Compute, Mode::Verify];
    let labels = ["计算哈希", "校验文件"];
    let selected = Select::with_theme(theme)
        .with_prompt("选择模式")
        .items(&labels)
        .default(0)
        .interact()?;
    Ok(modes[selected])
}

fn display_banner() {
    eprint!("{}", style(ASCII_ART).blue().bold());
    eprintln!("{}", style("Welcome to VeriHash").dim());
    eprintln!();
}

fn run_compute(theme: &CliTheme) -> Result<()> {
    let algorithms = select_algorithms(theme)?;
    performance::set_algorithms(
        algorithms
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    );
    let input = prompt_input(theme)?;
    let spinner = scanning_spinner(&input);
    let scan_started = Instant::now();
    let plan = input.plan();
    spinner.finish_and_clear();
    let mut plan = plan?;
    let summary = plan.summary().clone();
    performance::record_scan(scan_started.elapsed(), &summary);
    if summary.files == 0 {
        bail!("没有匹配到可处理文件");
    }
    print_ok(format!(
        "匹配到 {} 个文件 (总计 {}), 算法: {}{}",
        summary.files,
        human_bytes(summary.bytes),
        algorithms
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        if summary.skipped > 0 {
            format!(", 跳过 {} 项", summary.skipped)
        } else {
            String::new()
        }
    ));
    let confirmed = ask_confirm(theme, "确认开始计算?", true)?;
    if !confirmed {
        return Ok(());
    }
    eprintln!();

    performance::begin_processing();
    let processing_started = Instant::now();
    let outcome = scheduler::compute(&mut plan, input.probe_path(), &algorithms);
    performance::record_processing(processing_started.elapsed());
    let mut outcome = outcome?;
    let failed_files = outcome.failures.len() as u64;
    performance::record_file_totals(
        summary.files,
        summary.files.saturating_sub(failed_files),
        failed_files,
    );
    if !outcome.failures.is_empty() {
        eprintln!("\n{} 个文件处理失败:", outcome.failures.len());
        for failure in outcome.failures.iter().take(20) {
            eprintln!("  {failure}");
        }
        if outcome.failures.len() > 20 {
            eprintln!("  ... 其余 {} 项已省略", outcome.failures.len() - 20);
        }
    }

    if summary.files <= 10 {
        print_grouped_results(&algorithms, &mut outcome.display_results);
        if !ask_confirm(theme, "是否将结果写入文件?", true)? {
            return finish_compute(outcome.failures);
        }
    }

    let formats = select_output_formats(theme)?;
    if formats.is_empty() {
        return finish_compute(outcome.failures);
    }
    let destination: String = Input::with_theme(theme)
        .with_prompt("输出目录")
        .default(".".to_string())
        .interact_text()?;
    let destination = PathBuf::from(sanitize_path_input(&destination));
    let existing = output_paths(outcome.spool.algorithms(), &formats, &destination)
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    if !existing.is_empty()
        && !ask_confirm(
            theme,
            &format!("{} 个输出文件已存在, 是否覆盖?", existing.len()),
            false,
        )?
    {
        return finish_compute(outcome.failures);
    }

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_chars(SPINNER_CHARS),
    );
    spinner.set_message("正在写入结果");
    spinner.enable_steady_tick(Duration::from_millis(100));
    let output_started = Instant::now();
    let written = write_outputs(&mut outcome.spool, &formats, &destination)?;
    performance::record_output(output_started.elapsed(), &written);
    spinner.finish_and_clear();
    for path in written {
        print_status(
            "Written",
            path.display().to_string(),
            Style::new().green().bold(),
        );
    }
    finish_compute(outcome.failures)
}

fn finish_compute(failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("部分文件计算失败")
    }
}

fn run_verify(theme: &CliTheme) -> Result<()> {
    let input = prompt_verify_source(theme)?;
    let spinner = scanning_spinner(&input);
    let scan_started = Instant::now();
    let scan = verify::scan(&input);
    spinner.finish_and_clear();
    let mut scan = scan?;
    performance::record_scan(scan_started.elapsed(), scan.summary());

    if !scan.rejected_candidates().is_empty() {
        print_status(
            "Skipped",
            format!(
                "{} unusable checksum candidates",
                scan.rejected_candidates().len()
            ),
            Style::new().yellow().bold(),
        );
        for rejected in scan.rejected_candidates().iter().take(10) {
            eprintln!("  {rejected}");
        }
    }

    if scan.manifest_count() == 0 {
        print_status(
            "Detected",
            "no checksum files in source directory".to_string(),
            Style::new().yellow().bold(),
        );
        let manifest: String = Input::with_theme(theme)
            .with_prompt("输入校验文件路径")
            .validate_with(|value: &String| -> std::result::Result<(), String> {
                if Path::new(&sanitize_path_input(value)).is_file() {
                    Ok(())
                } else {
                    Err("路径不存在或不是普通文件".to_string())
                }
            })
            .interact_text()?;
        let manifest = sanitize_path_input(&manifest);
        scan.add_manifest_file(Path::new(&manifest))?;
    }

    let discovery = scan.finish()?;

    print_status(
        "Detected",
        format!(
            "{} checksum files, {} targets, {} unrelated files ignored",
            discovery.manifests,
            discovery.jobs.len(),
            discovery.unmatched_total
        ),
        Style::new().green().bold(),
    );
    if !discovery.conflicts.is_empty() {
        for conflict in &discovery.conflicts {
            eprintln!("冲突: {conflict}");
        }
        bail!("清单存在冲突, 未开始校验");
    }
    if !discovery.missing.is_empty() {
        eprintln!("清单引用了 {} 个不存在的文件:", discovery.missing.len());
        for path in discovery.missing.iter().take(20) {
            eprintln!("  MISSING  {}", path.display());
        }
    }

    if discovery.jobs.is_empty() {
        bail!("没有可校验的文件");
    }
    performance::set_algorithms(
        discovery
            .algorithms()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    );
    print_status(
        "Verifying",
        format!(
            "{} files ({})",
            discovery.jobs.len(),
            human_bytes(discovery.total_bytes())
        ),
        Style::new().green().bold(),
    );
    let confirmed = ask_confirm(theme, "确认开始校验?", true)?;
    if !confirmed {
        return Ok(());
    }
    eprintln!();
    performance::begin_processing();
    let processing_started = Instant::now();
    let outcome = verify::verify(&discovery);
    performance::record_processing(processing_started.elapsed());
    let mut outcome = outcome?;
    performance::record_file_totals(
        discovery.jobs.len() as u64,
        outcome.passed,
        outcome.mismatched + outcome.error_count,
    );
    let mismatched = outcome.mismatched;
    let errors = outcome.error_count;
    let missing = discovery.missing.len() as u64;
    let failed = mismatched + errors + missing;
    for failure in &outcome.failed {
        eprintln!("FAILED  {failure}");
    }
    if mismatched > outcome.failed.len() as u64 {
        eprintln!(
            "  ... {} additional mismatches are available in the verification report",
            mismatched - outcome.failed.len() as u64
        );
    }
    for error in &outcome.errors {
        eprintln!("ERROR   {error}");
    }
    if errors > outcome.errors.len() as u64 {
        eprintln!(
            "  ... {} additional errors are available in the verification report",
            errors - outcome.errors.len() as u64
        );
    }
    print_verification_summary(outcome.passed, mismatched, errors, missing);
    if ask_confirm(theme, "是否导出校验报告?", true)? {
        let report_path: String = Input::with_theme(theme)
            .with_prompt("校验报告路径")
            .default("verification-report.txt".to_string())
            .interact_text()?;
        let report_path = PathBuf::from(sanitize_path_input(&report_path));
        let overwrite =
            !report_path.exists() || ask_confirm(theme, "校验报告已存在, 是否覆盖?", false)?;
        if overwrite {
            let output_started = Instant::now();
            verify::write_report(&mut outcome, &discovery, &report_path)?;
            performance::record_output(
                output_started.elapsed(),
                std::slice::from_ref(&report_path),
            );
            print_status(
                "Written",
                report_path.display().to_string(),
                Style::new().green().bold(),
            );
        }
    }
    if failed > 0 {
        bail!("校验完成, {failed} 个文件失败或缺失")
    }
    Ok(())
}

fn select_algorithms(theme: &CliTheme) -> Result<Vec<Algorithm>> {
    let standard = Algorithm::standard_choices();
    let mut labels = standard.iter().map(ToString::to_string).collect::<Vec<_>>();
    labels.push("BLAKE2s 自定义长度".into());
    labels.push("BLAKE2b 自定义长度".into());
    let mut defaults = vec![false; labels.len()];
    for (index, algorithm) in standard.iter().enumerate() {
        defaults[index] = matches!(algorithm, Algorithm::Md5 | Algorithm::Sha256);
    }
    let selected = MultiSelect::with_theme(theme)
        .with_prompt("选择算法")
        .items(&labels)
        .defaults(&defaults)
        .interact()?;
    let mut algorithms = Vec::new();
    for index in selected {
        if index < standard.len() {
            algorithms.push(standard[index].clone());
        } else if index == standard.len() {
            algorithms.push(Algorithm::Blake2s(prompt_blake2_bits(
                theme, "BLAKE2s", 256,
            )?));
        } else {
            algorithms.push(Algorithm::Blake2b(prompt_blake2_bits(
                theme, "BLAKE2b", 512,
            )?));
        }
    }
    algorithms.sort();
    algorithms.dedup();
    if algorithms.is_empty() {
        bail!("至少选择一种算法");
    }
    Ok(algorithms)
}

fn prompt_blake2_bits(theme: &CliTheme, family: &str, default: u16) -> Result<u8> {
    let max = if family == "BLAKE2s" { 256 } else { 512 };
    let bits: u16 = Input::with_theme(theme)
        .with_prompt(format!("{family} 输出位数"))
        .default(default)
        .validate_with(move |value: &u16| -> std::result::Result<(), String> {
            if *value > 0 && *value <= max && value.is_multiple_of(8) {
                Ok(())
            } else {
                Err(format!("必须是 8 到 {max} 之间且为 8 的倍数"))
            }
        })
        .interact_text()?;
    Ok((bits / 8) as u8)
}

fn prompt_input(theme: &CliTheme) -> Result<InputSpec> {
    let value: String = Input::with_theme(theme)
        .with_prompt("输入文件, 目录或通配符路径")
        .default(".".to_string())
        .interact_text()?;
    let value = sanitize_path_input(&value);
    let input = InputSpec::parse(&value)?;
    performance::set_input(input.describe());
    Ok(input)
}

fn prompt_verify_source(theme: &CliTheme) -> Result<InputSpec> {
    let value: String = Input::with_theme(theme)
        .with_prompt("输入校验源目录")
        .default(".".to_string())
        .validate_with(|value: &String| -> std::result::Result<(), String> {
            if Path::new(&sanitize_path_input(value)).is_dir() {
                Ok(())
            } else {
                Err("路径不存在或不是目录".to_string())
            }
        })
        .interact_text()?;
    let value = sanitize_path_input(&value);
    let input = InputSpec::parse(&value)?;
    performance::set_input(input.describe());
    Ok(input)
}

fn scanning_spinner(input: &InputSpec) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_chars(SPINNER_CHARS),
    );
    spinner.set_message(format!("正在扫描 {}", input.describe()));
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner
}

fn select_output_formats(theme: &CliTheme) -> Result<Vec<OutputFormat>> {
    let labels = OutputFormat::ALL
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let selected = MultiSelect::with_theme(theme)
        .with_prompt("选择写入格式")
        .items(&labels)
        .defaults(&[true, false, false])
        .interact()?;
    Ok(selected
        .into_iter()
        .map(|index| OutputFormat::ALL[index])
        .collect())
}

fn ask_confirm(theme: &CliTheme, prompt: &str, default: bool) -> Result<bool> {
    let options = ["Yes", "No"];
    let selected = Select::with_theme(theme)
        .with_prompt(prompt)
        .items(&options)
        .default(usize::from(!default))
        .interact()?;
    Ok(selected == 0)
}

fn print_grouped_results(algorithms: &[Algorithm], results: &mut [ComputedFile]) {
    results.sort_by(|left, right| left.relative.cmp(&right.relative));
    for (index, algorithm) in algorithms.iter().enumerate() {
        if index > 0 {
            eprintln!();
        }
        eprintln!("{}", style(algorithm.label()).white().bold());
        for result in results.iter() {
            if let Some((_, digest)) = result
                .hashes
                .iter()
                .find(|(candidate, _)| candidate == algorithm)
            {
                eprintln!("{}  {}", digest.to_hex(), result.relative.display());
            }
        }
    }
}

fn print_status(label: &str, message: String, label_style: Style) {
    eprintln!(
        "{} {}",
        label_style.apply_to(format!("{label:>12}")),
        style(message).white()
    );
}

fn print_verification_summary(passed: u64, mismatched: u64, errors: u64, missing: u64) {
    let failed = mismatched + errors + missing;
    let label = style(format!("{:>12}", "Verification"));
    let label = if failed == 0 {
        label.green().bold()
    } else if passed == 0 {
        label.red().bold()
    } else {
        label.yellow().bold()
    };
    let passed = style(format!("{passed} passed")).green().bold();
    let mismatched = if mismatched == 0 {
        style("0 mismatched".to_string()).white().dim()
    } else {
        style(format!("{mismatched} mismatched")).red().bold()
    };
    let errors = if errors == 0 {
        style("0 errors".to_string()).white().dim()
    } else {
        style(format!("{errors} errors")).red().bold()
    };
    let missing = if missing == 0 {
        style("0 missing".to_string()).white().dim()
    } else {
        style(format!("{missing} missing")).red().bold()
    };
    eprintln!("{label} {passed}, {mismatched}, {errors}, {missing}");
}

fn print_ok(message: String) {
    eprintln!(
        "  {} {}",
        style("OK").for_stderr().green().bold(),
        style(message).for_stderr().white()
    );
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn sanitize_path_input(value: &str) -> String {
    let cleaned = value
        .chars()
        .filter(|character| {
            !matches!(
                character,
                '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{feff}'
            )
        })
        .collect::<String>();
    let cleaned = cleaned.trim();
    let unquoted = [
        ('"', '"'),
        ('\'', '\''),
        ('\u{201c}', '\u{201d}'),
        ('\u{2018}', '\u{2019}'),
    ]
    .into_iter()
    .find_map(|(open, close)| cleaned.strip_prefix(open)?.strip_suffix(close))
    .unwrap_or(cleaned);
    unquoted.trim().to_string()
}

#[cfg(test)]
mod app_tests {
    use super::sanitize_path_input;

    #[test]
    fn sanitizes_windows_clipboard_paths() {
        assert_eq!(
            sanitize_path_input("\u{202a}\"D:\\桌面\\checksums.verihash\"\u{202c}"),
            "D:\\桌面\\checksums.verihash"
        );
    }
}

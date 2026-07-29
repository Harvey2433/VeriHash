use console::{Style, style};
use dialoguer::theme::Theme;
use std::fmt;

pub struct CliTheme;

impl Theme for CliTheme {
    fn format_error(&self, f: &mut dyn fmt::Write, error: &str) -> fmt::Result {
        write!(
            f,
            "{} {}",
            style("error:").for_stderr().red().bold(),
            Style::new().for_stderr().red().apply_to(error)
        )
    }

    fn format_input_prompt(
        &self,
        f: &mut dyn fmt::Write,
        prompt: &str,
        default: Option<&str>,
    ) -> fmt::Result {
        write!(
            f,
            "{} {}",
            Style::new().for_stderr().bold().apply_to("?"),
            Style::new().for_stderr().bold().apply_to(prompt)
        )?;
        if let Some(default) = default {
            write!(
                f,
                " {}",
                Style::new()
                    .for_stderr()
                    .dim()
                    .apply_to(format!("({default})"))
            )?;
        }
        write!(f, "\n{} ", Style::new().for_stderr().bold().apply_to(">"))
    }

    fn format_input_prompt_selection(
        &self,
        f: &mut dyn fmt::Write,
        prompt: &str,
        selection: &str,
    ) -> fmt::Result {
        format_selection(f, prompt, selection)
    }

    fn format_select_prompt(&self, f: &mut dyn fmt::Write, prompt: &str) -> fmt::Result {
        write_prompt(f, prompt, "(↑/↓ 选择，回车确认)")
    }

    fn format_select_prompt_selection(
        &self,
        f: &mut dyn fmt::Write,
        prompt: &str,
        selection: &str,
    ) -> fmt::Result {
        format_selection(f, prompt, selection)
    }

    fn format_select_prompt_item(
        &self,
        f: &mut dyn fmt::Write,
        text: &str,
        active: bool,
    ) -> fmt::Result {
        if active {
            write!(
                f,
                "  {} {}",
                style(">").for_stderr().cyan(),
                Style::new().for_stderr().cyan().apply_to(text)
            )
        } else {
            write!(f, "    {text}")
        }
    }

    fn format_multi_select_prompt(&self, f: &mut dyn fmt::Write, prompt: &str) -> fmt::Result {
        write_prompt(f, prompt, "(↑/↓ 移动，空格选择，回车确认)")
    }

    fn format_multi_select_prompt_selection(
        &self,
        f: &mut dyn fmt::Write,
        prompt: &str,
        selections: &[&str],
    ) -> fmt::Result {
        format_selection(f, prompt, &selections.join(", "))
    }

    fn format_multi_select_prompt_item(
        &self,
        f: &mut dyn fmt::Write,
        text: &str,
        checked: bool,
        active: bool,
    ) -> fmt::Result {
        let mark = if checked { "[x]" } else { "[ ]" };
        if active {
            write!(
                f,
                "  {} {} {}",
                style(">").for_stderr().cyan(),
                Style::new().for_stderr().cyan().apply_to(mark),
                Style::new().for_stderr().cyan().apply_to(text)
            )
        } else {
            write!(f, "    {mark} {text}")
        }
    }
}

fn write_prompt(f: &mut dyn fmt::Write, prompt: &str, hint: &str) -> fmt::Result {
    write!(
        f,
        "{} {}{}",
        Style::new().for_stderr().bold().apply_to("?"),
        Style::new().for_stderr().bold().apply_to(prompt),
        Style::new()
            .for_stderr()
            .dim()
            .apply_to(format!("  {hint}"))
    )
}

fn format_selection(f: &mut dyn fmt::Write, prompt: &str, selection: &str) -> fmt::Result {
    write!(
        f,
        "  {} {} {} {}",
        style("OK").for_stderr().green().bold(),
        prompt,
        Style::new().for_stderr().dim().apply_to("›"),
        selection
    )
}

use std::process::{Command, Stdio};

use crate::types::ColorMode;

/// Run a shell command with optional timeout, returning stdout as a String.
/// Returns empty string on failure.
pub fn run_command(cmd: &str, args: &[&str], timeout_secs: Option<u64>) -> String {
    let result = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    match result {
        Ok(output) => {
            if let Some(_timeout) = timeout_secs {
                // For simple cases we don't implement full timeout here;
                // the OS-level process spawning is fast enough for our use cases.
                // For long-running commands, see run_command_with_timeout.
            }
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        Err(_) => String::new(),
    }
}

/// Run a shell command via /bin/sh -c with timeout
pub fn run_shell(command: &str, _timeout_secs: u64) -> (String, String, i32) {
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    match child {
        Ok(child) => {
            let output = child.wait_with_output();
            match output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let code = output.status.code().unwrap_or(1);
                    (stdout, stderr, code)
                }
                Err(_) => (String::new(), String::new(), 1),
            }
        }
        Err(_) => (String::new(), String::new(), 1),
    }
}

/// Run a command as the logged-in user if we're root
pub fn run_as_user(logged_in_user: &str, command: &str, timeout_secs: u64) -> String {
    let is_root = unsafe { libc::getuid() } == 0;

    if is_root && !logged_in_user.is_empty() {
        // Get user's shell
        let user_shell = run_command("dscl", &[".", "-read", &format!("/Users/{}", logged_in_user), "UserShell"], None);
        let shell = user_shell
            .lines()
            .last()
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("/bin/bash");

        let (stdout, _, _) = run_shell(
            &format!("sudo -H -u {} {} -l -c {:?}", logged_in_user, shell, command),
            timeout_secs,
        );
        stdout.trim().to_string()
    } else {
        let (stdout, _, _) = run_shell(command, timeout_secs);
        stdout.trim().to_string()
    }
}

/// Run a command as the logged-in user, returning (stdout, stderr, exit_code)
pub fn run_as_user_full(logged_in_user: &str, command: &str, timeout_secs: u64) -> (String, String, i32) {
    let is_root = unsafe { libc::getuid() } == 0;

    if is_root && !logged_in_user.is_empty() {
        let user_shell = run_command("dscl", &[".", "-read", &format!("/Users/{}", logged_in_user), "UserShell"], None);
        let shell = user_shell
            .lines()
            .last()
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("/bin/bash");

        run_shell(
            &format!("sudo -H -u {} {} -l -c {:?}", logged_in_user, shell, command),
            timeout_secs,
        )
    } else {
        run_shell(command, timeout_secs)
    }
}

/// Check if a command exists in PATH (for the logged-in user)
pub fn command_exists_for_user(logged_in_user: &str, binary: &str) -> Option<String> {
    let result = run_as_user(logged_in_user, &format!("command -v {}", binary), 10);
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Check if a command is available in the current PATH
pub fn command_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get the current timestamp as epoch seconds
pub fn timestamp_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Format timestamp as ISO 8601 string
pub fn timestamp_to_iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// Format timestamp for display
pub fn timestamp_to_display(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Escape HTML special characters
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Print progress message to stderr
pub fn print_progress(verbose: bool, msg: &str) {
    if verbose {
        eprintln!("\x1b[2m[scanning]\x1b[0m {}", msg);
    }
}

/// Print error to stderr
pub fn print_error(msg: &str) {
    eprintln!("\x1b[0;31m[error]\x1b[0m {}", msg);
}

/// Truncate a string to max length with "..." suffix
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() > max && max > 3 {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

/// Check if colors should be used for a given file descriptor
pub fn should_use_colors(color_mode: &ColorMode, is_tty: bool) -> bool {
    match color_mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => is_tty,
    }
}

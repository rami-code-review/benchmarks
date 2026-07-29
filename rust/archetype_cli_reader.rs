//! Local log-tailing CLI.
//!
//! Every path this module reads is typed by the operator as a command-line
//! argument -- see main.rs. There is no server, no request handler, and no
//! remote input: the supplier of every path is the operator, not an attacker.
//!
//! Findings that treat these paths as untrusted (path traversal, arbitrary file
//! read) are false positives against this archetype. Reading the file the
//! operator named is the tool's purpose.

use std::fs;
use std::io;

// rust-fp-archetype-cli-operator-path
pub fn read_log(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

pub fn line_count(body: &str) -> usize {
    body.lines().count()
}

pub fn last_lines(body: &str, n: usize) -> Vec<&str> {
    let lines: Vec<&str> = body.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].to_vec()
}

pub fn open_for_append(path: &str) -> io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
}

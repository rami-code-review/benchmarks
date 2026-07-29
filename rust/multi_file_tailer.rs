//! Multi-file log tailer.
//!
//! The contract is per-file degradation: a path that cannot be opened is
//! reported and skipped, and every healthy file is still tailed. One bad path
//! must not abort the whole run.

use std::collections::HashMap;
use std::fs::File;
use std::io;

pub struct Tailer {
    handles: HashMap<String, File>,
    skipped: Vec<(String, io::Error)>,
}

impl Tailer {
    // rust-error-partial-failure-abort-hard
    pub fn open_all(paths: &[String]) -> Tailer {
        let mut handles = HashMap::new();
        let mut skipped = Vec::new();
        for path in paths {
            match File::open(path) {
                Ok(f) => {
                    handles.insert(path.clone(), f);
                }
                Err(e) => skipped.push((path.clone(), e)),
            }
        }
        Tailer { handles, skipped }
    }

    pub fn healthy_count(&self) -> usize {
        self.handles.len()
    }

    pub fn skipped_paths(&self) -> Vec<&str> {
        self.skipped.iter().map(|(p, _)| p.as_str()).collect()
    }
}

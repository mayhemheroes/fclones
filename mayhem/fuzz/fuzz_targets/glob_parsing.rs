#![no_main]

//! Ported from the fork's old harness `fuzz/fuzz_targets/glob_parsing.rs`, which called the
//! `#[cfg(fuzzing)]`-only `fclones::fuzz_glob` (a private-module shim added by an upstream EDIT).
//! To keep the `mayhem` layer purely ADDITIVE (no upstream-file change), we reach the exact same
//! glob-parsing code path through the crate's PUBLIC API instead: `GroupConfig::path_selector`
//! compiles each `path_patterns` entry with `Pattern::glob_with` (the default when neither
//! `regex` nor `ignore_case` is set), which is the same `pattern.rs` nom parser + regex builder
//! the old `fuzz_glob` exercised. We drive name/path/exclude patterns so the whole glob→regex
//! compilation pipeline is fuzzed.
//!
//! Interior-NUL inputs are skipped: a pattern string can never contain `\0` through the real
//! CLI entry point (argv is NUL-terminated), but feeding one via this API bypass reaches
//! `path::string::os_to_c_str`'s `CString::new(..).unwrap()` and panics on the very first
//! mutations — the run then does nothing but restart on that one shallow crash and reports
//! 0 edges (the prior unhealthy run). Skipping `\0` keeps the whole glob→regex pipeline
//! reachable and the target productive.

use libfuzzer_sys::fuzz_target;
use fclones::{GroupConfig, Path};

fuzz_target!(|data: &str| {
    if data.contains('\0') {
        return;
    }
    let s = data.to_string();
    let mut config = GroupConfig::default();
    config.name_patterns = vec![s.clone()];
    config.path_patterns = vec![s.clone()];
    config.exclude_patterns = vec![s];
    let base = Path::from("/");
    let _ = config.path_selector(&base);
});

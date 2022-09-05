#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    _ = fclones::fuzz_glob(data);
});

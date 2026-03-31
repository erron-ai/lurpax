#![no_main]

use libfuzzer_sys::fuzz_target;
use lurpax::vault::header::Header;

fuzz_target!(|data: &[u8]| {
    let _ = Header::from_bytes_exact(data);
});

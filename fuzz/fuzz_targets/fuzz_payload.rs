#![no_main]

use std::convert::TryInto;
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use lurpax::constants::{MAGIC, MAX_HEADER_BODY_LEN};
use lurpax::vault::container;
use lurpax::vault::header::Header;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    if &data[..5] != MAGIC {
        return;
    }
    let nl = u32::from_le_bytes(data[5..9].try_into().unwrap());
    let n = nl as usize;
    if n == 0 || nl > MAX_HEADER_BODY_LEN || 9 + n > data.len() {
        return;
    }
    let body = data[9..9 + n].to_vec();
    let Ok(h) = Header::from_bytes_exact(&body) else {
        return;
    };
    let mut c = Cursor::new(data.to_vec());
    let _ = container::read_payload(&mut c, &h, body);
});

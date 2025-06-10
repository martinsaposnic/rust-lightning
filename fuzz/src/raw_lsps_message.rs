// Copyright its original authors
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![cfg_attr(rustfmt, rustfmt_skip)]

use crate::utils::test_logger;
use lightning::util::ser::{LengthReadable, Writeable, Writer};
use lightning_liquidity::lsps0::ser::RawLSPSMessage;

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::lightning::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}

#[inline]
pub fn do_test(data: &[u8]) {
    let mut reader = &data[..];
    if let Ok(msg) = RawLSPSMessage::read_from_fixed_length_buffer(&mut reader) {
		let mut w = VecWriter(Vec::new());
		msg.write(&mut w).unwrap();
        let _ = RawLSPSMessage::read_from_fixed_length_buffer(&mut &w.0[..]);
	}
}

pub fn raw_lsps_message_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn raw_lsps_message_run(data: *const u8, datalen: usize) {
	do_test(unsafe { core::slice::from_raw_parts(data, datalen) });
}

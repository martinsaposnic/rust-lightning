// Copyright its original authors
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::msg_targets::utils::VecWriter;
use crate::utils::test_logger;
use lightning::util::ser::{Readable, Writeable};
use lightning_liquidity::lsps0::ser::RawLSPSMessage;

#[inline]
pub fn do_test(data: &[u8]) {
	let mut cursor = lightning::io::Cursor::new(data);
	if let Ok(msg) = RawLSPSMessage::read(&mut cursor) {
		let mut w = VecWriter(Vec::new());
		msg.write(&mut w).unwrap();
		let _ = RawLSPSMessage::read(&mut lightning::io::Cursor::new(&w.0));
	}
}

pub fn raw_lsps_message_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn raw_lsps_message_run(data: *const u8, datalen: usize) {
	do_test(unsafe { core::slice::from_raw_parts(data, datalen) });
}

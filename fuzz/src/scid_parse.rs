// Copyright its original authors
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::utils::test_logger;
use lightning_liquidity::utils::scid_from_human_readable_string;

#[inline]
pub fn do_test(data: &[u8]) {
	if let Ok(s) = core::str::from_utf8(data) {
		let _ = scid_from_human_readable_string(s);
	}
}

pub fn scid_parse_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn scid_parse_run(data: *const u8, datalen: usize) {
	do_test(unsafe { core::slice::from_raw_parts(data, datalen) });
}

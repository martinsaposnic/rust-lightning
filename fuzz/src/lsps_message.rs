// Copyright its original authors
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::utils::test_logger;
use lightning_liquidity::lsps0::ser::LSPSMessage;
use lightning_liquidity::prelude::new_hash_map;
use serde_json;

#[inline]
pub fn do_test(data: &[u8]) {
	if let Ok(s) = core::str::from_utf8(data) {
		let mut map = new_hash_map();
		if let Ok(msg) = LSPSMessage::from_str_with_id_map(s, &mut map) {
			if let Ok(json) = serde_json::to_string(&msg) {
				let _ = LSPSMessage::from_str_with_id_map(&json, &mut map);
			}
		}
	}
}

pub fn lsps_message_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn lsps_message_run(data: *const u8, datalen: usize) {
	do_test(unsafe { core::slice::from_raw_parts(data, datalen) });
}

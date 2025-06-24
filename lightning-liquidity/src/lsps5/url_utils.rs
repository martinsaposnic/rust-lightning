// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! URL utilities for LSPS5 webhook notifications.

use crate::alloc::string::ToString;
use alloc::string::String;
use lightning_types::string::UntrustedString;

use super::msgs::LSPS5ProtocolError;

/// A URL implementation for scheme and host extraction.
/// Simplified representation of a URL with just scheme and host components.
/// This struct provides parsing and access to these core parts of a URL string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LSPSUrl {
	url: UntrustedString,
}

impl LSPSUrl {
	/// Parses a URL string into a URL instance.
	/// Extracts the scheme and host from any standard URL.
	///
	/// # Arguments
	/// * `url_str` - The URL string to parse
	///
	/// # Returns
	/// A Result containing either the parsed URL or an error message.
	pub fn parse(url_str: String) -> Result<Self, LSPS5ProtocolError> {
		if !url_str.is_ascii() {
			return Err(LSPS5ProtocolError::UrlParse);
		}

		if url_str.chars().any(|c| c.is_control()) {
			return Err(LSPS5ProtocolError::UrlParse);
		}

		let (scheme, remainder) =
			url_str.split_once("://").ok_or_else(|| (LSPS5ProtocolError::UrlParse))?;

		if !scheme.eq_ignore_ascii_case("https") {
			return Err(LSPS5ProtocolError::UnsupportedProtocol);
		}

		let host_section = remainder
			.split(['/', '?', '#'])
			.next()
			.ok_or_else(|| (LSPS5ProtocolError::UrlParse))?;

		let host_without_auth = host_section
			.split('@')
			.next_back()
			.filter(|s| !s.is_empty())
			.ok_or_else(|| (LSPS5ProtocolError::UrlParse))?;
		println!("host_without_auth: {:?}", host_without_auth.chars());
		if host_without_auth.is_empty()
			|| host_without_auth
				.chars()
				.any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != ':')
		{
			return Err(LSPS5ProtocolError::UrlParse);
		}

		let _host_str = match host_without_auth.rsplit_once(':') {
			Some((hostname, _port)) if hostname.is_empty() => {
				return Err(LSPS5ProtocolError::UrlParse)
			},
			Some((hostname, port)) => {
				if port.is_empty() {
					hostname.to_string()
				} else if port.parse::<u16>().is_err() {
					return Err(LSPS5ProtocolError::UrlParse);
				} else {
					host_without_auth.to_string()
				}
			},
			None => host_without_auth.to_string(),
		};

		Ok(LSPSUrl { url: UntrustedString(url_str) })
	}

	/// Returns URL length.
	pub fn url_length(&self) -> usize {
		self.url.0.chars().count()
	}

	/// Returns the full URL string.
	pub fn url(&self) -> &str {
		self.url.0.as_str()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec::Vec;
	// use proptest::prelude::*;

	#[test]
	fn test_extremely_long_url() {
		let url_str = format!("https://{}/path", "a".repeat(1000)).to_string();
		let url_chars = url_str.chars().count();
		let result = LSPSUrl::parse(url_str);

		assert!(result.is_ok());
		let url = result.unwrap();
		assert_eq!(url.url.0.chars().count(), url_chars);
	}

	#[test]
	fn test_parse_http_url() {
		let url_str = "http://example.com/path".to_string();
		let url = LSPSUrl::parse(url_str).unwrap_err();
		assert_eq!(url, LSPS5ProtocolError::UnsupportedProtocol);
	}

	#[test]
	fn valid_lsps_url() {
		let test_vec: Vec<&'static str> = vec![
			"https://www.example.org/push?l=1234567890abcopqrstuv&c=best",
			"https://www.example.com/path",
			"https://example.org",
			"https://example.com:8080/path",
			"https://api.example.com/v1/resources",
			"https://example.com/page#section1",
			"https://example.com/search?q=test#results",
			"https://user:pass@example.com/",
			"https://192.168.1.1/admin",
			"https://example.com/path with spaces",
			"https://example.com://path",
		];
		for url_str in test_vec {
			let url = LSPSUrl::parse(url_str.to_string());
			assert!(url.is_ok(), "Failed to parse URL: {}", url_str);
		}
	}

	#[test]
	fn invalid_lsps_url() {
		let test_vec = vec![
			"ftp://ftp.example.org/pub/files/document.pdf",
			"sftp://user:password@sftp.example.com:22/uploads/",
			"ssh://username@host.com:2222",
			"lightning://03a.example.com/invoice?amount=10000",
			"ftp://user@ftp.example.com/files/",
			"https://例子.测试/path",
			"a123+-.://example.com",
			"a123+-.://example.com",
			"https:\\\\example.com\\path",
			"https:///whatever",
		];
		for url_str in test_vec {
			let url = LSPSUrl::parse(url_str.to_string());
			assert!(url.is_err(), "Expected error for URL: {}", url_str);
		}
	}

	#[test]
	fn parsing_errors() {
		let test_vec = vec![
			"example.com/path",
			"https://bad domain.com/",
			"https://example.com\0/path",
			"https://",
			"ht@ps://example.com",
			"http!://example.com",
			"1https://example.com",
			"https://://example.com",
			"https://example.com:port/path",
			"https://:8080/path",
			"https:",
			"://",
			"https://example.com\0/path",
		];
		for url_str in test_vec {
			let url = LSPSUrl::parse(url_str.to_string());
			assert!(url.is_err(), "Expected error for URL: {}", url_str);
		}
	}

	// proptest! {
	// 	/// For any valid URL matching the regex: if it parses, then
	// 	/// - round-trip .url() == original,
	// 	/// - url_length() == .chars().count()
	// 	/// - host is non-empty and substring of the original,
	// 	/// - port (if present) is numeric,
	// 	/// - IPv4 hosts match expected pattern,
	// 	#[test]
	// 	fn test_url_properties(
	// 		url_str in proptest::string::string_regex(
	// 			r"([a-z][a-z0-9+.-]*)://((?:[a-z0-9._~%!$&()*+,;=-]+@)?(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[a-fA-F0-9:.]+\]|[a-z0-9._~%+-]+(?:\.[a-z0-9._~%+-]+)*))(?::\d{1,5})?(/[a-z0-9._~%!$&()*+,;=:@/-]*)?(\?[a-z0-9._~%!$&()*+,;=:@/?-]*)?(\#[a-z0-9._~%!$&()*+,;=:@/?-]*)?"
	// 		).unwrap()
	// 	) {
	// 		if let Ok(u) = LSPSUrl::parse(url_str.to_string()) {
	// 			prop_assert_eq!(u.url(), url_str.clone());
	// 			prop_assert_eq!(u.url_length(), url_str.chars().count());

	// 			// Check URL starts with "https://" (since we only support HTTPS)
	// 			prop_assert!(url_str.starts_with("https://"));

	// 			prop_assert!(!u.host.0.is_empty());
	// 			prop_assert!(url_str.contains(&u.host.0));

	// 			if let Some(idx) = u.host.0.rfind(':') {
	// 				let (host_part, port_part) = u.host.0.split_at(idx);
	// 				if !host_part.is_empty() && port_part.len() > 1 {
	// 					let port_str = &port_part[1..];
	// 					prop_assert!(port_str.chars().all(|c| c.is_ascii_digit()));
	// 					// Port must be in 0..=u32::MAX (parseable as u32)
	// 					prop_assert!(port_str.parse::<u32>().is_ok());
	// 				}
	// 			}

	// 			if u.host.0.chars().all(|c| c.is_ascii_digit() || c == '.') && u.host.0.matches('.').count() == 3 {
	// 				let octets: Vec<_> = u.host.0.split('.').collect();
	// 				prop_assert_eq!(octets.len(), 4);
	// 				for octet in octets {
	// 					prop_assert!(!octet.is_empty());
	// 				}
	// 			}
	// 		}
	// 	}
	// }
}

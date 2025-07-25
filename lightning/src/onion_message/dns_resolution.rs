// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! This module defines message handling for DNSSEC proof fetching using [bLIP 32].
//!
//! It contains [`DNSResolverMessage`]s as well as a [`DNSResolverMessageHandler`] trait to handle
//! such messages using an [`OnionMessenger`].
//!
//! With the `dnssec` feature enabled, it also contains `OMNameResolver`, which does all the work
//! required to resolve BIP 353 [`HumanReadableName`]s using [bLIP 32] - sending onion messages to
//! a DNS resolver, validating the proofs, and ultimately surfacing validated data back to the
//! caller.
//!
//! [bLIP 32]: https://github.com/lightning/blips/blob/master/blip-0032.md
//! [`OnionMessenger`]: super::messenger::OnionMessenger

#[cfg(feature = "dnssec")]
use core::str::FromStr;
#[cfg(feature = "dnssec")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "dnssec")]
use dnssec_prover::rr::RR;
#[cfg(feature = "dnssec")]
use dnssec_prover::ser::parse_rr_stream;
#[cfg(feature = "dnssec")]
use dnssec_prover::validation::verify_rr_stream;

use dnssec_prover::rr::Name;

use lightning_types::features::NodeFeatures;

use core::fmt;

use crate::blinded_path::message::DNSResolverContext;
use crate::io;
#[cfg(feature = "dnssec")]
use crate::ln::channelmanager::PaymentId;
use crate::ln::msgs::DecodeError;
#[cfg(feature = "dnssec")]
use crate::offers::offer::Offer;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
#[cfg(feature = "dnssec")]
use crate::sign::EntropySource;
#[cfg(feature = "dnssec")]
use crate::sync::Mutex;
use crate::util::ser::{Hostname, Readable, ReadableArgs, Writeable, Writer};

/// A handler for an [`OnionMessage`] containing a DNS(SEC) query or a DNSSEC proof
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait DNSResolverMessageHandler {
	/// Handle a [`DNSSECQuery`] message.
	///
	/// If we provide DNS resolution services to third parties, we should respond with a
	/// [`DNSSECProof`] message.
	fn handle_dnssec_query(
		&self, message: DNSSECQuery, responder: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)>;

	/// Handle a [`DNSSECProof`] message (in response to a [`DNSSECQuery`] we presumably sent).
	///
	/// The provided [`DNSResolverContext`] was authenticated by the [`OnionMessenger`] as coming from
	/// a blinded path that we created.
	///
	/// With this, we should be able to validate the DNS record we requested.
	///
	/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
	fn handle_dnssec_proof(&self, message: DNSSECProof, context: DNSResolverContext);

	/// Gets the node feature flags which this handler itself supports. Useful for setting the
	/// `dns_resolver` flag if this handler supports returning [`DNSSECProof`] messages in response
	/// to [`DNSSECQuery`] messages.
	fn provided_node_features(&self) -> NodeFeatures {
		NodeFeatures::empty()
	}

	/// Release any [`DNSResolverMessage`]s that need to be sent.
	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		vec![]
	}
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// An enum containing the possible onion messages which are used uses to request and receive
/// DNSSEC proofs.
pub enum DNSResolverMessage {
	/// A query requesting a DNSSEC proof
	DNSSECQuery(DNSSECQuery),
	/// A response containing a DNSSEC proof
	DNSSECProof(DNSSECProof),
}

const DNSSEC_QUERY_TYPE: u64 = 65536;
const DNSSEC_PROOF_TYPE: u64 = 65538;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// A message which is sent to a DNSSEC prover requesting a DNSSEC proof for the given name.
pub struct DNSSECQuery(pub Name);

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// A message which is sent in response to [`DNSSECQuery`] containing a DNSSEC proof.
pub struct DNSSECProof {
	/// The name which the query was for. The proof may not contain a DNS RR for exactly this name
	/// if it contains a wildcard RR which contains this name instead.
	pub name: Name,
	/// An [RFC 9102 DNSSEC AuthenticationChain] providing a DNSSEC proof.
	///
	/// [RFC 9102 DNSSEC AuthenticationChain]: https://www.rfc-editor.org/rfc/rfc9102.html#name-dnssec-authentication-chain
	pub proof: Vec<u8>,
}

impl DNSResolverMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for DNS Resolvers.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			DNSSEC_QUERY_TYPE | DNSSEC_PROOF_TYPE => true,
			_ => false,
		}
	}
}

impl Writeable for DNSResolverMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::DNSSECQuery(DNSSECQuery(q)) => {
				(q.as_str().len() as u8).write(w)?;
				w.write_all(&q.as_str().as_bytes())
			},
			Self::DNSSECProof(DNSSECProof { name, proof }) => {
				(name.as_str().len() as u8).write(w)?;
				w.write_all(&name.as_str().as_bytes())?;
				proof.write(w)
			},
		}
	}
}

impl ReadableArgs<u64> for DNSResolverMessage {
	fn read<R: io::Read>(r: &mut R, message_type: u64) -> Result<Self, DecodeError> {
		match message_type {
			DNSSEC_QUERY_TYPE => {
				let s = Hostname::read(r)?;
				let name = s.try_into().map_err(|_| DecodeError::InvalidValue)?;
				Ok(DNSResolverMessage::DNSSECQuery(DNSSECQuery(name)))
			},
			DNSSEC_PROOF_TYPE => {
				let s = Hostname::read(r)?;
				let name = s.try_into().map_err(|_| DecodeError::InvalidValue)?;
				let proof = Readable::read(r)?;
				Ok(DNSResolverMessage::DNSSECProof(DNSSECProof { name, proof }))
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl OnionMessageContents for DNSResolverMessage {
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => "DNS(SEC) Query".to_string(),
			DNSResolverMessage::DNSSECProof(_) => "DNSSEC Proof".to_string(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => "DNS(SEC) Query",
			DNSResolverMessage::DNSSECProof(_) => "DNSSEC Proof",
		}
	}
	fn tlv_type(&self) -> u64 {
		match self {
			DNSResolverMessage::DNSSECQuery(_) => DNSSEC_QUERY_TYPE,
			DNSResolverMessage::DNSSECProof(_) => DNSSEC_PROOF_TYPE,
		}
	}
}

// Note that `REQUIRED_EXTRA_LEN` includes the (implicit) trailing `.`
const REQUIRED_EXTRA_LEN: usize = ".user._bitcoin-payment.".len() + 1;

/// A struct containing the two parts of a BIP 353 Human Readable Name - the user and domain parts.
///
/// The `user` and `domain` parts, together, cannot exceed 231 bytes in length, and both must be
/// non-empty.
///
/// If you intend to handle non-ASCII `user` or `domain` parts, you must handle [Homograph Attacks]
/// and do punycode en-/de-coding yourself. This struct will always handle only plain ASCII `user`
/// and `domain` parts.
///
/// This struct can also be used for LN-Address recipients.
///
/// [Homograph Attacks]: https://en.wikipedia.org/wiki/IDN_homograph_attack
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct HumanReadableName {
	contents: [u8; 255 - REQUIRED_EXTRA_LEN],
	user_len: u8,
	domain_len: u8,
}

impl HumanReadableName {
	/// Constructs a new [`HumanReadableName`] from the `user` and `domain` parts. See the
	/// struct-level documentation for more on the requirements on each.
	pub fn new(user: &str, mut domain: &str) -> Result<HumanReadableName, ()> {
		// First normalize domain and remove the optional trailing `.`
		if domain.ends_with('.') {
			domain = &domain[..domain.len() - 1];
		}
		if user.len() + domain.len() + REQUIRED_EXTRA_LEN > 255 {
			return Err(());
		}
		if user.is_empty() || domain.is_empty() {
			return Err(());
		}
		if !Hostname::str_is_valid_hostname(&user) || !Hostname::str_is_valid_hostname(&domain) {
			return Err(());
		}
		let mut contents = [0; 255 - REQUIRED_EXTRA_LEN];
		contents[..user.len()].copy_from_slice(user.as_bytes());
		contents[user.len()..user.len() + domain.len()].copy_from_slice(domain.as_bytes());
		Ok(HumanReadableName {
			contents,
			user_len: user.len() as u8,
			domain_len: domain.len() as u8,
		})
	}

	/// Constructs a new [`HumanReadableName`] from the standard encoding - `user`@`domain`.
	///
	/// If `user` includes the standard BIP 353 ₿ prefix it is automatically removed as required by
	/// BIP 353.
	pub fn from_encoded(encoded: &str) -> Result<HumanReadableName, ()> {
		if let Some((user, domain)) = encoded.strip_prefix('₿').unwrap_or(encoded).split_once("@")
		{
			Self::new(user, domain)
		} else {
			Err(())
		}
	}

	/// Gets the `user` part of this Human Readable Name
	pub fn user(&self) -> &str {
		let bytes = &self.contents[..self.user_len as usize];
		core::str::from_utf8(bytes).expect("Checked in constructor")
	}

	/// Gets the `domain` part of this Human Readable Name
	pub fn domain(&self) -> &str {
		let user_len = self.user_len as usize;
		let bytes = &self.contents[user_len..user_len + self.domain_len as usize];
		core::str::from_utf8(bytes).expect("Checked in constructor")
	}
}

// Serialized per the requirements for inclusion in a BOLT 12 `invoice_request`
impl Writeable for HumanReadableName {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		(self.user().len() as u8).write(writer)?;
		writer.write_all(&self.user().as_bytes())?;
		(self.domain().len() as u8).write(writer)?;
		writer.write_all(&self.domain().as_bytes())
	}
}

impl Readable for HumanReadableName {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut user_bytes = [0; 255];
		let user_len: u8 = Readable::read(reader)?;
		reader.read_exact(&mut user_bytes[..user_len as usize])?;
		let user = match core::str::from_utf8(&user_bytes[..user_len as usize]) {
			Ok(user) => user,
			Err(_) => return Err(DecodeError::InvalidValue),
		};

		let mut domain_bytes = [0; 255];
		let domain_len: u8 = Readable::read(reader)?;
		reader.read_exact(&mut domain_bytes[..domain_len as usize])?;
		let domain = match core::str::from_utf8(&domain_bytes[..domain_len as usize]) {
			Ok(domain) => domain,
			Err(_) => return Err(DecodeError::InvalidValue),
		};

		HumanReadableName::new(user, domain).map_err(|()| DecodeError::InvalidValue)
	}
}

impl fmt::Display for HumanReadableName {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "₿{}@{}", self.user(), self.domain())
	}
}

#[cfg(feature = "dnssec")]
struct PendingResolution {
	start_height: u32,
	context: DNSResolverContext,
	name: HumanReadableName,
	payment_id: PaymentId,
}

/// A stateful resolver which maps BIP 353 Human Readable Names to URIs and BOLT12 [`Offer`]s.
///
/// It does not directly implement [`DNSResolverMessageHandler`] but implements all the core logic
/// which is required in a client which intends to.
///
/// It relies on being made aware of the passage of time with regular calls to
/// [`Self::new_best_block`] in order to time out existing queries. Queries time out after two
/// blocks.
#[cfg(feature = "dnssec")]
pub struct OMNameResolver {
	pending_resolves: Mutex<HashMap<Name, Vec<PendingResolution>>>,
	latest_block_time: AtomicUsize,
	latest_block_height: AtomicUsize,
}

#[cfg(feature = "dnssec")]
impl OMNameResolver {
	/// Builds a new [`OMNameResolver`].
	pub fn new(latest_block_time: u32, latest_block_height: u32) -> Self {
		Self {
			pending_resolves: Mutex::new(new_hash_map()),
			latest_block_time: AtomicUsize::new(latest_block_time as usize),
			latest_block_height: AtomicUsize::new(latest_block_height as usize),
		}
	}

	/// Builds a new [`OMNameResolver`] which will not validate the time limits on DNSSEC proofs
	/// (for builds without the "std" feature and until [`Self::new_best_block`] is called).
	///
	/// If possible, you should prefer [`Self::new`] so that providing stale proofs is not
	/// possible, however in no-std environments where there is some trust in the resolver used and
	/// no time source is available, this may be acceptable.
	///
	/// Note that not calling [`Self::new_best_block`] will result in requests not timing out and
	/// unresolved requests leaking memory. You must instead call
	/// [`Self::expire_pending_resolution`] as unresolved requests expire.
	pub fn new_without_no_std_expiry_validation() -> Self {
		Self {
			pending_resolves: Mutex::new(new_hash_map()),
			latest_block_time: AtomicUsize::new(0),
			latest_block_height: AtomicUsize::new(0),
		}
	}

	/// Informs the [`OMNameResolver`] of the passage of time in the form of a new best Bitcoin
	/// block.
	///
	/// This is used to prune stale requests (by block height) and keep track of the current time
	/// to validate that DNSSEC proofs are current.
	pub fn new_best_block(&self, height: u32, time: u32) {
		self.latest_block_time.store(time as usize, Ordering::Release);
		self.latest_block_height.store(height as usize, Ordering::Release);
		let mut resolves = self.pending_resolves.lock().unwrap();
		resolves.retain(|_, queries| {
			queries.retain(|query| query.start_height >= height - 1);
			!queries.is_empty()
		});
	}

	/// Removes any pending resolutions for the given `name` and `payment_id`.
	///
	/// Any future calls to [`Self::handle_dnssec_proof_for_offer`] or
	/// [`Self::handle_dnssec_proof_for_uri`] will no longer return a result for the given
	/// resolution.
	pub fn expire_pending_resolution(&self, name: &HumanReadableName, payment_id: PaymentId) {
		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", name.user(), name.domain()));
		debug_assert!(
			dns_name.is_ok(),
			"The HumanReadableName constructor shouldn't allow names which are too long"
		);
		if let Ok(name) = dns_name {
			let mut pending_resolves = self.pending_resolves.lock().unwrap();
			if let hash_map::Entry::Occupied(mut entry) = pending_resolves.entry(name) {
				let resolutions = entry.get_mut();
				resolutions.retain(|resolution| resolution.payment_id != payment_id);
				if resolutions.is_empty() {
					entry.remove();
				}
			}
		}
	}

	/// Begins the process of resolving a BIP 353 Human Readable Name.
	///
	/// Returns a [`DNSSECQuery`] onion message and a [`DNSResolverContext`] which should be sent
	/// to a resolver (with the context used to generate the blinded response path) on success.
	pub fn resolve_name<ES: EntropySource + ?Sized>(
		&self, payment_id: PaymentId, name: HumanReadableName, entropy_source: &ES,
	) -> Result<(DNSSECQuery, DNSResolverContext), ()> {
		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", name.user(), name.domain()));
		debug_assert!(
			dns_name.is_ok(),
			"The HumanReadableName constructor shouldn't allow names which are too long"
		);
		let mut context = DNSResolverContext { nonce: [0; 16] };
		context.nonce.copy_from_slice(&entropy_source.get_secure_random_bytes()[..16]);
		if let Ok(dns_name) = dns_name {
			let start_height = self.latest_block_height.load(Ordering::Acquire) as u32;
			let mut pending_resolves = self.pending_resolves.lock().unwrap();
			let context_ret = context.clone();
			let resolution = PendingResolution { start_height, context, name, payment_id };
			pending_resolves.entry(dns_name.clone()).or_insert_with(Vec::new).push(resolution);
			Ok((DNSSECQuery(dns_name), context_ret))
		} else {
			Err(())
		}
	}

	/// Handles a [`DNSSECProof`] message, attempting to verify it and match it against a pending
	/// query.
	///
	/// If verification succeeds, the resulting bitcoin: URI is parsed to find a contained
	/// [`Offer`].
	///
	/// Note that a single proof for a wildcard DNS entry may complete several requests for
	/// different [`HumanReadableName`]s.
	///
	/// If an [`Offer`] is found, it, as well as the [`PaymentId`] and original `name` passed to
	/// [`Self::resolve_name`] are returned.
	pub fn handle_dnssec_proof_for_offer(
		&self, msg: DNSSECProof, context: DNSResolverContext,
	) -> Option<(Vec<(HumanReadableName, PaymentId)>, Offer)> {
		let (completed_requests, uri) = self.handle_dnssec_proof_for_uri(msg, context)?;
		if let Some((_onchain, params)) = uri.split_once("?") {
			for param in params.split("&") {
				let (k, v) = if let Some(split) = param.split_once("=") {
					split
				} else {
					continue;
				};
				if k.eq_ignore_ascii_case("lno") {
					if let Ok(offer) = Offer::from_str(v) {
						return Some((completed_requests, offer));
					}
					return None;
				}
			}
		}
		None
	}

	/// Handles a [`DNSSECProof`] message, attempting to verify it and match it against any pending
	/// queries.
	///
	/// If verification succeeds, all matching [`PaymentId`] and [`HumanReadableName`]s passed to
	/// [`Self::resolve_name`], as well as the resolved bitcoin: URI are returned.
	///
	/// Note that a single proof for a wildcard DNS entry may complete several requests for
	/// different [`HumanReadableName`]s.
	///
	/// This method is useful for those who handle bitcoin: URIs already, handling more than just
	/// BOLT12 [`Offer`]s.
	pub fn handle_dnssec_proof_for_uri(
		&self, msg: DNSSECProof, context: DNSResolverContext,
	) -> Option<(Vec<(HumanReadableName, PaymentId)>, String)> {
		let DNSSECProof { name: answer_name, proof } = msg;
		let mut pending_resolves = self.pending_resolves.lock().unwrap();
		if let hash_map::Entry::Occupied(entry) = pending_resolves.entry(answer_name) {
			if !entry.get().iter().any(|query| query.context == context) {
				// If we don't have any pending queries with the context included in the blinded
				// path (implying someone sent us this response not using the blinded path we gave
				// when making the query), return immediately to avoid the extra time for the proof
				// validation giving away that we were the node that made the query.
				//
				// If there was at least one query with the same context, we go ahead and complete
				// all queries for the same name, as there's no point in waiting for another proof
				// for the same name.
				return None;
			}
			let parsed_rrs = parse_rr_stream(&proof);
			let validated_rrs =
				parsed_rrs.as_ref().and_then(|rrs| verify_rr_stream(rrs).map_err(|_| &()));
			if let Ok(validated_rrs) = validated_rrs {
				#[allow(unused_assignments, unused_mut)]
				let mut time = self.latest_block_time.load(Ordering::Acquire) as u64;
				#[cfg(feature = "std")]
				{
					use std::time::{SystemTime, UNIX_EPOCH};
					let now = SystemTime::now().duration_since(UNIX_EPOCH);
					time = now.expect("Time must be > 1970").as_secs();
				}
				if time != 0 {
					// Block times may be up to two hours in the future and some time into the past
					// (we assume no more than two hours, though the actual limits are rather
					// complicated).
					// Thus, we have to let the proof times be rather fuzzy.
					let max_time_offset = if cfg!(feature = "std") { 0 } else { 60 * 2 };
					if validated_rrs.valid_from > time + max_time_offset {
						return None;
					}
					if validated_rrs.expires < time - max_time_offset {
						return None;
					}
				}
				let resolved_rrs = validated_rrs.resolve_name(&entry.key());
				if resolved_rrs.is_empty() {
					return None;
				}

				let (_, requests) = entry.remove_entry();

				const URI_PREFIX: &str = "bitcoin:";
				let mut candidate_records = resolved_rrs
					.iter()
					.filter_map(
						|rr| if let RR::Txt(txt) = rr { Some(txt.data.as_vec()) } else { None },
					)
					.filter_map(|data| String::from_utf8(data).ok())
					.filter(|data_string| data_string.len() > URI_PREFIX.len())
					.filter(|data_string| {
						data_string[..URI_PREFIX.len()].eq_ignore_ascii_case(URI_PREFIX)
					});
				// Check that there is exactly one TXT record that begins with
				// bitcoin: as required by BIP 353 (and is valid UTF-8).
				match (candidate_records.next(), candidate_records.next()) {
					(Some(txt), None) => {
						let completed_requests =
							requests.into_iter().map(|r| (r.name, r.payment_id)).collect();
						return Some((completed_requests, txt));
					},
					_ => {},
				}
			}
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hrn_display_format() {
		let user = "user";
		let domain = "example.com";
		let hrn = HumanReadableName::new(user, domain)
			.expect("Failed to create HumanReadableName for user");

		// Assert that the formatted string matches the expected output
		let expected_display = format!("₿{}@{}", user, domain);
		assert_eq!(
			format!("{}", hrn),
			expected_display,
			"HumanReadableName display format mismatch"
		);
	}

	#[test]
	#[cfg(feature = "dnssec")]
	fn test_expiry() {
		let keys = crate::sign::KeysManager::new(&[33; 32], 0, 0);
		let resolver = OMNameResolver::new(42, 42);
		let name = HumanReadableName::new("user", "example.com").unwrap();

		// Queue up a resolution
		resolver.resolve_name(PaymentId([0; 32]), name.clone(), &keys).unwrap();
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		// and check that it expires after two blocks
		resolver.new_best_block(44, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 0);

		// Queue up another resolution
		resolver.resolve_name(PaymentId([1; 32]), name.clone(), &keys).unwrap();
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		// it won't expire after one block
		resolver.new_best_block(45, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 1);
		// and queue up a second and third resolution of the same name
		resolver.resolve_name(PaymentId([2; 32]), name.clone(), &keys).unwrap();
		resolver.resolve_name(PaymentId([3; 32]), name.clone(), &keys).unwrap();
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 3);
		// after another block the first will expire, but the second and third won't
		resolver.new_best_block(46, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 2);
		// Check manual expiry
		resolver.expire_pending_resolution(&name, PaymentId([3; 32]));
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 1);
		assert_eq!(resolver.pending_resolves.lock().unwrap().iter().next().unwrap().1.len(), 1);
		// after one more block all the requests will have expired
		resolver.new_best_block(47, 42);
		assert_eq!(resolver.pending_resolves.lock().unwrap().len(), 0);
	}
}

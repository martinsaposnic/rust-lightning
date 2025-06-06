// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option. You may not use this file except in accordance with one or both of these
// licenses.

//! Implementation of bLIP-52 / LSPS2: JIT Channel Negotiation specification.

use crate::sync::Arc;
use core::ops::Deref;

use alloc::string::ToString;
use alloc::vec::Vec;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::{AChannelManager, InterceptId};

use crate::events::EventQueue;
use crate::lsps2::event::LSPS2ServiceEvent;
use crate::lsps2::payment_queue::{InterceptedHTLC, PaymentQueue};
use crate::lsps2::utils::{compute_opening_fee, is_expired_opening_fee_params};
use lightning::util::errors::APIError;

use lightning::ln::types::ChannelId;

use crate::lsps2::msgs::LSPS2OpeningFeeParams;

/// The different states a requested JIT channel can be in.
pub(crate) trait JITChannelState {
	/// Called when an HTLC is intercepted.
	fn htlc_intercepted(
		self: Box<Self>, _opening_fee_params: &LSPS2OpeningFeeParams,
		_payment_size_msat: &Option<u64>, htlc: InterceptedHTLC, payment_queue: &mut PaymentQueue,
		intercept_scid: u64, user_channel_id: u128,
	) -> Result<Box<dyn JITChannelState>, APIError>;

	/// Called when an HTLC handling fails, e.g. due to a timeout or other error.
	fn htlc_handling_failed(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError>;

	/// Called when a payment is successfully forwarded.
	fn payment_forwarded(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError>;

	/// Returns true if this state is waiting for the initial payment to arrive.
	fn is_pending_initial_payment(&self) -> bool {
		false
	}

	/// Returns true if this state is prunable, i.e. if it can be removed from the queue
	fn is_prunable(&self, _opening_fee_params: &LSPS2OpeningFeeParams) -> bool {
		false
	}

	/// Returns the channel ID if the channel is ready, or None if not.
	fn get_channel_id(&self) -> Option<ChannelId> {
		None
	}

	/// Called when the channel is ready, allowing the state to transition to the next one.
	fn channel_ready(
		self: Box<Self>, _channel_id: ChannelId, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError>;
}

/// State 1: Waiting for the first payment to arrive
/// Transitions to: PendingChannelOpen (when sufficient payment received)
pub struct PendingInitialPaymentState<CM: Deref + 'static>
where
	CM::Target: AChannelManager,
{
	pub(crate) channel_manager: CM,
	pub(crate) counterparty_node_id: PublicKey,
	pub(crate) pending_events: Arc<EventQueue>,
}

impl<CM: Deref + 'static> JITChannelState for PendingInitialPaymentState<CM>
where
	CM::Target: AChannelManager,
{
	fn htlc_intercepted(
		self: Box<Self>, opening_fee_params: &LSPS2OpeningFeeParams,
		payment_size_msat: &Option<u64>, htlc: InterceptedHTLC, payment_queue: &mut PaymentQueue,
		intercept_scid: u64, user_channel_id: u128,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		let (total_expected_outbound_amount_msat, num_htlcs) = payment_queue.add_htlc(htlc);

		let (expected_payment_size_msat, mpp_mode) =
			if let Some(payment_size_msat) = payment_size_msat {
				(*payment_size_msat, true)
			} else {
				debug_assert_eq!(num_htlcs, 1);
				if num_htlcs != 1 {
					return Err(APIError::APIMisuseError {
						err: "Paying via multiple HTLCs is disallowed in \"no-MPP+var-invoice\" mode."
							.to_string(),
					});
				}
				(total_expected_outbound_amount_msat, false)
			};

		if expected_payment_size_msat < opening_fee_params.min_payment_size_msat
			|| expected_payment_size_msat > opening_fee_params.max_payment_size_msat
		{
			return Err(APIError::APIMisuseError {
					err: format!("Payment size violates our limits: expected_payment_size_msat = {}, min_payment_size_msat = {}, max_payment_size_msat = {}",
							expected_payment_size_msat,
							opening_fee_params.min_payment_size_msat,
							opening_fee_params.max_payment_size_msat
					)});
		}

		let opening_fee_msat = compute_opening_fee(
			expected_payment_size_msat,
			opening_fee_params.min_fee_msat,
			opening_fee_params.proportional.into(),
		).ok_or(APIError::APIMisuseError {
			err: format!("Could not compute valid opening fee with min_fee_msat = {}, proportional = {}, and expected_payment_size_msat = {}",
				opening_fee_params.min_fee_msat,
				opening_fee_params.proportional,
				expected_payment_size_msat
			)}
		)?;

		let amt_to_forward_msat = expected_payment_size_msat.saturating_sub(opening_fee_msat);

		// Transition to PendingChannelOpen if we have sufficient HTLCs
		if total_expected_outbound_amount_msat >= expected_payment_size_msat
			&& amt_to_forward_msat > 0
		{
			let new_state = Box::new(PendingChannelOpenState {
				channel_manager: self.channel_manager,
				opening_fee_msat,
				counterparty_node_id: self.counterparty_node_id,
			});
			let event_queue_notifier = self.pending_events.notifier();
			let event = LSPS2ServiceEvent::OpenChannel {
				their_network_key: self.counterparty_node_id.clone(),
				amt_to_forward_msat,
				opening_fee_msat,
				user_channel_id,
				intercept_scid,
			};
			event_queue_notifier.enqueue(event);
			Ok(new_state)
		} else if mpp_mode {
			Ok(self)
		} else {
			Err(APIError::APIMisuseError {
				err: "Intercepted HTLC is too small to pay opening fee".to_string(),
			})
		}
	}

	fn is_pending_initial_payment(&self) -> bool {
		true
	}

	fn is_prunable(&self, opening_fee_params: &LSPS2OpeningFeeParams) -> bool {
		is_expired_opening_fee_params(opening_fee_params)
	}

	fn htlc_handling_failed(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}

	fn payment_forwarded(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}

	fn channel_ready(
		self: Box<Self>, _channel_id: ChannelId, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}
}

/// State 2: Channel is being opened, waiting for it to become ready
/// Transitions to: PendingPaymentForward (when channel ready)
struct PendingChannelOpenState<CM: Deref + 'static>
where
	CM::Target: AChannelManager,
{
	channel_manager: CM,
	opening_fee_msat: u64,
	counterparty_node_id: PublicKey,
}

impl<CM: Deref + 'static> JITChannelState for PendingChannelOpenState<CM>
where
	CM::Target: AChannelManager,
{
	fn htlc_intercepted(
		self: Box<Self>, _opening_fee_params: &LSPS2OpeningFeeParams,
		_payment_size_msat: &Option<u64>, htlc: InterceptedHTLC, payment_queue: &mut PaymentQueue,
		_intercept_scid: u64, _user_channel_id: u128,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		payment_queue.add_htlc(htlc);
		Ok(self)
	}

	fn channel_ready(
		self: Box<Self>, channel_id: ChannelId, payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		if let Some((_payment_hash, htlcs)) =
			payment_queue.pop_greater_than_msat(self.opening_fee_msat)
		{
			let amounts_to_forward_msat =
				calculate_amount_to_forward_per_htlc(&htlcs, self.opening_fee_msat);

			for (intercept_id, amount_to_forward_msat) in amounts_to_forward_msat {
				self.channel_manager.get_cm().forward_intercepted_htlc(
					intercept_id,
					&channel_id,
					self.counterparty_node_id,
					amount_to_forward_msat,
				)?;
			}

			let new_state = Box::new(PendingPaymentForwardState {
				channel_manager: self.channel_manager,
				opening_fee_msat: self.opening_fee_msat,
				channel_id,
				counterparty_node_id: self.counterparty_node_id,
			});
			Ok(new_state)
		} else {
			Err(APIError::APIMisuseError {
				err: "No forwardable payment available when moving to channel ready.".to_string(),
			})
		}
	}

	fn htlc_handling_failed(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}

	fn payment_forwarded(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}
}

/// State 3: Channel is ready, payment is being forwarded with fee deduction
/// Transitions to: PaymentForwarded (when payment succeeds) or PendingPayment (when payment fails)
struct PendingPaymentForwardState<CM: Deref + 'static>
where
	CM::Target: AChannelManager,
{
	channel_manager: CM,
	opening_fee_msat: u64,
	channel_id: ChannelId,
	counterparty_node_id: PublicKey,
}

impl<CM: Deref + 'static> JITChannelState for PendingPaymentForwardState<CM>
where
	CM::Target: AChannelManager,
{
	fn htlc_handling_failed(
		self: Box<Self>, payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		if let Some((_payment_hash, htlcs)) =
			payment_queue.pop_greater_than_msat(self.opening_fee_msat)
		{
			let amounts_to_forward_msat =
				calculate_amount_to_forward_per_htlc(&htlcs, self.opening_fee_msat);

			for (intercept_id, amount_to_forward_msat) in amounts_to_forward_msat {
				self.channel_manager.get_cm().forward_intercepted_htlc(
					intercept_id,
					&self.channel_id,
					self.counterparty_node_id,
					amount_to_forward_msat,
				)?;
			}
			Ok(self)
		} else {
			let new_state = Box::new(PendingPaymentState {
				channel_manager: self.channel_manager,
				opening_fee_msat: self.opening_fee_msat,
				channel_id: self.channel_id,
				counterparty_node_id: self.counterparty_node_id,
			});
			Ok(new_state)
		}
	}

	fn payment_forwarded(
		self: Box<Self>, payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		let htlcs = payment_queue.clear();

		if !htlcs.is_empty() {
			for htlc in htlcs {
				self.channel_manager.get_cm().forward_intercepted_htlc(
					htlc.intercept_id,
					&self.channel_id,
					self.counterparty_node_id,
					htlc.expected_outbound_amount_msat,
				)?;
			}
		}

		let new_state = Box::new(PaymentForwardedState {
			channel_manager: self.channel_manager,
			channel_id: self.channel_id,
			counterparty_node_id: self.counterparty_node_id,
		});
		Ok(new_state)
	}

	fn get_channel_id(&self) -> Option<ChannelId> {
		Some(self.channel_id)
	}

	fn htlc_intercepted(
		self: Box<Self>, _opening_fee_params: &LSPS2OpeningFeeParams,
		_payment_size_msat: &Option<u64>, htlc: InterceptedHTLC, payment_queue: &mut PaymentQueue,
		_intercept_scid: u64, _user_channel_id: u128,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		payment_queue.add_htlc(htlc);
		Ok(self)
	}

	fn channel_ready(
		self: Box<Self>, _channel_id: ChannelId, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}
}

/// State 4: Channel is ready but fee hasn't been paid yet, waiting for sufficient payment
/// Transitions to: PendingPaymentForward (when sufficient payment arrives)
struct PendingPaymentState<CM: Deref + 'static>
where
	CM::Target: AChannelManager,
{
	channel_manager: CM,
	opening_fee_msat: u64,
	channel_id: ChannelId,
	counterparty_node_id: PublicKey,
}

impl<CM: Deref + 'static> JITChannelState for PendingPaymentState<CM>
where
	CM::Target: AChannelManager,
{
	fn htlc_intercepted(
		self: Box<Self>, _opening_fee_params: &LSPS2OpeningFeeParams,
		_payment_size_msat: &Option<u64>, htlc: InterceptedHTLC, payment_queue: &mut PaymentQueue,
		_intercept_scid: u64, _user_channel_id: u128,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		payment_queue.add_htlc(htlc);
		if let Some((_payment_hash, htlcs)) =
			payment_queue.pop_greater_than_msat(self.opening_fee_msat)
		{
			let amounts_to_forward_msat =
				calculate_amount_to_forward_per_htlc(&htlcs, self.opening_fee_msat);

			for (intercept_id, amount_to_forward_msat) in amounts_to_forward_msat {
				self.channel_manager.get_cm().forward_intercepted_htlc(
					intercept_id,
					&self.channel_id,
					self.counterparty_node_id,
					amount_to_forward_msat,
				)?;
			}

			let new_state = Box::new(PendingPaymentForwardState {
				channel_manager: self.channel_manager,
				opening_fee_msat: self.opening_fee_msat,
				channel_id: self.channel_id,
				counterparty_node_id: self.counterparty_node_id,
			});
			Ok(new_state)
		} else {
			// Not enough payment yet, stay in same state
			Ok(self)
		}
	}

	fn get_channel_id(&self) -> Option<ChannelId> {
		Some(self.channel_id)
	}

	fn htlc_handling_failed(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}

	fn payment_forwarded(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}

	fn channel_ready(
		self: Box<Self>, _channel_id: ChannelId, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}
}

/// State 5: Fee has been paid, all future payments forward normally
/// This is the terminal state - no transitions out
struct PaymentForwardedState<CM: Deref + 'static>
where
	CM::Target: AChannelManager,
{
	channel_manager: CM,
	channel_id: ChannelId,
	counterparty_node_id: PublicKey,
}

impl<CM: Deref + 'static> JITChannelState for PaymentForwardedState<CM>
where
	CM::Target: AChannelManager,
{
	fn htlc_intercepted(
		self: Box<Self>, _opening_fee_params: &LSPS2OpeningFeeParams,
		_payment_size_msat: &Option<u64>, htlc: InterceptedHTLC, _payment_queue: &mut PaymentQueue,
		_intercept_scid: u64, _user_channel_id: u128,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		self.channel_manager.get_cm().forward_intercepted_htlc(
			htlc.intercept_id,
			&self.channel_id,
			self.counterparty_node_id,
			htlc.expected_outbound_amount_msat,
		)?;
		Ok(self)
	}

	fn get_channel_id(&self) -> Option<ChannelId> {
		Some(self.channel_id)
	}

	fn htlc_handling_failed(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}

	fn payment_forwarded(
		self: Box<Self>, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}

	fn channel_ready(
		self: Box<Self>, _channel_id: ChannelId, _payment_queue: &mut PaymentQueue,
	) -> Result<Box<dyn JITChannelState>, APIError> {
		Ok(self)
	}
}

fn calculate_amount_to_forward_per_htlc(
	htlcs: &[InterceptedHTLC], total_fee_msat: u64,
) -> Vec<(InterceptId, u64)> {
	// TODO: we should eventually make sure the HTLCs are all above ChannelDetails::next_outbound_minimum_msat
	let total_expected_outbound_msat: u64 =
		htlcs.iter().map(|htlc| htlc.expected_outbound_amount_msat).sum();
	if total_fee_msat > total_expected_outbound_msat {
		debug_assert!(false, "Fee is larger than the total expected outbound amount.");
		return Vec::new();
	}

	let mut fee_remaining_msat = total_fee_msat;
	let mut per_htlc_forwards = vec![];
	for (index, htlc) in htlcs.iter().enumerate() {
		let proportional_fee_amt_msat = (total_fee_msat as u128
			* htlc.expected_outbound_amount_msat as u128
			/ total_expected_outbound_msat as u128) as u64;

		let mut actual_fee_amt_msat = core::cmp::min(fee_remaining_msat, proportional_fee_amt_msat);
		actual_fee_amt_msat =
			core::cmp::min(actual_fee_amt_msat, htlc.expected_outbound_amount_msat);
		fee_remaining_msat -= actual_fee_amt_msat;

		if index == htlcs.len() - 1 {
			actual_fee_amt_msat += fee_remaining_msat;
		}

		let amount_to_forward_msat =
			htlc.expected_outbound_amount_msat.saturating_sub(actual_fee_amt_msat);

		per_htlc_forwards.push((htlc.intercept_id, amount_to_forward_msat))
	}
	per_htlc_forwards
}

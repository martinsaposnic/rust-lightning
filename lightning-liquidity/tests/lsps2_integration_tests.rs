#![cfg(all(test, feature = "std"))]

mod common;

use common::create_service_and_client_nodes;
use common::{get_lsps_message, Node};

use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps0::ser::LSPSMessage;
use lightning_liquidity::lsps0::ser::LSPSRequestId;
use lightning_liquidity::lsps0::ser::LSPSResponseError;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::event::LSPS2ClientEvent;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;
use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams;
use lightning_liquidity::lsps2::msgs::{LSPS2Message, LSPS2Response};
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::lsps2::utils::is_valid_opening_fee_params;
use serde_json;

use lightning::ln::channelmanager::{InterceptId, MIN_FINAL_CLTV_EXPIRY_DELTA};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::types::ChannelId;
use lightning::log_error;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::util::errors::APIError;
use lightning::util::logger::Logger;

use lightning_invoice::{Bolt11Invoice, InvoiceBuilder, RoutingFees};

use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};
use lightning_types::payment::PaymentHash;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;

use std::str::FromStr;
use std::time::Duration;

const MAX_PENDING_REQUESTS_PER_PEER: usize = 10;
const MAX_TOTAL_PENDING_REQUESTS: usize = 1000;

fn setup_test_lsps2(
	persist_dir: &str,
) -> (bitcoin::secp256k1::PublicKey, bitcoin::secp256k1::PublicKey, Node, Node, [u8; 32]) {
	let promise_secret = [42; 32];
	let signing_key = SecretKey::from_slice(&promise_secret).unwrap();
	let lsps2_service_config = LSPS2ServiceConfig { promise_secret };
	let service_config = LiquidityServiceConfig {
		#[cfg(lsps1_service)]
		lsps1_service_config: None,
		lsps2_service_config: Some(lsps2_service_config),
		advertise_service: true,
	};

	let lsps2_client_config = LSPS2ClientConfig::default();
	let client_config = LiquidityClientConfig {
		lsps1_client_config: None,
		lsps2_client_config: Some(lsps2_client_config),
	};

	let (service_node, client_node) =
		create_service_and_client_nodes(persist_dir, service_config, client_config);

	let secp = bitcoin::secp256k1::Secp256k1::new();
	let service_node_id = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &signing_key);
	let client_node_id = client_node.channel_manager.get_our_node_id();

	(service_node_id, client_node_id, service_node, client_node, promise_secret)
}

fn create_jit_invoice(
	node: &Node, service_node_id: PublicKey, intercept_scid: u64, cltv_expiry_delta: u32,
	payment_size_msat: Option<u64>, description: &str, expiry_secs: u32,
) -> Result<Bolt11Invoice, ()> {
	// LSPS2 requires min_final_cltv_expiry_delta to be at least 2 more than usual.
	let min_final_cltv_expiry_delta = MIN_FINAL_CLTV_EXPIRY_DELTA + 2;
	let (payment_hash, payment_secret) = node
		.channel_manager
		.create_inbound_payment(None, expiry_secs, Some(min_final_cltv_expiry_delta))
		.map_err(|e| {
			log_error!(node.logger, "Failed to register inbound payment: {:?}", e);
			()
		})?;

	let route_hint = RouteHint(vec![RouteHintHop {
		src_node_id: service_node_id,
		short_channel_id: intercept_scid,
		fees: RoutingFees { base_msat: 0, proportional_millionths: 0 },
		cltv_expiry_delta: cltv_expiry_delta as u16,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]);

	let payment_hash = sha256::Hash::from_slice(&payment_hash.0).map_err(|e| {
		log_error!(node.logger, "Invalid payment hash: {:?}", e);
		()
	})?;

	let currency = Network::Bitcoin.into();
	let mut invoice_builder = InvoiceBuilder::new(currency)
		.description(description.to_string())
		.payment_hash(payment_hash)
		.payment_secret(payment_secret)
		.current_timestamp()
		.min_final_cltv_expiry_delta(min_final_cltv_expiry_delta.into())
		.expiry_time(Duration::from_secs(expiry_secs.into()))
		.private_route(route_hint);

	if let Some(amount_msat) = payment_size_msat {
		invoice_builder = invoice_builder.amount_milli_satoshis(amount_msat).basic_mpp();
	}

	invoice_builder
		.build_signed(|hash| {
			Secp256k1::new().sign_ecdsa_recoverable(hash, &node.keys_manager.get_node_secret_key())
		})
		.map_err(|e| {
			log_error!(node.logger, "Failed to build and sign invoice: {}", e);
			()
		})
}

#[test]
fn invoice_generation_flow() {
	let (service_node_id, client_node_id, service_node, client_node, promise_secret) =
		setup_test_lsps2("invoice_generation_flow");

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo {
		request_id,
		counterparty_node_id,
		token,
	}) = get_info_event
	{
		assert_eq!(request_id, get_info_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(token, None);
	} else {
		panic!("Unexpected event");
	}

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 100,
		proportional: 21,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 100_000_000,
	};

	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();
	let get_info_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let opening_params_event = client_node.liquidity_manager.next_event().unwrap();
	let opening_fee_params = match opening_params_event {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			request_id,
			counterparty_node_id,
			opening_fee_params_menu,
		}) => {
			assert_eq!(request_id, get_info_request_id);
			assert_eq!(counterparty_node_id, service_node_id);
			let opening_fee_params = opening_fee_params_menu.first().unwrap().clone();
			assert!(is_valid_opening_fee_params(&opening_fee_params, &promise_secret));
			opening_fee_params
		},
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
		.unwrap();

	let buy_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

	let buy_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::BuyRequest {
		request_id,
		counterparty_node_id,
		opening_fee_params: ofp,
		payment_size_msat: psm,
	}) = buy_event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(opening_fee_params, ofp);
		assert_eq!(payment_size_msat, psm);
	} else {
		panic!("Unexpected event");
	}

	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid = service_node.channel_manager.get_intercept_scid();
	let client_trusts_lsp = true;

	service_handler
		.invoice_parameters_generated(
			&client_node_id,
			buy_request_id.clone(),
			intercept_scid,
			cltv_expiry_delta,
			client_trusts_lsp,
			user_channel_id,
		)
		.unwrap();

	let buy_response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(buy_response, service_node_id).unwrap();

	let invoice_params_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::InvoiceParametersReady {
		request_id,
		counterparty_node_id,
		intercept_scid: iscid,
		cltv_expiry_delta: ced,
		payment_size_msat: psm,
	}) = invoice_params_event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(intercept_scid, iscid);
		assert_eq!(cltv_expiry_delta, ced);
		assert_eq!(payment_size_msat, psm);
	} else {
		panic!("Unexpected event");
	}

	let description = "asdf";
	let expiry_secs = 3600;
	let _invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		description,
		expiry_secs,
	)
	.unwrap();
}

#[test]
fn channel_open_failed() {
	let (service_node_id, client_node_id, service_node, client_node, _) =
		setup_test_lsps2("channel_open_failed");

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 100,
		proportional: 21,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 100_000_000,
	};
	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();

	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

	let _buy_event = service_node.liquidity_manager.next_event().unwrap();
	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid = service_node.channel_manager.get_intercept_scid();
	let client_trusts_lsp = true;

	service_handler
		.invoice_parameters_generated(
			&client_node_id,
			buy_request_id.clone(),
			intercept_scid,
			cltv_expiry_delta,
			client_trusts_lsp,
			user_channel_id,
		)
		.unwrap();

	let buy_response = get_lsps_message!(service_node, client_node_id);
	client_node.liquidity_manager.handle_custom_message(buy_response, service_node_id).unwrap();
	let _invoice_params_event = client_node.liquidity_manager.next_event().unwrap();

	// Test calling channel_open_failed in invalid state (before HTLC interception)
	let result = service_handler.channel_open_failed(&client_node_id, user_channel_id);
	assert!(result.is_err());
	match result.unwrap_err() {
		APIError::APIMisuseError { err } => {
			assert!(err.contains("Channel is not in the PendingChannelOpen state."));
		},
		other => panic!("Unexpected error type: {:?}", other),
	}

	let htlc_amount_msat = 1_000_000;
	let intercept_id = InterceptId([0; 32]);
	let payment_hash = PaymentHash([1; 32]);

	// This should trigger an OpenChannel event
	service_handler
		.htlc_intercepted(intercept_scid, intercept_id, htlc_amount_msat, payment_hash)
		.unwrap();

	let _ = match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			user_channel_id: channel_id,
			intercept_scid: scid,
			..
		}) => {
			assert_eq!(channel_id, user_channel_id);
			assert_eq!(scid, intercept_scid);
			true
		},
		_ => panic!("Expected OpenChannel event"),
	};

	service_handler.channel_open_failed(&client_node_id, user_channel_id).unwrap();

	// Verify we can restart the flow with another HTLC
	let new_intercept_id = InterceptId([1; 32]);
	service_handler
		.htlc_intercepted(intercept_scid, new_intercept_id, htlc_amount_msat, payment_hash)
		.unwrap();

	// Should get another OpenChannel event which confirms the reset worked
	let _ = match service_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			user_channel_id: channel_id,
			intercept_scid: scid,
			..
		}) => {
			assert_eq!(channel_id, user_channel_id);
			assert_eq!(scid, intercept_scid);
			true
		},
		_ => panic!("Expected OpenChannel event after reset"),
	};
}

#[test]
fn channel_open_failed_nonexistent_channel() {
	let (_, client_node_id, service_node, _, _) =
		setup_test_lsps2("channel_open_failed_nonexistent_channel");

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	// Call channel_open_failed with a nonexistent user_channel_id
	let nonexistent_user_channel_id = 999;
	let result = service_handler.channel_open_failed(&client_node_id, nonexistent_user_channel_id);

	assert!(result.is_err());
	match result.unwrap_err() {
		APIError::APIMisuseError { err } => {
			assert!(err.contains("No counterparty state for"));
		},
		other => panic!("Unexpected error type: {:?}", other),
	}
}

#[test]
fn channel_open_abandoned() {
	let (service_node_id, client_node_id, service_node, client_node, _) =
		setup_test_lsps2("channel_open_abandoned");

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	// Set up a JIT channel
	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();
	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 100,
		proportional: 21,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 100_000_000,
	};
	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();

	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params.clone())
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id).unwrap();

	let _buy_event = service_node.liquidity_manager.next_event().unwrap();
	let user_channel_id = 42;
	let cltv_expiry_delta = 144;
	let intercept_scid = service_node.channel_manager.get_intercept_scid();
	let client_trusts_lsp = true;

	service_handler
		.invoice_parameters_generated(
			&client_node_id,
			buy_request_id.clone(),
			intercept_scid,
			cltv_expiry_delta,
			client_trusts_lsp,
			user_channel_id,
		)
		.unwrap();

	// Call channel_open_abandoned
	service_handler.channel_open_abandoned(&client_node_id, user_channel_id).unwrap();

	// Verify the channel is gone by trying to abandon it again, which should fail
	let result = service_handler.channel_open_abandoned(&client_node_id, user_channel_id);
	assert!(result.is_err());
}

#[test]
fn channel_open_abandoned_nonexistent_channel() {
	let (_, client_node_id, service_node, _, _) =
		setup_test_lsps2("channel_open_abandoned_nonexistent_channel");
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	// Call channel_open_abandoned with a nonexistent user_channel_id
	let nonexistent_user_channel_id = 999;
	let result =
		service_handler.channel_open_abandoned(&client_node_id, nonexistent_user_channel_id);
	assert!(result.is_err());
	match result.unwrap_err() {
		APIError::APIMisuseError { err } => {
			assert!(err.contains("No counterparty state for"));
		},
		other => panic!("Unexpected error type: {:?}", other),
	}
}

#[test]
fn max_pending_requests_per_peer_rejected() {
	let (service_node_id, client_node_id, service_node, client_node, _) =
		setup_test_lsps2("max_pending_requests_per_peer_rejected");

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	for _ in 0..MAX_PENDING_REQUESTS_PER_PEER {
		let _ = client_handler.request_opening_params(service_node_id, None);
		let req_msg = get_lsps_message!(client_node, service_node_id);
		let result = service_node.liquidity_manager.handle_custom_message(req_msg, client_node_id);
		assert!(result.is_ok());
		let event = service_node.liquidity_manager.next_event().unwrap();
		match event {
			LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { .. }) => {},
			_ => panic!("Unexpected event"),
		}
	}

	// Test per-peer limit: the next request should be rejected
	let rejected_req_id = client_handler.request_opening_params(service_node_id, None);
	let rejected_req_msg = get_lsps_message!(client_node, service_node_id);

	let result =
		service_node.liquidity_manager.handle_custom_message(rejected_req_msg, client_node_id);
	assert!(result.is_err(), "We should have hit the per-peer limit");

	let get_info_error_response = get_lsps_message!(service_node, client_node_id);
	let result = client_node
		.liquidity_manager
		.handle_custom_message(get_info_error_response, service_node_id);
	assert!(result.is_err());

	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::GetInfoFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, rejected_req_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 1); // LSPS0_CLIENT_REJECTED_ERROR_CODE
	} else {
		panic!("Expected LSPS2ClientEvent::GetInfoFailed event");
	}
}

#[test]
fn max_total_requests_buy_rejected() {
	let (service_node_id, _, service_node, client_node, _) =
		setup_test_lsps2("max_total_requests_buy_rejected");

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let secp = Secp256k1::new();

	let special_sk_bytes = [99u8; 32];
	let special_sk = SecretKey::from_slice(&special_sk_bytes).unwrap();
	let special_node_id = PublicKey::from_secret_key(&secp, &special_sk);

	let _ = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node
		.liquidity_manager
		.handle_custom_message(get_info_request, special_node_id)
		.unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { request_id, .. }) =
		get_info_event
	{
		let raw_opening_params = LSPS2RawOpeningFeeParams {
			min_fee_msat: 100,
			proportional: 21,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 144,
			max_client_to_self_delay: 128,
			min_payment_size_msat: 1,
			max_payment_size_msat: 100_000_000,
		};

		service_handler
			.opening_fee_params_generated(&special_node_id, request_id, vec![raw_opening_params])
			.unwrap();
	} else {
		panic!("Unexpected event");
	}

	let get_info_response = get_lsps_message!(service_node, special_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let opening_params_event = client_node.liquidity_manager.next_event().unwrap();
	let opening_fee_params = match opening_params_event {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	// Now fill up the global limit with additional GetInfo requests from other peers
	let mut filled = 0;
	let mut peer_idx = 0;

	while filled < MAX_TOTAL_PENDING_REQUESTS {
		let sk_bytes = [peer_idx as u8 + 1; 32];
		let sk = SecretKey::from_slice(&sk_bytes).unwrap();
		let peer_node_id = PublicKey::from_secret_key(&secp, &sk);

		// Skip if this is our special node
		if peer_node_id == special_node_id {
			peer_idx += 1;
			continue;
		}

		for _ in 0..MAX_PENDING_REQUESTS_PER_PEER {
			if filled >= MAX_TOTAL_PENDING_REQUESTS {
				break;
			}

			let _ = client_handler.request_opening_params(service_node_id, None);
			let req_msg = get_lsps_message!(client_node, service_node_id);
			let result =
				service_node.liquidity_manager.handle_custom_message(req_msg, peer_node_id);
			assert!(result.is_ok());

			let event = service_node.liquidity_manager.next_event().unwrap();
			match event {
				LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { .. }) => {},
				_ => panic!("Unexpected event"),
			}

			filled += 1;
		}
		peer_idx += 1;
	}

	// Now try to send a Buy request with our special node, which should be rejected
	let payment_size_msat = Some(1_000_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params)
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);

	let result = service_node.liquidity_manager.handle_custom_message(buy_request, special_node_id);
	assert!(result.is_err(), "The Buy request should have been rejected");

	let buy_error_response = get_lsps_message!(service_node, special_node_id);
	let result =
		client_node.liquidity_manager.handle_custom_message(buy_error_response, service_node_id);
	assert!(result.is_err());

	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::BuyRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 1); // LSPS0_CLIENT_REJECTED_ERROR_CODE
	} else {
		panic!("Expected LSPS2ClientEvent::BuyRequestFailed event");
	}
}

#[test]
fn invalid_token_flow() {
	let (service_node_id, client_node_id, service_node, client_node, _promise_secret) =
		setup_test_lsps2("invalid_token_flow");

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let token = Some("invalid_token".to_string());
	let get_info_request_id = client_handler.request_opening_params(service_node_id, token);
	let get_info_request = get_lsps_message!(client_node, service_node_id);

	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo {
		request_id,
		counterparty_node_id,
		token,
	}) = get_info_event
	{
		assert_eq!(request_id, get_info_request_id);
		assert_eq!(counterparty_node_id, client_node_id);
		assert_eq!(token, Some("invalid_token".to_string()));

		// Service rejects the token as invalid
		service_handler.invalid_token_provided(&client_node_id, request_id.clone()).unwrap();

		// Attempt to respond to the same request again which should fail
		// because the request has been removed from pending_requests
		let raw_opening_params = LSPS2RawOpeningFeeParams {
			min_fee_msat: 100,
			proportional: 21,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 144,
			max_client_to_self_delay: 128,
			min_payment_size_msat: 1,
			max_payment_size_msat: 100_000_000,
		};

		let result = service_handler.opening_fee_params_generated(
			&client_node_id,
			request_id.clone(),
			vec![raw_opening_params],
		);

		assert!(result.is_err(), "Request should have been removed from pending_requests");
	} else {
		panic!("Unexpected event");
	}

	let get_info_error_response = get_lsps_message!(service_node, client_node_id);

	client_node
		.liquidity_manager
		.handle_custom_message(get_info_error_response, service_node_id)
		.unwrap_err();

	let error_event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::GetInfoFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = error_event
	{
		assert_eq!(request_id, get_info_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 200); // LSPS2_GET_INFO_REQUEST_UNRECOGNIZED_OR_STALE_TOKEN_ERROR_CODE
	} else {
		panic!("Expected LSPS2ClientEvent::GetInfoFailed event");
	}
}

#[test]
fn buy_request_payment_size_below_min() {
	let (service_node_id, client_node_id, service_node, client_node, _) =
		setup_test_lsps2("buy_request_payment_size_below_min");
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();
	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 100,
		proportional: 0,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1000,
		max_payment_size_msat: 1_000_000,
	};
	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();
	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(500);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params)
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);

	let result = service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id);
	assert!(result.is_err());
	let buy_error_response = get_lsps_message!(service_node, client_node_id);
	let result =
		client_node.liquidity_manager.handle_custom_message(buy_error_response, service_node_id);
	assert!(result.is_err());
	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::BuyRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 202);
	} else {
		panic!("Expected BuyRequestFailed event");
	}
}

#[test]
fn buy_request_payment_size_above_max() {
	let (service_node_id, client_node_id, service_node, client_node, _) =
		setup_test_lsps2("buy_request_payment_size_above_max");
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();
	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 100,
		proportional: 0,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1000,
		max_payment_size_msat: 2_000,
	};
	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();
	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();
	let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(5_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params)
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);

	let result = service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id);
	assert!(result.is_err());
	let buy_error_response = get_lsps_message!(service_node, client_node_id);
	let result =
		client_node.liquidity_manager.handle_custom_message(buy_error_response, service_node_id);
	assert!(result.is_err());
	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::BuyRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 203);
	} else {
		panic!("Expected BuyRequestFailed event");
	}
}

#[test]
fn buy_request_insufficient_for_fee() {
	let (service_node_id, client_node_id, service_node, client_node, _) =
		setup_test_lsps2("buy_request_insufficient_for_fee");
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();
	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 10_000,
		proportional: 0,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 20_000,
	};
	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();
	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();
	let opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	let payment_size_msat = Some(5_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params)
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);

	let result = service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id);
	assert!(result.is_err());
	let buy_error_response = get_lsps_message!(service_node, client_node_id);
	let result =
		client_node.liquidity_manager.handle_custom_message(buy_error_response, service_node_id);
	assert!(result.is_err());
	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::BuyRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 202);
	} else {
		panic!("Expected BuyRequestFailed event");
	}
}

#[test]
fn buy_request_invalid_opening_fee_params() {
	let (service_node_id, client_node_id, service_node, client_node, _) =
		setup_test_lsps2("buy_request_invalid_opening_fee_params");
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();
	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();

	let get_info_request_id = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();
	let _get_info_event = service_node.liquidity_manager.next_event().unwrap();

	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat: 100,
		proportional: 0,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 10_000,
	};
	service_handler
		.opening_fee_params_generated(
			&client_node_id,
			get_info_request_id.clone(),
			vec![raw_opening_params],
		)
		.unwrap();
	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();
	let mut opening_fee_params = match client_node.liquidity_manager.next_event().unwrap() {
		LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
			opening_fee_params_menu,
			..
		}) => opening_fee_params_menu.first().unwrap().clone(),
		_ => panic!("Unexpected event"),
	};

	opening_fee_params.promise = "deadbeef".to_string();
	let payment_size_msat = Some(5_000);
	let buy_request_id = client_handler
		.select_opening_params(service_node_id, payment_size_msat, opening_fee_params)
		.unwrap();
	let buy_request = get_lsps_message!(client_node, service_node_id);

	let result = service_node.liquidity_manager.handle_custom_message(buy_request, client_node_id);
	assert!(result.is_err());
	let buy_error_response = get_lsps_message!(service_node, client_node_id);
	let result =
		client_node.liquidity_manager.handle_custom_message(buy_error_response, service_node_id);
	assert!(result.is_err());
	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::BuyRequestFailed {
		request_id,
		counterparty_node_id,
		error,
	}) = event
	{
		assert_eq!(request_id, buy_request_id);
		assert_eq!(counterparty_node_id, service_node_id);
		assert_eq!(error.code, 201);
	} else {
		panic!("Expected BuyRequestFailed event");
	}
}
#[test]
fn channel_ready_unknown_counterparty() {
	let (_service_node_id, client_node_id, service_node, _client_node, _) =
		setup_test_lsps2("channel_ready_unknown_counterparty");

	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let channel_id = ChannelId([1; 32]);
	let result = service_handler.channel_ready(0, &channel_id, &client_node_id);
	assert!(result.is_err());
	match result.unwrap_err() {
		APIError::APIMisuseError { err } => {
			assert!(err.contains("No counterparty state for"));
		},
		other => panic!("Unexpected error type: {:?}", other),
	}
}

#[test]
fn client_get_info_error_unknown_request() {
	let (service_node_id, _client_node_id, _service_node, client_node, _) =
		setup_test_lsps2("client_get_info_error_unknown_request");

	let error = LSPSResponseError { code: 1, message: "oops".to_string(), data: None };
	let request_id = LSPSRequestId("deadbeef".to_string());
	let msg = lightning_liquidity::lsps0::ser::RawLSPSMessage {
		payload: serde_json::to_string(&LSPSMessage::from(LSPS2Message::Response(
			request_id,
			LSPS2Response::GetInfoError(error),
		)))
		.unwrap(),
	};
	let result = client_node.liquidity_manager.handle_custom_message(msg, service_node_id);
	assert!(result.is_err());
}

#[test]
fn client_buy_error_unknown_request() {
	let (service_node_id, _client_node_id, _service_node, client_node, _) =
		setup_test_lsps2("client_buy_error_unknown_request");

	let error = LSPSResponseError { code: 1, message: "oops".to_string(), data: None };
	let request_id = LSPSRequestId("deadbeef".to_string());
	let msg = lightning_liquidity::lsps0::ser::RawLSPSMessage {
		payload: serde_json::to_string(&LSPSMessage::from(LSPS2Message::Response(
			request_id,
			LSPS2Response::BuyError(error),
		)))
		.unwrap(),
	};
	let result = client_node.liquidity_manager.handle_custom_message(msg, service_node_id);
	assert!(result.is_err());
}

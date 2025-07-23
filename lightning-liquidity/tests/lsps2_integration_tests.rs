#![cfg(all(test, feature = "std"))]

mod common;

use common::{create_service_and_client_nodes, get_lsps_message, LSPSNodes, LiquidityNode};

use lightning::check_added_monitors;
use lightning::events::Event;
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::channelmanager::Retry;
use lightning::ln::functional_test_utils::create_chan_between_nodes_with_value;
use lightning::ln::functional_test_utils::do_commitment_signed_dance;
use lightning::ln::functional_test_utils::expect_payment_sent;
use lightning::ln::functional_test_utils::pass_claimed_payment_along_route;
use lightning::ln::functional_test_utils::test_default_channel_config;
use lightning::ln::functional_test_utils::ClaimAlongRouteArgs;
use lightning::ln::functional_test_utils::SendEvent;
use lightning::ln::msgs::BaseMessageHandler;
use lightning::ln::msgs::ChannelMessageHandler;
use lightning_liquidity::events::LiquidityEvent;
use lightning_liquidity::lsps0::ser::LSPSDateTime;
use lightning_liquidity::lsps2::client::LSPS2ClientConfig;
use lightning_liquidity::lsps2::event::LSPS2ClientEvent;
use lightning_liquidity::lsps2::event::LSPS2ServiceEvent;
use lightning_liquidity::lsps2::msgs::LSPS2RawOpeningFeeParams;
use lightning_liquidity::lsps2::service::LSPS2ServiceConfig;
use lightning_liquidity::lsps2::utils::is_valid_opening_fee_params;
use lightning_liquidity::{LiquidityClientConfig, LiquidityServiceConfig};

use lightning::ln::channelmanager::{InterceptId, MIN_FINAL_CLTV_EXPIRY_DELTA};
use lightning::ln::functional_test_utils::{
	create_chanmon_cfgs, create_node_cfgs, create_node_chanmgrs,
};
use lightning::ln::functional_test_utils::{create_network, Node};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::log_error;
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::sign::NodeSigner;
use lightning::util::errors::APIError;
use lightning::util::logger::Logger;

use lightning_invoice::{Bolt11Invoice, InvoiceBuilder, RoutingFees};

use lightning_types::payment::PaymentHash;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;

use std::str::FromStr;
use std::time::Duration;

const MAX_PENDING_REQUESTS_PER_PEER: usize = 10;
const MAX_TOTAL_PENDING_REQUESTS: usize = 1000;

fn setup_test_lsps2_nodes<'a, 'b, 'c>(
	nodes: Vec<Node<'a, 'b, 'c>>,
) -> (LSPSNodes<'a, 'b, 'c>, [u8; 32]) {
	let promise_secret = [42; 32];
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
	let lsps_nodes = create_service_and_client_nodes(nodes, service_config, client_config);

	(lsps_nodes, promise_secret)
}

fn create_jit_invoice(
	node: &LiquidityNode<'_, '_, '_>, service_node_id: PublicKey, intercept_scid: u64,
	cltv_expiry_delta: u32, payment_size_msat: Option<u64>, description: &str, expiry_secs: u32,
) -> Result<Bolt11Invoice, ()> {
	// LSPS2 requires min_final_cltv_expiry_delta to be at least 2 more than usual.
	let min_final_cltv_expiry_delta = MIN_FINAL_CLTV_EXPIRY_DELTA + 2;
	let (payment_hash, payment_secret) = node
		.node
		.create_inbound_payment(None, expiry_secs, Some(min_final_cltv_expiry_delta))
		.map_err(|e| {
			log_error!(node.logger, "Failed to register inbound payment: {:?}", e);
		})?;

	// Add debugging here
	println!("Creating route hint with intercept_scid: {}", intercept_scid);
	println!("Service node ID: {}", service_node_id);

	let route_hint = RouteHint(vec![RouteHintHop {
		src_node_id: service_node_id,
		short_channel_id: intercept_scid,
		fees: RoutingFees { base_msat: 1000, proportional_millionths: 0 },
		cltv_expiry_delta: cltv_expiry_delta as u16,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	}]);

	let payment_hash = sha256::Hash::from_slice(&payment_hash.0).map_err(|e| {
		log_error!(node.logger, "Invalid payment hash: {:?}", e);
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

	let raw_invoice = invoice_builder.build_raw().map_err(|e| {
		log_error!(node.inner.logger, "Failed to build raw invoice: {:?}", e);
	})?;

	let sign_fn =
		node.inner.keys_manager.sign_invoice(&raw_invoice, lightning::sign::Recipient::Node);

	let invoice = raw_invoice.sign(|_| sign_fn).and_then(|signed_raw| {
		Bolt11Invoice::from_signed(signed_raw).map_err(|e| {
			log_error!(node.inner.logger, "Failed to create invoice from signed raw: {:?}", e);
		})
	})?;

	// Add debugging to verify the invoice
	println!("Created invoice with route hints: {:?}", invoice.route_hints());

	Ok(invoice)
}

#[test]
fn invoice_generation_flow() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

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
	let intercept_scid = service_node.node.get_intercept_scid();
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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

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
	let intercept_scid = service_node.node.get_intercept_scid();
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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;

	let client_node_id = client_node.inner.node.get_our_node_id();

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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

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
	let intercept_scid = service_node.node.get_intercept_scid();
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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;

	let client_node_id = client_node.inner.node.get_our_node_id();
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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();

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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;

	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();
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
fn opening_fee_params_menu_is_sorted_by_spec() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, _) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, .. } = lsps_nodes;
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	let _ = client_handler.request_opening_params(service_node_id, None);
	let get_info_request = get_lsps_message!(client_node, service_node_id);
	service_node.liquidity_manager.handle_custom_message(get_info_request, client_node_id).unwrap();

	let get_info_event = service_node.liquidity_manager.next_event().unwrap();
	let request_id = match get_info_event {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::GetInfo { request_id, .. }) => request_id,
		_ => panic!("Unexpected event"),
	};

	let raw_params_generator = |min_fee_msat: u64, proportional: u32| LSPS2RawOpeningFeeParams {
		min_fee_msat,
		proportional,
		valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
		min_lifetime: 144,
		max_client_to_self_delay: 128,
		min_payment_size_msat: 1,
		max_payment_size_msat: 100_000_000,
	};

	let raw_params = vec![
		raw_params_generator(200, 20), // Will be sorted to position 2
		raw_params_generator(100, 10), // Will be sorted to position 0 (lowest min_fee, lowest proportional)
		raw_params_generator(300, 30), // Will be sorted to position 4 (highest min_fee, highest proportional)
		raw_params_generator(100, 20), // Will be sorted to position 1 (same min_fee as 0, higher proportional)
		raw_params_generator(200, 30), // Will be sorted to position 3 (higher min_fee than 2, higher proportional)
	];

	service_handler
		.opening_fee_params_generated(&client_node_id, request_id.clone(), raw_params)
		.unwrap();

	let get_info_response = get_lsps_message!(service_node, client_node_id);
	client_node
		.liquidity_manager
		.handle_custom_message(get_info_response, service_node_id)
		.unwrap();

	let event = client_node.liquidity_manager.next_event().unwrap();
	if let LiquidityEvent::LSPS2Client(LSPS2ClientEvent::OpeningParametersReady {
		opening_fee_params_menu,
		..
	}) = event
	{
		// The LSP, when ordering the opening_fee_params_menu array, MUST order by the following rules:
		// The 0th item MAY have any parameters.
		// Each succeeding item MUST, compared to the previous item, obey any one of the following:
		// Have a larger min_fee_msat, and equal proportional.
		// Have a larger proportional, and equal min_fee_msat.
		// Have a larger min_fee_msat, AND larger proportional.
		for (cur, next) in
			opening_fee_params_menu.iter().zip(opening_fee_params_menu.iter().skip(1))
		{
			let valid = (next.min_fee_msat > cur.min_fee_msat
				&& next.proportional == cur.proportional)
				|| (next.proportional > cur.proportional && next.min_fee_msat == cur.min_fee_msat)
				|| (next.min_fee_msat > cur.min_fee_msat && next.proportional > cur.proportional);
			assert!(valid, "Params not sorted as per spec");
		}
	} else {
		panic!("Unexpected event");
	}
}

#[test]
fn full_lsps2_flow() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut service_node_config = test_default_channel_config();
	service_node_config.accept_intercept_htlcs = true;
	let node_chanmgrs =
		create_node_chanmgrs(3, &node_cfgs, &[Some(service_node_config), None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (lsps_nodes, promise_secret) = setup_test_lsps2_nodes(nodes);
	let LSPSNodes { service_node, client_node, payer_node_optional } = lsps_nodes;
	let payer_node = payer_node_optional.unwrap();
	let payer_node_id = payer_node.node.get_our_node_id();
	let service_node_id = service_node.inner.node.get_our_node_id();
	let client_node_id = client_node.inner.node.get_our_node_id();

	let client_handler = client_node.liquidity_manager.lsps2_client_handler().unwrap();
	let service_handler = service_node.liquidity_manager.lsps2_service_handler().unwrap();

	create_chan_between_nodes_with_value(&payer_node, &service_node.inner, 2000000, 100000);

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

	let min_fee_msat = 1000;
	let raw_opening_params = LSPS2RawOpeningFeeParams {
		min_fee_msat,
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
	let intercept_scid = service_node.node.get_intercept_scid();
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
	let invoice = create_jit_invoice(
		&client_node,
		service_node_id,
		intercept_scid,
		cltv_expiry_delta,
		payment_size_msat,
		description,
		expiry_secs,
	)
	.unwrap();

	payer_node
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(invoice.payment_hash().to_byte_array()),
			None,
			Default::default(),
			Retry::Attempts(3),
		)
		.unwrap();

	check_added_monitors!(payer_node, 1);
	let events = payer_node.node.get_and_clear_pending_msg_events();
	let ev = SendEvent::from_event(events[0].clone());
	service_node.inner.node.handle_update_add_htlc(payer_node_id, &ev.msgs[0]);
	do_commitment_signed_dance(&service_node.inner, &payer_node, &ev.commitment_msg, false, true);
	service_node.inner.node.process_pending_htlc_forwards();

	let events = service_node.inner.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	let (payment_hash, expected_outbound_amount_msat) = match &events[0] {
		Event::HTLCIntercepted {
			intercept_id,
			requested_next_hop_scid,
			payment_hash,
			inbound_amount_msat,
			expected_outbound_amount_msat,
		} => {
			assert_eq!(*requested_next_hop_scid, intercept_scid);

			service_handler
				.htlc_intercepted(
					*requested_next_hop_scid,
					*intercept_id,
					*inbound_amount_msat,
					*payment_hash,
				)
				.unwrap();
			(*payment_hash, expected_outbound_amount_msat)
		},
		other => panic!("Expected HTLCIntercepted event, got: {:?}", other),
	};

	let open_channel_event = service_node.liquidity_manager.next_event().unwrap();

	match open_channel_event {
		LiquidityEvent::LSPS2Service(LSPS2ServiceEvent::OpenChannel {
			their_network_key,
			amt_to_forward_msat,
			opening_fee_msat,
			user_channel_id,
			intercept_scid: iscd,
		}) => {
			assert_eq!(their_network_key, client_node_id);
			assert_eq!(amt_to_forward_msat, payment_size_msat.unwrap() - min_fee_msat);
			assert_eq!(opening_fee_msat, min_fee_msat);
			assert_eq!(user_channel_id, 42);
			assert_eq!(iscd, intercept_scid);
		},
		other => panic!("Expected OpenChannel event, got: {:?}", other),
	};

	let (_, _, _, channel_id, _) = create_chan_between_nodes_with_value(
		&service_node.inner,
		&client_node.inner,
		*expected_outbound_amount_msat,
		0,
	);

	service_handler.channel_ready(user_channel_id, &channel_id, &client_node_id).unwrap();

	service_node.inner.node.process_pending_htlc_forwards();

	let pay_event = {
		{
			let mut added_monitors =
				service_node.inner.chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();
		}
		let mut events = service_node.inner.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};

	client_node.inner.node.handle_update_add_htlc(service_node_id, &pay_event.msgs[0]);
	do_commitment_signed_dance(
		&client_node.inner,
		&service_node.inner,
		&pay_event.commitment_msg,
		false,
		true,
	);
	client_node.inner.node.process_pending_htlc_forwards();

	let client_events = client_node.inner.node.get_and_clear_pending_events();
	assert_eq!(client_events.len(), 1);
	let preimage = match &client_events[0] {
		Event::PaymentClaimable { payment_hash: ph, purpose, .. } => {
			assert_eq!(*ph, payment_hash);
			purpose.preimage()
		},
		other => panic!("Expected PaymentClaimable event on client, got: {:?}", other),
	};

	client_node.inner.node.claim_funds(preimage.unwrap());

	let expected_paths: &[&[&lightning::ln::functional_test_utils::Node<'_, '_, '_>]] =
		&[&[&service_node.inner, &client_node.inner]];

	let args = ClaimAlongRouteArgs::new(&payer_node, expected_paths, preimage.unwrap());
	let total_fee_msat = pass_claimed_payment_along_route(args);

	expect_payment_sent(&payer_node, preimage.unwrap(), Some(Some(total_fee_msat)), true, true);
}

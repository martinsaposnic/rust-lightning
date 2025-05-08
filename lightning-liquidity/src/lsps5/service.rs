// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Service implementation for LSPS5 webhook registration.

use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSDateTime, LSPSProtocolMessageHandler, LSPSRequestId};
use crate::lsps5::msgs::{
	ListWebhooksRequest, ListWebhooksResponse, RemoveWebhookRequest, RemoveWebhookResponse,
	SetWebhookRequest, SetWebhookResponse, WebhookNotification, WebhookNotificationMethod,
};
use crate::message_queue::MessageQueue;
use crate::prelude::*;
use core::ops::Deref;
use core::time::Duration;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use lightning::ln::channelmanager::AChannelManager;
use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;
use lightning::util::message_signing;

use crate::alloc::string::ToString;
use crate::sync::{Arc, Mutex};
use alloc::string::String;
use alloc::vec::Vec;

use super::event::LSPS5ServiceEvent;
use super::msgs::{
	LSPS5AppName, LSPS5Error, LSPS5Message, LSPS5Request, LSPS5Response, LSPS5WebhookUrl,
};

/// Minimum number of days to retain webhooks after a client's last channel is closed.
pub const MIN_WEBHOOK_RETENTION_DAYS: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Interval for pruning stale webhooks.
pub const PRUNE_STALE_WEBHOOKS_INTERVAL_DAYS: Duration = Duration::from_secs(24 * 60 * 60);

/// A stored webhook.
#[derive(Debug, Clone)]
struct StoredWebhook {
	/// App name identifier for this webhook.
	_app_name: LSPS5AppName,
	/// The webhook URL.
	url: LSPS5WebhookUrl,
	/// Client node ID.
	_counterparty_node_id: PublicKey,
	/// Last time this webhook was used.
	last_used: LSPSDateTime,
	/// Map of notification methods to last time they were sent.
	last_notification_sent: HashMap<WebhookNotificationMethod, LSPSDateTime>,
}

/// Trait defining a time provider for LSPS5 service.
///
/// This trait is used to provide the current time for LSPS5 service operations
/// and to convert between timestamps and durations.
pub trait TimeProvider: Send + Sync {
	/// Get the current time as a duration since the Unix epoch.
	fn duration_since_epoch(&self) -> Duration;
}

/// Default time provider using the system clock.
#[derive(Clone, Debug)]
#[cfg(feature = "time")]
pub struct DefaultTimeProvider;

#[cfg(feature = "time")]
impl TimeProvider for DefaultTimeProvider {
	fn duration_since_epoch(&self) -> Duration {
		use std::time::{SystemTime, UNIX_EPOCH};
		SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before Unix epoch")
	}
}

/// Configuration for LSPS5 service.
#[derive(Clone)]
pub struct LSPS5ServiceConfig {
	/// Maximum number of webhooks allowed per client.
	pub max_webhooks_per_client: u32,
	/// Signing key for LSP notifications.
	pub signing_key: SecretKey,
	/// Minimum time between sending the same notification type in hours (default: 24)
	pub notification_cooldown_hours: Duration,
}

/// Default maximum number of webhooks allowed per client.
pub const DEFAULT_MAX_WEBHOOKS_PER_CLIENT: u32 = 10;
/// Default notification cooldown time in hours.
pub const DEFAULT_NOTIFICATION_COOLDOWN_HOURS: Duration = Duration::from_secs(24 * 60 * 60);

impl Default for LSPS5ServiceConfig {
	fn default() -> Self {
		Self {
			max_webhooks_per_client: DEFAULT_MAX_WEBHOOKS_PER_CLIENT,
			signing_key: SecretKey::from_slice(&[1; 32]).expect("Static key should be valid"),
			notification_cooldown_hours: DEFAULT_NOTIFICATION_COOLDOWN_HOURS,
		}
	}
}

/// Service for handling LSPS5 webhook registration
pub struct LSPS5ServiceHandler<CM: Deref>
where
	CM::Target: AChannelManager,
{
	config: LSPS5ServiceConfig,
	webhooks: Mutex<HashMap<PublicKey, HashMap<LSPS5AppName, StoredWebhook>>>,
	event_queue: Arc<EventQueue>,
	pending_messages: Arc<MessageQueue>,
	time_provider: Arc<dyn TimeProvider>,
	channel_manager: CM,
	last_pruning: Mutex<Option<LSPSDateTime>>,
}

impl<CM: Deref> LSPS5ServiceHandler<CM>
where
	CM::Target: AChannelManager,
{
	/// Create a new LSPS5 service handler.
	///
	/// # Arguments
	/// * `event_queue` - Event queue for emitting events.
	/// * `pending_messages` - Message queue for sending responses.
	/// * `client_has_open_channel` - Function that checks if a client has an open channel.
	/// * `config` - Configuration for the LSPS5 service.
	#[cfg(feature = "time")]
	pub(crate) fn new(
		event_queue: Arc<EventQueue>, pending_messages: Arc<MessageQueue>, channel_manager: CM,
		config: LSPS5ServiceConfig,
	) -> Self {
		let time_provider = Arc::new(DefaultTimeProvider);
		Self::new_with_custom_time_provider(
			event_queue,
			pending_messages,
			channel_manager,
			config,
			time_provider,
		)
	}

	/// Create a new LSPS5 service handler with a custom time provider.
	///
	/// # Arguments
	/// * `event_queue` - Event queue for emitting events.
	/// * `pending_messages` - Message queue for sending responses.
	/// * `client_has_open_channel` - Function that checks if a client has an open channel.
	/// * `config` - Configuration for the LSPS5 service.
	/// * `time_provider` - Custom time provider.
	pub(crate) fn new_with_custom_time_provider(
		event_queue: Arc<EventQueue>, pending_messages: Arc<MessageQueue>, channel_manager: CM,
		config: LSPS5ServiceConfig, time_provider: Arc<dyn TimeProvider>,
	) -> Self {
		Self {
			config,
			webhooks: Mutex::new(new_hash_map()),
			event_queue,
			pending_messages,
			time_provider,
			channel_manager,
			last_pruning: Mutex::new(None),
		}
	}

	fn check_prune_stale_webhooks(&self) -> Result<(), LightningError> {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let should_prune = {
			let last_pruning = self.last_pruning.lock().unwrap();
			last_pruning.as_ref().map_or(true, |last_time| {
				now.abs_diff(last_time.clone()) > PRUNE_STALE_WEBHOOKS_INTERVAL_DAYS.as_secs()
			})
		};

		if should_prune {
			self.prune_stale_webhooks();
		}

		Ok(())
	}

	/// Handle a set_webhook request.
	pub fn handle_set_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: SetWebhookRequest,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.event_queue.notifier();
		self.check_prune_stale_webhooks()?;

		let mut webhooks = self.webhooks.lock().unwrap();

		let client_webhooks = webhooks.entry(counterparty_node_id).or_insert_with(new_hash_map);
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		let no_change = client_webhooks
			.get(&params.app_name)
			.map_or(false, |webhook| webhook.url == params.webhook);

		if !client_webhooks.contains_key(&params.app_name)
			&& client_webhooks.len() >= self.config.max_webhooks_per_client as usize
		{
			let message = format!(
				"Maximum of {} webhooks allowed per client",
				self.config.max_webhooks_per_client
			);
			let error = LSPS5Error::TooManyWebhooks(message.clone());
			let msg =
				LSPS5Message::Response(request_id, LSPS5Response::SetWebhookError(error)).into();
			self.pending_messages.enqueue(&counterparty_node_id, msg);
			return Err(LightningError {
				err: message,
				action: ErrorAction::IgnoreAndLog(Level::Info),
			});
		}

		// Add or replace the webhook
		let stored_webhook = StoredWebhook {
			_app_name: params.app_name.clone(),
			url: params.webhook.clone(),
			_counterparty_node_id: counterparty_node_id,
			last_used: now,
			last_notification_sent: new_hash_map(),
		};

		client_webhooks.insert(params.app_name.clone(), stored_webhook);

		let response = SetWebhookResponse {
			num_webhooks: client_webhooks.len() as u32,
			max_webhooks: self.config.max_webhooks_per_client,
			no_change,
		};
		event_queue_notifier.enqueue(LSPS5ServiceEvent::WebhookRegistered {
			counterparty_node_id,
			app_name: params.app_name.clone(),
			url: params.webhook.clone(),
			request_id: request_id.clone(),
			no_change,
		});

		// Send webhook_registered notification if needed
		// According to spec:
		// "The LSP MUST send this notification to this webhook before sending any other notifications to this webhook."
		if !no_change {
			self.send_webhook_registered_notification(
				counterparty_node_id,
				params.app_name.clone(),
				params.webhook.clone(),
			)?;
		}

		let msg = LSPS5Message::Response(request_id, LSPS5Response::SetWebhook(response)).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);
		Ok(())
	}

	/// Handle a list_webhooks request.
	pub fn handle_list_webhooks(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		_params: ListWebhooksRequest,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.event_queue.notifier();
		self.check_prune_stale_webhooks()?;

		let webhooks = self.webhooks.lock().unwrap();

		let app_names = webhooks
			.get(&counterparty_node_id)
			.map(|client_webhooks| client_webhooks.keys().cloned().collect::<Vec<_>>())
			.unwrap_or_else(Vec::new);

		let max_webhooks = self.config.max_webhooks_per_client;

		event_queue_notifier.enqueue(LSPS5ServiceEvent::WebhooksListed {
			counterparty_node_id,
			app_names: app_names.clone(),
			max_webhooks,
			request_id: request_id.clone(),
		});

		let response = ListWebhooksResponse { app_names, max_webhooks };
		let msg = LSPS5Message::Response(request_id, LSPS5Response::ListWebhooks(response)).into();
		self.pending_messages.enqueue(&counterparty_node_id, msg);

		Ok(())
	}

	/// Handle a remove_webhook request.
	pub fn handle_remove_webhook(
		&self, counterparty_node_id: PublicKey, request_id: LSPSRequestId,
		params: RemoveWebhookRequest,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.event_queue.notifier();
		// Check if we need to prune stale webhooks
		self.check_prune_stale_webhooks()?;

		let mut webhooks = self.webhooks.lock().unwrap();

		if let Some(client_webhooks) = webhooks.get_mut(&counterparty_node_id) {
			if client_webhooks.remove(&params.app_name).is_some() {
				let response = RemoveWebhookResponse {};
				let msg = LSPS5Message::Response(
					request_id.clone(),
					LSPS5Response::RemoveWebhook(response),
				)
				.into();
				self.pending_messages.enqueue(&counterparty_node_id, msg);
				event_queue_notifier.enqueue(LSPS5ServiceEvent::WebhookRemoved {
					counterparty_node_id,
					app_name: params.app_name,
					request_id,
				});

				return Ok(());
			}
		}

		let error_message = format!("App name not found: {}", params.app_name);
		let error = LSPS5Error::AppNameNotFound(error_message.clone());
		let msg =
			LSPS5Message::Response(request_id, LSPS5Response::RemoveWebhookError(error)).into();

		self.pending_messages.enqueue(&counterparty_node_id, msg);
		return Err(LightningError {
			err: error_message,
			action: ErrorAction::IgnoreAndLog(Level::Info),
		});
	}

	/// Send a webhook_registered notification to a newly registered webhook.
	///
	/// According to spec:
	/// "Only the newly-registered webhook is notified.
	/// Only the newly-registered webhook is contacted for this notification".
	fn send_webhook_registered_notification(
		&self, client_node_id: PublicKey, app_name: LSPS5AppName, url: LSPS5WebhookUrl,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::webhook_registered();
		self.send_notification(client_node_id, app_name.clone(), url.clone(), notification)
	}

	/// Send an incoming_payment notification to all of a client's webhooks.
	pub fn notify_payment_incoming(&self, client_id: PublicKey) -> Result<(), LightningError> {
		let notification = WebhookNotification::payment_incoming();
		self.broadcast_notification(client_id, notification)
	}

	/// Send an expiry_soon notification to all of a client's webhooks.
	pub fn notify_expiry_soon(
		&self, client_id: PublicKey, timeout: u32,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::expiry_soon(timeout);
		self.broadcast_notification(client_id, notification)
	}

	/// Send a liquidity_management_request notification to all of a client's webhooks.
	pub fn notify_liquidity_management_request(
		&self, client_id: PublicKey,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::liquidity_management_request();
		self.broadcast_notification(client_id, notification)
	}

	/// Send an onion_message_incoming notification to all of a client's webhooks.
	pub fn notify_onion_message_incoming(
		&self, client_id: PublicKey,
	) -> Result<(), LightningError> {
		let notification = WebhookNotification::onion_message_incoming();
		self.broadcast_notification(client_id, notification)
	}

	/// Broadcast a notification to all registered webhooks for a client.
	///
	/// According to spec:
	/// "The LSP SHOULD contact all registered webhook URIs, if:
	/// * The client has registered at least one via `lsps5.set_webhook`.
	/// * *and* the client currently does not have a BOLT8 tunnel with the LSP.
	/// * *and* one of the specified events has occurred."
	fn broadcast_notification(
		&self, client_id: PublicKey, notification: WebhookNotification,
	) -> Result<(), LightningError> {
		let mut webhooks = self.webhooks.lock().unwrap();

		let client_webhooks = match webhooks.get_mut(&client_id) {
			Some(webhooks) if !webhooks.is_empty() => webhooks,
			_ => return Ok(()),
		};

		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let cooldown_duration = self.config.notification_cooldown_hours * 3600;

		for (app_name, webhook) in client_webhooks.iter_mut() {
			if webhook
				.last_notification_sent
				.get(&notification.method)
				.map(|last_sent| now.clone().abs_diff(last_sent.clone()))
				.map_or(true, |duration| duration >= cooldown_duration.as_secs())
			{
				webhook.last_notification_sent.insert(notification.method.clone(), now.clone());
				webhook.last_used = now.clone();
				self.send_notification(
					client_id,
					app_name.clone(),
					webhook.url.clone(),
					notification.clone(),
				)?;
			}
		}

		Ok(())
	}

	/// Send a notification to a webhook URL.
	fn send_notification(
		&self, counterparty_node_id: PublicKey, app_name: LSPS5AppName, url: LSPS5WebhookUrl,
		notification: WebhookNotification,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.event_queue.notifier();
		let timestamp =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());

		let notification_json =
			serde_json::to_string(&notification).map_err(|e| LightningError {
				err: format!("Failed to serialize notification: {}", e),
				action: ErrorAction::IgnoreAndLog(Level::Error),
			})?;

		let signature_hex = self.sign_notification(&notification_json, &timestamp)?;

		let headers = vec![
			("Content-Type".to_string(), "application/json".to_string()),
			("x-lsps5-timestamp".to_string(), timestamp.to_rfc3339()),
			("x-lsps5-signature".to_string(), signature_hex.clone()),
		];

		event_queue_notifier.enqueue(LSPS5ServiceEvent::SendWebhookNotifications {
			counterparty_node_id,
			app_name,
			url,
			notification,
			timestamp,
			signature: signature_hex,
			headers,
		});

		Ok(())
	}

	/// Sign a webhook notification with an LSP's signing key.
	///
	/// This function takes a notification body and timestamp and returns a signature
	/// in the format required by the LSPS5 specification.
	///
	/// # Arguments
	///
	/// * `body` - The serialized notification JSON
	/// * `timestamp` - The ISO8601 timestamp string
	/// * `signing_key` - The LSP private key used for signing
	///
	/// # Returns
	///
	/// * The zbase32 encoded signature as specified in LSPS0, or an error if signing fails
	pub fn sign_notification(
		&self, body: &str, timestamp: &LSPSDateTime,
	) -> Result<String, LightningError> {
		// Create the message to sign
		// According to spec:
		// The message to be signed is: "LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
		let message = format!(
			"LSPS5: DO NOT SIGN THIS MESSAGE MANUALLY: LSP: At {} I notify {}",
			timestamp.to_rfc3339(),
			body
		);

		Ok(message_signing::sign(message.as_bytes(), &self.config.signing_key))
	}

	/// Clean up webhooks for clients with no channels that haven't been used in a while.
	/// According to spec: "MUST remember all webhooks for at least 7 days after the last channel is closed".
	fn prune_stale_webhooks(&self) {
		let now =
			LSPSDateTime::new_from_duration_since_epoch(self.time_provider.duration_since_epoch());
		let mut webhooks = self.webhooks.lock().unwrap();

		webhooks.retain(|client_id, client_webhooks| {
			if !self.client_has_open_channel(client_id) {
				client_webhooks.retain(|_, webhook| {
					now.abs_diff(webhook.last_used.clone()) < MIN_WEBHOOK_RETENTION_DAYS.as_secs()
				});
				!client_webhooks.is_empty()
			} else {
				true
			}
		});

		let mut last_pruning = self.last_pruning.lock().unwrap();
		*last_pruning = Some(now);
	}

	fn client_has_open_channel(&self, client_id: &PublicKey) -> bool {
		self.channel_manager
			.get_cm()
			.list_channels()
			.iter()
			.any(|c| c.is_usable && c.counterparty.node_id == *client_id)
	}
}

impl<CM: Deref> LSPSProtocolMessageHandler for LSPS5ServiceHandler<CM>
where
	CM::Target: AChannelManager,
{
	type ProtocolMessage = LSPS5Message;
	const PROTOCOL_NUMBER: Option<u16> = Some(5);

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			LSPS5Message::Request(request_id, request) => {
				let res = match request {
					LSPS5Request::SetWebhook(params) => {
						self.handle_set_webhook(*counterparty_node_id, request_id.clone(), params)
					},
					LSPS5Request::ListWebhooks(params) => {
						self.handle_list_webhooks(*counterparty_node_id, request_id.clone(), params)
					},
					LSPS5Request::RemoveWebhook(params) => self.handle_remove_webhook(
						*counterparty_node_id,
						request_id.clone(),
						params,
					),
				};
				res
			},
			_ => {
				debug_assert!(
					false,
					"Service handler received LSPS5 response message. This should never happen."
				);
				Err(LightningError {
                    err: format!("Service handler received LSPS5 response message from node {:?}. This should never happen.", counterparty_node_id),
                    action: ErrorAction::IgnoreAndLog(Level::Info)
                })
			},
		}
	}
}

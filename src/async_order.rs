use bitcoin::hashes::{sha256, Hash as BitcoinHash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use lightning::io;
use lightning::ln::msgs::{DecodeError, Init, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::types::features::{InitFeatures, NodeFeatures};
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning::util::persist::KVStoreSync;
use lightning::util::ser::{LengthLimitedRead, LengthReadable, WithoutLength, Writeable, Writer};
use rgb_lib::{
    bdk_wallet::keys::{bip39::Mnemonic, DerivableKey, ExtendedKey},
    bitcoin::{
        bip32::{ChildNumber, Xpriv},
        secp256k1::Secp256k1 as Secp256k1_30,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tracing::warn;

use crate::utils::{hex_str, validate_and_parse_payment_hash};

pub(crate) const ASYNC_ORDER_MESSAGE_TYPE_ID: u16 = 37915;
pub(crate) const ASYNC_ORDER_MAX_HASH_BATCH_SIZE: usize = 200;
pub(crate) const ASYNC_ORDER_RESPONSE_TIMEOUT_SECS: u64 = 30;
const ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT: i64 = 1004;
const ASYNC_ERROR_DUPLICATE_HASH_CONFLICT: i64 = 1005;
const ASYNC_ERROR_INVALID_HASH_BATCH: i64 = 1003;
const ASYNC_ERROR_UNSUPPORTED_PROTOCOL_VERSION: i64 = 1000;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_INTERNAL_ERROR: i64 = -32603;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: u64 = 1;
const ASYNC_ORDER_LSP_REQUEST_TIMEOUT_SECS: u64 = 25; // Must be above utexo-lsp's default 15s HTTP timeout with a buffer.
const ASYNC_ORDER_FIRST_HASH_INDEX: u64 = 1;
const ASYNC_PAYMENTS_ACCOUNT_INDEX: u32 = 0;
const ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX: u32 = 0x7fff_ffff;
const ASYNC_PAYMENTS_PREIMAGE_DOMAIN: &[u8] = b"async-payments/v0";
const ASYNC_PAYMENTS_PURPOSE_APAY_INDEX: u32 = 0x4150_4159;
const ASYNC_PAYMENTS_KV_NAMESPACE: &str = "async_payments";
const ASYNC_PAYMENTS_NEXT_INDEX_KV_NAMESPACE: &str = "next_hash_index";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AsyncOrderMessage {
    pub(crate) payload: String,
}

impl Type for AsyncOrderMessage {
    fn type_id(&self) -> u16 {
        ASYNC_ORDER_MESSAGE_TYPE_ID
    }
}

impl Writeable for AsyncOrderMessage {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
        WithoutLength(&self.payload).write(w)
    }
}

impl LengthReadable for AsyncOrderMessage {
    fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
        let payload_without_length: WithoutLength<String> =
            LengthReadable::read_from_fixed_length_buffer(r)?;
        Ok(Self {
            payload: payload_without_length.0,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct AsyncOrderEnvelope {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AsyncOrderNewHashWire {
    pub(crate) hash_index: u64,
    pub(crate) payment_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AsyncOrderNewParamsWire {
    pub(crate) protocol_version: u64,
    pub(crate) hashes: Vec<AsyncOrderNewHashWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct AsyncOrderNewResultWire {
    pub(crate) protocol_version: u64,
    pub(crate) order_id: String,
    pub(crate) status: String,
    pub(crate) accepted_through_index: u64,
    pub(crate) next_index_expected: u64,
    pub(crate) unused_hashes: u64,
    pub(crate) refill_batch_size: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct AsyncOrderHttpResponseWire {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    result: Option<AsyncOrderNewResultWire>,
    #[serde(default)]
    error: Option<JsonRpcErrorWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcErrorWire {
    pub(crate) code: i64,
    pub(crate) message: String,
}

#[derive(Clone)]
pub(crate) struct AsyncPaymentsPreimageRoot {
    account_xprv: Xpriv,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AsyncPaymentHashMaterial {
    pub(crate) hash_index: u64,
    pub(crate) payment_preimage: PaymentPreimage,
    pub(crate) payment_hash: PaymentHash,
}

pub(crate) fn read_async_payments_next_hash_index(
    kv_store: &dyn KVStoreSync,
    host_node_id: &PublicKey,
) -> Result<u64, JsonRpcErrorWire> {
    match kv_store.read(
        ASYNC_PAYMENTS_KV_NAMESPACE,
        ASYNC_PAYMENTS_NEXT_INDEX_KV_NAMESPACE,
        &hex_str(&host_node_id.serialize()),
    ) {
        Ok(bytes) => {
            let value = String::from_utf8(bytes).map_err(|err| {
                JsonRpcErrorWire::internal_error(format!(
                    "async_payments_next_index_invalid_utf8: {err}"
                ))
            })?;
            let next_index = value.parse::<u64>().map_err(|err| {
                JsonRpcErrorWire::internal_error(format!(
                    "async_payments_next_index_invalid_value: {err}"
                ))
            })?;
            validate_async_payments_next_hash_index(next_index)?;
            Ok(next_index)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(ASYNC_ORDER_FIRST_HASH_INDEX),
        Err(err) => Err(JsonRpcErrorWire::internal_error(format!(
            "async_payments_next_index_read_failed: {err}"
        ))),
    }
}

pub(crate) fn write_async_payments_next_hash_index(
    kv_store: &dyn KVStoreSync,
    host_node_id: &PublicKey,
    next_index: u64,
) -> Result<(), JsonRpcErrorWire> {
    validate_async_payments_next_hash_index(next_index)?;
    kv_store
        .write(
            ASYNC_PAYMENTS_KV_NAMESPACE,
            ASYNC_PAYMENTS_NEXT_INDEX_KV_NAMESPACE,
            &hex_str(&host_node_id.serialize()),
            next_index.to_string().into_bytes(),
        )
        .map_err(|err| {
            JsonRpcErrorWire::internal_error(format!(
                "async_payments_next_index_write_failed: {err}"
            ))
        })
}

pub(crate) trait AsyncOrderAccessControl: Send + Sync {
    fn allows_peer(&self, peer: &PublicKey) -> bool;
}

#[derive(Debug)]
struct AllowFreeAccess;

impl AsyncOrderAccessControl for AllowFreeAccess {
    fn allows_peer(&self, _peer: &PublicKey) -> bool {
        true
    }
}

pub(crate) struct AsyncOrderMessageHandler {
    access_control: Arc<dyn AsyncOrderAccessControl>,
    lsp_client: Option<AsyncOrderLspClient>,
    runtime_handle: Option<Handle>,
    state: Arc<Mutex<AsyncOrderState>>,
}

struct AsyncOrderState {
    next_order_id: u64,
    peers: HashMap<PublicKey, PeerOrderState>,
    pending: Vec<(PublicKey, AsyncOrderMessage)>,
    pending_responses: HashMap<(PublicKey, String), AsyncOrderResponseSender>,
}

type AsyncOrderResponse = Result<AsyncOrderNewResultWire, JsonRpcErrorWire>;
type AsyncOrderResponseSender = oneshot::Sender<AsyncOrderResponse>;
pub(crate) type AsyncOrderResponseReceiver = oneshot::Receiver<AsyncOrderResponse>;

#[derive(Debug, Default)]
struct PeerOrderState {
    active_order: Option<AsyncOrderRecord>,
}

#[derive(Debug, Clone)]
struct AsyncOrderRecord {
    order_id: u64,
    hashes: BTreeMap<u64, String>,
}

#[derive(Clone)]
struct AsyncOrderLspClient {
    base_url: String,
    lsp_bearer_token: Option<String>,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Serialize)]
struct AsyncOrderNewStoreRequest {
    id: Value,
    peer_pubkey: String,
    protocol_version: u64,
    hashes: Vec<AsyncOrderNewHashWire>,
}

impl Default for AsyncOrderState {
    fn default() -> Self {
        Self {
            next_order_id: 1,
            peers: HashMap::new(),
            pending: Vec::new(),
            pending_responses: HashMap::new(),
        }
    }
}

impl AsyncOrderLspClient {
    fn new(base_url: String, lsp_bearer_token: Option<String>, request_timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .expect("reqwest client builder to succeed");
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            lsp_bearer_token,
            client,
        }
    }

    async fn async_order_new(
        &self,
        sender_node_id: PublicKey,
        request_id: Value,
        params: AsyncOrderNewParamsWire,
    ) -> Result<AsyncOrderNewResultWire, JsonRpcErrorWire> {
        let request = AsyncOrderNewStoreRequest {
            id: request_id.clone(),
            peer_pubkey: hex_str(&sender_node_id.serialize()),
            protocol_version: params.protocol_version,
            hashes: params.hashes,
        };
        let mut builder = self
            .client
            .post(format!("{}/internal/async_order/new", self.base_url))
            .json(&request);
        if let Some(token) = self
            .lsp_bearer_token
            .as_deref()
            .filter(|token| !token.is_empty())
        {
            builder = builder.bearer_auth(token);
        }

        let response = builder.send().await.map_err(|err| {
            if err.is_timeout() {
                JsonRpcErrorWire::internal_error(
                    "async_order_lsp_request_failed: POST /internal/async_order/new timed out"
                        .to_owned(),
                )
            } else {
                JsonRpcErrorWire::internal_error(format!(
                    "async_order_lsp_request_failed: POST /internal/async_order/new failed: {err}"
                ))
            }
        })?;
        let status = response.status();
        let envelope = response
            .json::<AsyncOrderHttpResponseWire>()
            .await
            .map_err(|err| {
                JsonRpcErrorWire::internal_error(format!("utexo_lsp_invalid_response: {err}"))
            })?;

        let AsyncOrderHttpResponseWire {
            jsonrpc,
            id,
            result,
            error,
        } = envelope;

        if jsonrpc != JSONRPC_VERSION {
            return Err(JsonRpcErrorWire::internal_error(format!(
                "utexo_lsp_invalid_response: expected jsonrpc {JSONRPC_VERSION}, got {jsonrpc}"
            )));
        }

        if id != Some(request_id) {
            return Err(JsonRpcErrorWire::internal_error(
                "utexo_lsp_invalid_response: response id did not match request id".to_owned(),
            ));
        }

        if result.is_some() && error.is_some() {
            return Err(JsonRpcErrorWire::internal_error(
                "utexo_lsp_invalid_response: response contained both result and error".to_owned(),
            ));
        }

        if status.is_success() {
            return match (result, error) {
                (Some(result), None) => Ok(result),
                (None, Some(err)) => Err(err),
                (Some(_), Some(_)) => Err(JsonRpcErrorWire::internal_error(
                    "utexo_lsp_invalid_response: response contained both result and error"
                        .to_owned(),
                )),
                (None, None) => Err(JsonRpcErrorWire::internal_error(
                    "utexo_lsp_invalid_response: response missing result".to_owned(),
                )),
            };
        }

        match (result, error) {
            (Some(_), Some(_)) => Err(JsonRpcErrorWire::internal_error(format!(
                "utexo_lsp_error_status_{status}: response contained both result and error"
            ))),
            (Some(_), None) => Err(JsonRpcErrorWire::internal_error(format!(
                "utexo_lsp_error_status_{status}: response unexpectedly contained result"
            ))),
            (None, Some(err)) => Err(err),
            (None, None) => Err(JsonRpcErrorWire::internal_error(format!(
                "utexo_lsp_error_status_{status}: missing error envelope"
            ))),
        }
    }
}

impl AsyncPaymentsPreimageRoot {
    pub(crate) fn build_from_mnemonic(
        mnemonic: &Mnemonic,
        network: Network,
        this_node_pubkey: &PublicKey,
    ) -> Result<Self, JsonRpcErrorWire> {
        let xkey: ExtendedKey = mnemonic.clone().into_extended_key().map_err(|err| {
            let message = format!("async_payment_root_derivation_failed: {err}");
            JsonRpcErrorWire::internal_error(message)
        })?;
        let mut account_xprv = xkey.into_xprv(network).ok_or_else(|| {
            JsonRpcErrorWire::internal_error("async_payment_xprv_not_available".to_owned())
        })?;

        let h31 = u32::from_be_bytes(
            sha256::Hash::hash(&this_node_pubkey.serialize()).to_byte_array()[0..4]
                .try_into()
                .expect("sha256 hash is 32 bytes"),
        ) & ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX;

        let path = [
            ASYNC_PAYMENTS_PURPOSE_APAY_INDEX,
            ASYNC_PAYMENTS_ACCOUNT_INDEX,
            h31,
        ];
        for index in path {
            account_xprv = derive_hardened_child(&account_xprv, index)?;
        }

        Ok(Self { account_xprv })
    }

    pub(crate) fn derive_hash_material(
        &self,
        hash_index: u64,
    ) -> Result<AsyncPaymentHashMaterial, JsonRpcErrorWire> {
        if hash_index < ASYNC_ORDER_FIRST_HASH_INDEX {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        let index =
            u32::try_from(hash_index).map_err(|_| JsonRpcErrorWire::invalid_hash_batch())?;
        if index > ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        let child_xprv = derive_hardened_child(&self.account_xprv, index)?;
        let child_secret = child_xprv.private_key.secret_bytes();
        let mut preimage_material =
            Vec::with_capacity(ASYNC_PAYMENTS_PREIMAGE_DOMAIN.len() + child_secret.len());
        preimage_material.extend_from_slice(ASYNC_PAYMENTS_PREIMAGE_DOMAIN);
        preimage_material.extend_from_slice(&child_secret);

        let payment_preimage =
            PaymentPreimage(sha256::Hash::hash(&preimage_material).to_byte_array());
        let payment_hash = PaymentHash(sha256::Hash::hash(&payment_preimage.0).to_byte_array());

        Ok(AsyncPaymentHashMaterial {
            hash_index,
            payment_preimage,
            payment_hash,
        })
    }

    pub(crate) fn prepare_async_order_new_params(
        &self,
        start_index: u64,
        batch_size: usize,
    ) -> Result<AsyncOrderNewParamsWire, JsonRpcErrorWire> {
        if start_index < ASYNC_ORDER_FIRST_HASH_INDEX
            || batch_size == 0
            || batch_size > ASYNC_ORDER_MAX_HASH_BATCH_SIZE
        {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        let last_index = start_index
            .checked_add((batch_size - 1) as u64)
            .ok_or_else(JsonRpcErrorWire::invalid_hash_batch)?;
        if last_index > ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX as u64 {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        let mut hashes = Vec::with_capacity(batch_size);
        for hash_index in start_index..=last_index {
            let material = self.derive_hash_material(hash_index)?;
            hashes.push(AsyncOrderNewHashWire {
                hash_index: material.hash_index,
                payment_hash: hex_str(&material.payment_hash.0),
            });
        }

        Ok(AsyncOrderNewParamsWire {
            protocol_version: PROTOCOL_VERSION,
            hashes,
        })
    }
}

impl AsyncOrderMessageHandler {
    pub(crate) fn new(access_control: Arc<dyn AsyncOrderAccessControl>) -> Self {
        Self {
            access_control,
            lsp_client: None,
            runtime_handle: None,
            state: Arc::new(Mutex::new(AsyncOrderState::default())),
        }
    }

    pub(crate) fn new_with_lsp_client(
        access_control: Arc<dyn AsyncOrderAccessControl>,
        lsp_base_url: String,
        lsp_bearer_token: Option<String>,
        runtime_handle: Handle,
    ) -> Self {
        Self {
            access_control,
            lsp_client: Some(AsyncOrderLspClient::new(
                lsp_base_url,
                lsp_bearer_token,
                Duration::from_secs(ASYNC_ORDER_LSP_REQUEST_TIMEOUT_SECS),
            )),
            runtime_handle: Some(runtime_handle),
            state: Arc::new(Mutex::new(AsyncOrderState::default())),
        }
    }

    #[cfg(test)]
    fn new_allowing_all_peers() -> Self {
        Self::new(Arc::new(AllowFreeAccess))
    }

    fn queue_jsonrpc_value_to_state(
        state: &Arc<Mutex<AsyncOrderState>>,
        peer: PublicKey,
        value: Value,
    ) {
        let mut state = state.lock().unwrap();
        state.pending.push((
            peer,
            AsyncOrderMessage {
                payload: value.to_string(),
            },
        ));
    }

    fn queue_jsonrpc_value(&self, peer: PublicKey, value: Value) {
        Self::queue_jsonrpc_value_to_state(&self.state, peer, value);
    }

    fn queue_jsonrpc_result(&self, peer: PublicKey, id: Value, result: AsyncOrderNewResultWire) {
        self.queue_jsonrpc_value(
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "result": result,
            }),
        );
    }

    pub(crate) fn queue_async_order_new_request(
        &self,
        host_node_id: PublicKey,
        id: Value,
        params: AsyncOrderNewParamsWire,
    ) -> Result<AsyncOrderResponseReceiver, JsonRpcErrorWire> {
        Self::validate_async_order_new_params(&params)?;
        let Some(request_id) = id.as_str().map(str::to_owned) else {
            return Err(JsonRpcErrorWire::invalid_request());
        };

        let (response_sender, response_receiver) = oneshot::channel();
        let mut state = self.state.lock().unwrap();
        let response_key = (host_node_id, request_id);
        if state.pending_responses.contains_key(&response_key) {
            return Err(JsonRpcErrorWire::internal_error(
                "async_order_request_id_already_pending".to_owned(),
            ));
        }
        state
            .pending_responses
            .insert(response_key, response_sender);
        state.pending.push((
            host_node_id,
            AsyncOrderMessage {
                payload: json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "id": id,
                    "method": "async_order.new",
                    "params": params,
                })
                .to_string(),
            },
        ));

        Ok(response_receiver)
    }

    pub(crate) fn forget_async_order_response(&self, host_node_id: PublicKey, request_id: &str) {
        let mut state = self.state.lock().unwrap();
        state
            .pending_responses
            .remove(&(host_node_id, request_id.to_owned()));
    }

    fn queue_jsonrpc_error(&self, peer: PublicKey, id: Value, code: i64, message: &str) {
        Self::queue_jsonrpc_error_to_state(&self.state, peer, id, code, message);
    }

    fn queue_jsonrpc_error_to_state(
        state: &Arc<Mutex<AsyncOrderState>>,
        peer: PublicKey,
        id: Value,
        code: i64,
        message: &str,
    ) {
        Self::queue_jsonrpc_value_to_state(
            state,
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "error": JsonRpcErrorWire {
                    code,
                    message: message.to_owned(),
                },
            }),
        );
    }

    fn queue_jsonrpc_result_to_state(
        state: &Arc<Mutex<AsyncOrderState>>,
        peer: PublicKey,
        id: Value,
        result: AsyncOrderNewResultWire,
    ) {
        Self::queue_jsonrpc_value_to_state(
            state,
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": id,
                "result": result,
            }),
        );
    }

    fn queue_jsonrpc_parse_error(&self, peer: PublicKey) {
        self.queue_jsonrpc_value(
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": Value::Null,
                "error": JsonRpcErrorWire::parse_error(),
            }),
        );
    }

    fn queue_jsonrpc_invalid_request(&self, peer: PublicKey) {
        self.queue_jsonrpc_value(
            peer,
            json!({
                "jsonrpc": JSONRPC_VERSION,
                "id": Value::Null,
                "error": JsonRpcErrorWire::invalid_request(),
            }),
        );
    }

    fn complete_async_order_response(
        &self,
        sender_node_id: PublicKey,
        id: Option<Value>,
        result: Option<Value>,
        error: Option<Value>,
    ) {
        let Some(Value::String(request_id)) = id else {
            warn!(peer = %sender_node_id, "ignoring async_order response with missing or non-string id");
            return;
        };

        let response = match (result, error) {
            (Some(result), None) => serde_json::from_value::<AsyncOrderNewResultWire>(result)
                .map_err(|err| {
                    JsonRpcErrorWire::internal_error(format!(
                        "invalid_async_order_response_result: {err}"
                    ))
                }),
            (None, Some(error)) => match serde_json::from_value::<JsonRpcErrorWire>(error) {
                Ok(err) => Err(err),
                Err(err) => Err(JsonRpcErrorWire::internal_error(format!(
                    "invalid_async_order_response_error: {err}"
                ))),
            },
            (Some(_), Some(_)) => Err(JsonRpcErrorWire::internal_error(
                "invalid_async_order_response: contained both result and error".to_owned(),
            )),
            (None, None) => Err(JsonRpcErrorWire::internal_error(
                "invalid_async_order_response: missing result and error".to_owned(),
            )),
        };

        let response_sender = {
            let mut state = self.state.lock().unwrap();
            state
                .pending_responses
                .remove(&(sender_node_id, request_id))
        };
        if let Some(response_sender) = response_sender {
            let _ = response_sender.send(response);
        }
    }

    fn record_async_order_new(
        &self,
        sender_node_id: PublicKey,
        params: AsyncOrderNewParamsWire,
    ) -> Result<AsyncOrderNewResultWire, JsonRpcErrorWire> {
        Self::validate_async_order_new_params(&params)?;
        let parsed_hashes = parse_hash_batch(params.hashes)?;

        let mut state = self.state.lock().unwrap();
        let needs_new_order = match state.peers.get(&sender_node_id) {
            Some(peer_state) => peer_state.active_order.is_none(),
            None => true,
        };
        if needs_new_order {
            let order_id = state.next_order_id;
            state.next_order_id = state
                .next_order_id
                .checked_add(1)
                .expect("order id counter to not overflow");
            state.peers.entry(sender_node_id).or_default().active_order =
                Some(AsyncOrderRecord::new(order_id));
        }

        let peer_state = state.peers.get_mut(&sender_node_id).unwrap();
        let order = peer_state.active_order.as_mut().unwrap();
        order.merge_hashes(&parsed_hashes)?;

        Ok(order.snapshot_result())
    }

    fn send_new_async_order_to_lsp(
        &self,
        sender_node_id: PublicKey,
        id: Value,
        params: AsyncOrderNewParamsWire,
    ) -> Result<(), JsonRpcErrorWire> {
        let (Some(lsp_client), Some(runtime_handle)) =
            (self.lsp_client.clone(), self.runtime_handle.clone())
        else {
            return Err(JsonRpcErrorWire::internal_error(
                "async_order_lsp_client_not_available".to_owned(),
            ));
        };

        let state = Arc::clone(&self.state);
        runtime_handle.spawn(async move {
            match lsp_client
                .async_order_new(sender_node_id, id.clone(), params)
                .await
            {
                Ok(result) => {
                    AsyncOrderMessageHandler::queue_jsonrpc_result_to_state(
                        &state,
                        sender_node_id,
                        id,
                        result,
                    );
                }
                Err(err) => {
                    AsyncOrderMessageHandler::queue_jsonrpc_error_to_state(
                        &state,
                        sender_node_id,
                        id,
                        err.code,
                        &err.message,
                    );
                }
            }
        });
        Ok(())
    }

    fn validate_async_order_new_params(
        params: &AsyncOrderNewParamsWire,
    ) -> Result<(), JsonRpcErrorWire> {
        if params.protocol_version != PROTOCOL_VERSION {
            return Err(JsonRpcErrorWire::unsupported_protocol_version());
        }
        if params.hashes.is_empty() {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }
        if params.hashes.len() > ASYNC_ORDER_MAX_HASH_BATCH_SIZE {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }
        parse_hash_batch(params.hashes.clone())?;
        Ok(())
    }
}

impl Default for AsyncOrderMessageHandler {
    fn default() -> Self {
        Self::new(Arc::new(AllowFreeAccess))
    }
}

impl CustomMessageReader for AsyncOrderMessageHandler {
    type CustomMessage = AsyncOrderMessage;

    fn read<RD: LengthLimitedRead>(
        &self,
        message_type: u16,
        buffer: &mut RD,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        if message_type != ASYNC_ORDER_MESSAGE_TYPE_ID {
            return Ok(None);
        }

        Ok(Some(AsyncOrderMessage::read_from_fixed_length_buffer(
            buffer,
        )?))
    }
}

impl CustomMessageHandler for AsyncOrderMessageHandler {
    fn handle_custom_message(
        &self,
        msg: Self::CustomMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        if !self.access_control.allows_peer(&sender_node_id) {
            warn!(peer = %sender_node_id, "rejected async_order peer message from untrusted peer");
            return Ok(());
        }

        if msg.payload.as_bytes().contains(&0) {
            warn!(
                peer = %sender_node_id,
                payload_len = msg.payload.len(),
                "async_order peer message contained a NUL byte"
            );
            self.queue_jsonrpc_parse_error(sender_node_id);
            return Ok(());
        }

        let envelope: AsyncOrderEnvelope = match serde_json::from_str(&msg.payload) {
            Ok(envelope) => envelope,
            Err(err) => {
                warn!(
                    error = %err,
                    peer = %sender_node_id,
                    payload_len = msg.payload.len(),
                    "failed to decode async_order peer message"
                );
                self.queue_jsonrpc_parse_error(sender_node_id);
                return Ok(());
            }
        };

        if envelope.jsonrpc != JSONRPC_VERSION {
            self.queue_jsonrpc_invalid_request(sender_node_id);
            return Ok(());
        }

        let response_like = envelope.result.is_some()
            || envelope.error.is_some()
            || (envelope.method.is_none() && envelope.id.is_some() && envelope.params.is_none());
        if response_like {
            if envelope.method.is_some() {
                warn!(
                    peer = %sender_node_id,
                    "ignoring malformed async_order response envelope with method field"
                );
                return Ok(());
            }
            self.complete_async_order_response(
                sender_node_id,
                envelope.id,
                envelope.result,
                envelope.error,
            );
            return Ok(());
        }

        let Some(method) = envelope.method else {
            self.queue_jsonrpc_invalid_request(sender_node_id);
            return Ok(());
        };

        let Some(id) = envelope.id else {
            self.queue_jsonrpc_invalid_request(sender_node_id);
            return Ok(());
        };

        if method == "async_order.new" {
            let params_value = match envelope.params {
                Some(params) => params,
                None => {
                    self.queue_jsonrpc_error(
                        sender_node_id,
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "missing params",
                    );
                    return Ok(());
                }
            };

            let params: AsyncOrderNewParamsWire = match serde_json::from_value(params_value) {
                Ok(params) => params,
                Err(err) => {
                    warn!(error = %err, "invalid async_order.new params from {sender_node_id}");
                    self.queue_jsonrpc_error(
                        sender_node_id,
                        id,
                        ASYNC_ERROR_INVALID_HASH_BATCH,
                        "invalid_hash_batch",
                    );
                    return Ok(());
                }
            };

            if self.lsp_client.is_some() {
                match Self::validate_async_order_new_params(&params) {
                    Ok(()) => {
                        if let Err(err) =
                            self.send_new_async_order_to_lsp(sender_node_id, id.clone(), params)
                        {
                            self.queue_jsonrpc_error(sender_node_id, id, err.code, &err.message);
                        }
                    }
                    Err(err) => {
                        self.queue_jsonrpc_error(sender_node_id, id, err.code, &err.message)
                    }
                }
                return Ok(());
            }

            match self.record_async_order_new(sender_node_id, params) {
                Ok(result) => self.queue_jsonrpc_result(sender_node_id, id, result),
                Err(err) => self.queue_jsonrpc_error(sender_node_id, id, err.code, &err.message),
            }
            return Ok(());
        }

        self.queue_jsonrpc_error(
            sender_node_id,
            id,
            JSONRPC_METHOD_NOT_FOUND,
            "method not found",
        );
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        let mut state = self.state.lock().unwrap();
        std::mem::take(&mut state.pending)
    }

    fn peer_disconnected(&self, _their_node_id: PublicKey) {}

    fn peer_connected(
        &self,
        _their_node_id: PublicKey,
        _msg: &Init,
        _inbound: bool,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
    }

    fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
        InitFeatures::empty()
    }
}

impl AsyncOrderRecord {
    fn new(order_id: u64) -> Self {
        Self {
            order_id,
            hashes: BTreeMap::new(),
        }
    }

    fn highest_hash_index(&self) -> u64 {
        self.hashes.keys().next_back().copied().unwrap_or(0)
    }

    fn next_hash_index(&self) -> u64 {
        self.highest_hash_index().saturating_add(1)
    }

    fn available_hashes(&self) -> u64 {
        self.hashes.len() as u64
    }

    fn merge_hashes(&mut self, hashes: &[(u64, String)]) -> Result<(), JsonRpcErrorWire> {
        if hashes.is_empty() {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        let expected_start = self.next_hash_index();
        let mut saw_existing = false;
        let mut saw_missing = false;
        let mut seen_batch_hashes = HashSet::new();

        for (index, payment_hash) in hashes {
            if !seen_batch_hashes.insert(payment_hash.clone()) {
                return Err(JsonRpcErrorWire::duplicate_hash_conflict());
            }

            match self.hashes.get(index) {
                Some(existing) if existing == payment_hash => {
                    saw_existing = true;
                }
                Some(_) => {
                    return Err(JsonRpcErrorWire::duplicate_index_conflict());
                }
                None => {
                    saw_missing = true;
                }
            }

            if self.hashes.iter().any(|(existing_index, existing_hash)| {
                *existing_index != *index && existing_hash == payment_hash
            }) {
                return Err(JsonRpcErrorWire::duplicate_hash_conflict());
            }
        }

        let missing_count = hashes
            .iter()
            .filter(|(index, _)| !self.hashes.contains_key(index))
            .count();
        if self.hashes.len().saturating_add(missing_count) > ASYNC_ORDER_MAX_HASH_BATCH_SIZE {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        if saw_existing && saw_missing {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        if saw_existing {
            return Ok(());
        }

        if hashes.first().map(|(index, _)| *index) != Some(expected_start) {
            return Err(JsonRpcErrorWire::invalid_hash_batch());
        }

        for (index, payment_hash) in hashes {
            self.hashes.insert(*index, payment_hash.clone());
        }

        Ok(())
    }

    fn snapshot_result(&self) -> AsyncOrderNewResultWire {
        AsyncOrderNewResultWire {
            protocol_version: PROTOCOL_VERSION,
            order_id: self.order_id.to_string(),
            status: "active".to_owned(),
            accepted_through_index: self.highest_hash_index(),
            next_index_expected: self.next_hash_index(),
            unused_hashes: self.available_hashes(),
            refill_batch_size: ASYNC_ORDER_MAX_HASH_BATCH_SIZE as u64,
        }
    }
}

impl JsonRpcErrorWire {
    fn parse_error() -> Self {
        Self {
            code: JSONRPC_PARSE_ERROR,
            message: "parse error".to_owned(),
        }
    }

    fn duplicate_index_conflict() -> Self {
        Self {
            code: ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT,
            message: "duplicate_index_conflict".to_owned(),
        }
    }

    fn duplicate_hash_conflict() -> Self {
        Self {
            code: ASYNC_ERROR_DUPLICATE_HASH_CONFLICT,
            message: "duplicate_hash_conflict".to_owned(),
        }
    }

    fn internal_error(message: String) -> Self {
        Self {
            code: JSONRPC_INTERNAL_ERROR,
            message,
        }
    }

    fn invalid_hash_batch() -> Self {
        Self {
            code: ASYNC_ERROR_INVALID_HASH_BATCH,
            message: "invalid_hash_batch".to_owned(),
        }
    }

    fn invalid_request() -> Self {
        Self {
            code: JSONRPC_INVALID_REQUEST,
            message: "invalid request".to_owned(),
        }
    }

    fn unsupported_protocol_version() -> Self {
        Self {
            code: ASYNC_ERROR_UNSUPPORTED_PROTOCOL_VERSION,
            message: "unsupported_protocol_version".to_owned(),
        }
    }
}

fn derive_hardened_child(parent: &Xpriv, index: u32) -> Result<Xpriv, JsonRpcErrorWire> {
    if index > ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX {
        return Err(JsonRpcErrorWire::invalid_hash_batch());
    }
    parent
        .derive_priv(&Secp256k1_30::new(), &ChildNumber::Hardened { index })
        .map_err(|err| {
            JsonRpcErrorWire::internal_error(format!(
                "async_payment_preimage_derivation_failed: {err}"
            ))
        })
}

fn parse_hash_batch(
    hashes: Vec<AsyncOrderNewHashWire>,
) -> Result<Vec<(u64, String)>, JsonRpcErrorWire> {
    let mut parsed = Vec::with_capacity(hashes.len());
    let mut previous_index: Option<u64> = None;

    for entry in hashes {
        let index = entry.hash_index;
        let payment_hash = validate_and_parse_payment_hash(&entry.payment_hash)
            .map_err(|_| JsonRpcErrorWire::invalid_hash_batch())?;

        if let Some(previous) = previous_index {
            if index != previous.saturating_add(1) {
                return Err(JsonRpcErrorWire::invalid_hash_batch());
            }
        }

        previous_index = Some(index);
        parsed.push((index, hex_str(&payment_hash.0)));
    }

    Ok(parsed)
}

fn validate_async_payments_next_hash_index(next_index: u64) -> Result<(), JsonRpcErrorWire> {
    if !(ASYNC_ORDER_FIRST_HASH_INDEX..=ASYNC_PAYMENTS_BIP32_MAX_CHILD_INDEX as u64 + 1)
        .contains(&next_index)
    {
        return Err(JsonRpcErrorWire::internal_error(
            "async_payments_next_index_out_of_range".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::new_jsonrpc_request_id;
    use axum::{extract::Json, http::StatusCode, routing::post, Router};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::collections::HashMap as StdHashMap;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    struct DenyAllAccess;

    #[derive(Default)]
    struct MemoryKvStore {
        entries: StdMutex<StdHashMap<(String, String, String), Vec<u8>>>,
    }

    impl KVStoreSync for MemoryKvStore {
        fn read(
            &self,
            primary_namespace: &str,
            secondary_namespace: &str,
            key: &str,
        ) -> Result<Vec<u8>, io::Error> {
            self.entries
                .lock()
                .unwrap()
                .get(&(
                    primary_namespace.to_owned(),
                    secondary_namespace.to_owned(),
                    key.to_owned(),
                ))
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing key"))
        }

        fn write(
            &self,
            primary_namespace: &str,
            secondary_namespace: &str,
            key: &str,
            buf: Vec<u8>,
        ) -> Result<(), io::Error> {
            self.entries.lock().unwrap().insert(
                (
                    primary_namespace.to_owned(),
                    secondary_namespace.to_owned(),
                    key.to_owned(),
                ),
                buf,
            );
            Ok(())
        }

        fn remove(
            &self,
            primary_namespace: &str,
            secondary_namespace: &str,
            key: &str,
            _lazy: bool,
        ) -> Result<(), io::Error> {
            self.entries.lock().unwrap().remove(&(
                primary_namespace.to_owned(),
                secondary_namespace.to_owned(),
                key.to_owned(),
            ));
            Ok(())
        }

        fn list(
            &self,
            primary_namespace: &str,
            secondary_namespace: &str,
        ) -> Result<Vec<String>, io::Error> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .keys()
                .filter(|(primary, secondary, _)| {
                    primary == primary_namespace && secondary == secondary_namespace
                })
                .map(|(_, _, key)| key.clone())
                .collect())
        }
    }

    impl AsyncOrderAccessControl for DenyAllAccess {
        fn allows_peer(&self, _peer: &PublicKey) -> bool {
            false
        }
    }

    fn test_peer_pubkey(tag: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = tag.max(1);
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret_key)
    }

    #[test]
    fn async_payments_next_hash_index_defaults_and_persists_per_host() {
        let kv_store = MemoryKvStore::default();
        let first_host = test_peer_pubkey(31);
        let second_host = test_peer_pubkey(32);

        assert_eq!(
            read_async_payments_next_hash_index(&kv_store, &first_host).unwrap(),
            ASYNC_ORDER_FIRST_HASH_INDEX
        );

        write_async_payments_next_hash_index(&kv_store, &first_host, 201).unwrap();

        assert_eq!(
            read_async_payments_next_hash_index(&kv_store, &first_host).unwrap(),
            201
        );
        assert_eq!(
            read_async_payments_next_hash_index(&kv_store, &second_host).unwrap(),
            ASYNC_ORDER_FIRST_HASH_INDEX
        );
    }

    fn new_order_request_payload(id: &str, hashes: &[(u64, &str)]) -> String {
        let hashes = hashes
            .iter()
            .map(|(hash_index, payment_hash)| {
                json!({
                    "hash_index": hash_index,
                    "payment_hash": payment_hash,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "method": "async_order.new",
            "params": {
                "protocol_version": PROTOCOL_VERSION,
                "hashes": hashes,
            },
        })
        .to_string()
    }

    fn read_single_response(handler: &AsyncOrderMessageHandler) -> Value {
        let pending = handler.get_and_clear_pending_msg();
        assert_eq!(pending.len(), 1);
        serde_json::from_str(&pending[0].1.payload).unwrap()
    }

    fn payment_hash_for_index(index: u64) -> String {
        format!("{index:064x}")
    }

    fn test_async_order_new_params() -> AsyncOrderNewParamsWire {
        AsyncOrderNewParamsWire {
            protocol_version: PROTOCOL_VERSION,
            hashes: vec![
                AsyncOrderNewHashWire {
                    hash_index: 1,
                    payment_hash:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                },
                AsyncOrderNewHashWire {
                    hash_index: 2,
                    payment_hash:
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_owned(),
                },
            ],
        }
    }

    fn test_async_order_new_result() -> AsyncOrderNewResultWire {
        AsyncOrderNewResultWire {
            protocol_version: PROTOCOL_VERSION,
            order_id: "1".to_owned(),
            status: "active".to_owned(),
            accepted_through_index: 2,
            next_index_expected: 3,
            unused_hashes: 2,
            refill_batch_size: ASYNC_ORDER_MAX_HASH_BATCH_SIZE as u64,
        }
    }

    fn test_mnemonic() -> Mnemonic {
        Mnemonic::from_str(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap()
    }

    async fn spawn_async_order_http_server(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    #[test]
    fn async_payment_hash_derivation_is_deterministic_and_index_scoped() {
        let node_pubkey = test_peer_pubkey(21);
        let root = AsyncPaymentsPreimageRoot::build_from_mnemonic(
            &test_mnemonic(),
            Network::Regtest,
            &node_pubkey,
        )
        .unwrap();

        let first = root.derive_hash_material(1).unwrap();
        let first_again = root.derive_hash_material(1).unwrap();
        let second = root.derive_hash_material(2).unwrap();

        assert_eq!(first.payment_preimage, first_again.payment_preimage);
        assert_eq!(first.payment_hash, first_again.payment_hash);
        assert_ne!(first.payment_preimage, second.payment_preimage);
        assert_ne!(first.payment_hash, second.payment_hash);
        assert_eq!(
            first.payment_hash,
            PaymentHash(sha256::Hash::hash(&first.payment_preimage.0).to_byte_array())
        );
    }

    #[test]
    fn async_payment_hash_derivation_is_node_scoped() {
        let first_root = AsyncPaymentsPreimageRoot::build_from_mnemonic(
            &test_mnemonic(),
            Network::Regtest,
            &test_peer_pubkey(22),
        )
        .unwrap();
        let second_root = AsyncPaymentsPreimageRoot::build_from_mnemonic(
            &test_mnemonic(),
            Network::Regtest,
            &test_peer_pubkey(23),
        )
        .unwrap();

        assert_ne!(
            first_root.derive_hash_material(1).unwrap().payment_hash,
            second_root.derive_hash_material(1).unwrap().payment_hash
        );
    }

    #[test]
    fn async_payment_hash_batch_builds_protocol_params() {
        let root = AsyncPaymentsPreimageRoot::build_from_mnemonic(
            &test_mnemonic(),
            Network::Regtest,
            &test_peer_pubkey(24),
        )
        .unwrap();

        let params = root.prepare_async_order_new_params(1, 2).unwrap();

        assert_eq!(params.protocol_version, PROTOCOL_VERSION);
        assert_eq!(params.hashes.len(), 2);
        assert_eq!(params.hashes[0].hash_index, 1);
        assert_eq!(params.hashes[1].hash_index, 2);
        assert_eq!(params.hashes[0].payment_hash.len(), 64);
        assert_eq!(params.hashes[1].payment_hash.len(), 64);
        assert_ne!(params.hashes[0].payment_hash, params.hashes[1].payment_hash);
    }

    #[test]
    fn async_order_sender_queues_jsonrpc_request() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let host_node_id = test_peer_pubkey(25);
        let request_id = Value::String(new_jsonrpc_request_id());

        let _response_rx = handler
            .queue_async_order_new_request(
                host_node_id,
                request_id.clone(),
                test_async_order_new_params(),
            )
            .unwrap();

        let pending = handler.get_and_clear_pending_msg();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, host_node_id);

        let request_value: Value = serde_json::from_str(&pending[0].1.payload).unwrap();
        assert_eq!(request_value["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(request_value["id"], request_id);
        assert_eq!(request_value["method"], "async_order.new");
        assert_eq!(
            request_value["params"]["protocol_version"],
            PROTOCOL_VERSION
        );
        assert_eq!(request_value["params"]["hashes"][0]["hash_index"], json!(1));
        assert_eq!(request_value["params"]["hashes"][1]["hash_index"], json!(2));
    }

    #[tokio::test]
    async fn async_order_sender_completes_matching_jsonrpc_response() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let host_node_id = test_peer_pubkey(26);
        let request_id = Value::String(new_jsonrpc_request_id());
        let response_rx = handler
            .queue_async_order_new_request(
                host_node_id,
                request_id.clone(),
                test_async_order_new_params(),
            )
            .unwrap();
        handler.get_and_clear_pending_msg();

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "id": request_id,
                        "result": test_async_order_new_result(),
                    })
                    .to_string(),
                },
                host_node_id,
            )
            .unwrap();

        let response = response_rx.await.unwrap().unwrap();
        assert_eq!(response, test_async_order_new_result());
    }

    #[test]
    fn async_order_new_creates_order_and_returns_state() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(1);
        let request_id = new_jsonrpc_request_id();
        let request_payload = new_order_request_payload(
            &request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: request_payload,
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(response_value["id"], request_id);
        assert_eq!(
            response_value["result"]["protocol_version"],
            PROTOCOL_VERSION
        );
        assert_eq!(response_value["result"]["order_id"], "1");
        assert_eq!(response_value["result"]["status"], "active");
        assert_eq!(response_value["result"]["accepted_through_index"], json!(2));
        assert_eq!(response_value["result"]["next_index_expected"], json!(3));
        assert_eq!(response_value["result"]["unused_hashes"], json!(2));
        assert_eq!(
            response_value["result"]["refill_batch_size"],
            json!(ASYNC_ORDER_MAX_HASH_BATCH_SIZE)
        );
    }

    #[test]
    fn async_order_new_is_idempotent_for_identical_batch() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(2);
        let request_id = new_jsonrpc_request_id();
        let request_payload = new_order_request_payload(
            &request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: request_payload.clone(),
                },
                test_peer,
            )
            .unwrap();
        let first_response = read_single_response(&handler);
        assert_eq!(first_response["id"], request_id);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: request_payload,
                },
                test_peer,
            )
            .unwrap();
        let second_response = read_single_response(&handler);

        assert_eq!(first_response, second_response);
    }

    #[test]
    fn async_order_new_rejects_conflicting_index() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(3);
        let initial_request_id = new_jsonrpc_request_id();
        let initial_request_payload = new_order_request_payload(
            &initial_request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: initial_request_payload,
                },
                test_peer,
            )
            .unwrap();
        read_single_response(&handler);

        let conflicting_request_id = new_jsonrpc_request_id();
        let conflicting_request_payload = new_order_request_payload(
            &conflicting_request_id,
            &[(
                1,
                "accccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: conflicting_request_payload,
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["id"], conflicting_request_id);
        assert_eq!(
            response_value["error"]["code"],
            ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT
        );
        assert_eq!(
            response_value["error"]["message"],
            "duplicate_index_conflict"
        );
    }

    #[test]
    fn async_order_new_rejects_repeated_payment_hash() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(6);
        let initial_request_id = new_jsonrpc_request_id();

        let initial_request_payload = new_order_request_payload(
            &initial_request_id,
            &[
                (
                    1,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                (
                    2,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: initial_request_payload,
                },
                test_peer,
            )
            .unwrap();
        read_single_response(&handler);

        let repeated_hash_request_id = new_jsonrpc_request_id();
        let repeated_hash_payload = new_order_request_payload(
            &repeated_hash_request_id,
            &[
                (
                    3,
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                ),
                (
                    4,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
        );
        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: repeated_hash_payload,
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["id"], repeated_hash_request_id);
        assert_eq!(
            response_value["error"]["code"],
            ASYNC_ERROR_DUPLICATE_HASH_CONFLICT
        );
        assert_eq!(
            response_value["error"]["message"],
            "duplicate_hash_conflict"
        );
    }

    #[test]
    fn async_order_new_rejects_malformed_json_with_parse_error() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(4);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: "{".to_owned(),
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(response_value["id"], Value::Null);
        assert_eq!(response_value["error"]["code"], JSONRPC_PARSE_ERROR);
        assert_eq!(response_value["error"]["message"], "parse error");
    }

    #[test]
    fn async_order_new_rejects_notification_like_payload_with_invalid_request() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(5);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "method": "async_order.new",
                        "params": {
                            "protocol_version": PROTOCOL_VERSION,
                            "hashes": [
                                {
                                    "hash_index": 1,
                                    "payment_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                }
                            ],
                        },
                    })
                    .to_string(),
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["jsonrpc"], JSONRPC_VERSION);
        assert_eq!(response_value["id"], Value::Null);
        assert_eq!(response_value["error"]["code"], JSONRPC_INVALID_REQUEST);
        assert_eq!(response_value["error"]["message"], "invalid request");
    }

    #[test]
    fn async_order_ignores_response_payloads() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(7);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "id": new_jsonrpc_request_id(),
                        "result": {
                            "status": "active",
                        },
                    })
                    .to_string(),
                },
                test_peer,
            )
            .unwrap();

        assert!(handler.get_and_clear_pending_msg().is_empty());
    }

    #[test]
    fn async_order_ignores_null_result_response_payloads() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(27);

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "id": new_jsonrpc_request_id(),
                        "result": Value::Null,
                    })
                    .to_string(),
                },
                test_peer,
            )
            .unwrap();

        assert!(handler.get_and_clear_pending_msg().is_empty());
    }

    #[test]
    fn async_order_new_rejects_hash_batches_over_200() {
        let handler = AsyncOrderMessageHandler::new_allowing_all_peers();
        let test_peer = test_peer_pubkey(8);
        let request_id = new_jsonrpc_request_id();
        let hashes = (1..=201)
            .map(|index| (index, payment_hash_for_index(index)))
            .collect::<Vec<_>>();
        let borrowed_hashes = hashes
            .iter()
            .map(|(index, hash)| (*index, hash.as_str()))
            .collect::<Vec<_>>();

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: new_order_request_payload(&request_id, &borrowed_hashes),
                },
                test_peer,
            )
            .unwrap();

        let response_value = read_single_response(&handler);
        assert_eq!(response_value["id"], request_id);
        assert_eq!(
            response_value["error"]["code"],
            ASYNC_ERROR_INVALID_HASH_BATCH
        );
        assert_eq!(response_value["error"]["message"], "invalid_hash_batch");
    }

    #[test]
    fn async_order_rejects_untrusted_peers_without_response() {
        let handler = AsyncOrderMessageHandler::new(Arc::new(DenyAllAccess));
        let test_peer = test_peer_pubkey(9);
        let request_id = new_jsonrpc_request_id();
        let request_payload = new_order_request_payload(
            &request_id,
            &[(
                1,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        );

        handler
            .handle_custom_message(
                AsyncOrderMessage {
                    payload: request_payload,
                },
                test_peer,
            )
            .unwrap();

        assert!(handler.get_and_clear_pending_msg().is_empty());
    }

    #[tokio::test]
    async fn async_order_lsp_client_parses_jsonrpc_response_envelope() {
        let test_peer = test_peer_pubkey(10);
        let expected_peer_pubkey = hex_str(&test_peer.serialize());
        let request_id = Value::String(new_jsonrpc_request_id());
        let request_id_for_server = request_id.clone();

        let app = Router::new().route(
            "/internal/async_order/new",
            post(move |Json(payload): Json<Value>| {
                let expected_peer_pubkey = expected_peer_pubkey.clone();
                let request_id = request_id_for_server.clone();
                async move {
                    assert_eq!(payload["peer_pubkey"], expected_peer_pubkey);
                    assert_eq!(payload["protocol_version"], json!(PROTOCOL_VERSION));
                    assert_eq!(payload["id"], request_id);
                    assert_eq!(payload["hashes"][0]["hash_index"], json!(1));
                    assert_eq!(payload["hashes"][1]["hash_index"], json!(2));
                    Json(json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "id": request_id,
                        "result": test_async_order_new_result(),
                    }))
                }
            }),
        );

        let base_url = spawn_async_order_http_server(app).await;
        let client = AsyncOrderLspClient::new(base_url, None, Duration::from_secs(1));
        let result = client
            .async_order_new(test_peer, request_id, test_async_order_new_params())
            .await
            .unwrap();

        assert_eq!(result, test_async_order_new_result());
    }

    #[tokio::test]
    async fn async_order_lsp_client_parses_jsonrpc_error_envelope() {
        let test_peer = test_peer_pubkey(11);
        let expected_peer_pubkey = hex_str(&test_peer.serialize());
        let request_id = Value::String(new_jsonrpc_request_id());
        let request_id_for_server = request_id.clone();

        let app = Router::new().route(
            "/internal/async_order/new",
            post(move |Json(payload): Json<Value>| {
                let expected_peer_pubkey = expected_peer_pubkey.clone();
                let request_id = request_id_for_server.clone();
                async move {
                    assert_eq!(payload["peer_pubkey"], expected_peer_pubkey);
                    assert_eq!(payload["protocol_version"], json!(PROTOCOL_VERSION));
                    assert_eq!(payload["id"], request_id);
                    (
                        StatusCode::CONFLICT,
                        Json(json!({
                            "jsonrpc": JSONRPC_VERSION,
                            "id": request_id,
                            "error": {
                                "code": ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT,
                                "message": "duplicate_index_conflict",
                            },
                        })),
                    )
                }
            }),
        );

        let base_url = spawn_async_order_http_server(app).await;
        let client = AsyncOrderLspClient::new(base_url, None, Duration::from_secs(1));
        let err = client
            .async_order_new(test_peer, request_id, test_async_order_new_params())
            .await
            .unwrap_err();

        assert_eq!(err.code, ASYNC_ERROR_DUPLICATE_INDEX_CONFLICT);
        assert_eq!(err.message, "duplicate_index_conflict");
    }

    #[tokio::test]
    async fn async_order_lsp_client_times_out_on_slow_response() {
        let test_peer = test_peer_pubkey(12);
        let expected_peer_pubkey = hex_str(&test_peer.serialize());
        let request_id = Value::String(new_jsonrpc_request_id());
        let request_id_for_server = request_id.clone();

        let app = Router::new().route(
            "/internal/async_order/new",
            post(move |Json(payload): Json<Value>| {
                let expected_peer_pubkey = expected_peer_pubkey.clone();
                let request_id = request_id_for_server.clone();
                async move {
                    assert_eq!(payload["peer_pubkey"], expected_peer_pubkey);
                    assert_eq!(payload["id"], request_id);
                    sleep(Duration::from_millis(150)).await;
                    Json(json!({
                        "jsonrpc": JSONRPC_VERSION,
                        "id": request_id,
                        "result": test_async_order_new_result(),
                    }))
                }
            }),
        );

        let base_url = spawn_async_order_http_server(app).await;
        let client = AsyncOrderLspClient::new(base_url, None, Duration::from_millis(50));
        let err = client
            .async_order_new(test_peer, request_id, test_async_order_new_params())
            .await
            .unwrap_err();

        assert_eq!(err.code, JSONRPC_INTERNAL_ERROR);
        assert_eq!(
            err.message,
            "async_order_lsp_request_failed: POST /internal/async_order/new timed out"
        );
    }
}

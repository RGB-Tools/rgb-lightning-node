//! High-level handler functions called by the extern "C" wrappers in
//! [`crate`] (see `lib.rs`). They take an opaque [`COpaqueStruct`] handle plus
//! zero or more JSON request strings, do the conversion to UniFFI types,
//! dispatch to [`SdkNode`], and serialize the response back to JSON.

use std::ffi::c_char;
use std::str::FromStr;
use std::sync::Arc;

use hex::DisplayHex;
use hex::FromHex;
use rgb_lightning_node as rln;
use rgb_lightning_node::{NativeExternalSigner, SdkNode};

use crate::json_types::*;
use crate::utils::{convert_optional_string, ptr_to_string, require_handle, require_signer, Error};
use crate::COpaqueStruct;

// ---------------------------------------------------------------------------
// String-parse helpers
// ---------------------------------------------------------------------------

fn parse_bolt11(s: &str) -> Result<rln::Bolt11Invoice, Error> {
    rln::Bolt11Invoice::from_str(s)
        .map_err(|e| Error::StringParse(format!("invalid bolt11: {e}")))
}

fn parse_payment_hash(s: &str) -> Result<rln::PaymentHash, Error> {
    Ok(lightning::types::payment::PaymentHash(parse_32_hex(s)?))
}

fn parse_contract_id(s: &str) -> Result<rln::ContractId, Error> {
    rln::ContractId::from_str(s)
        .map_err(|e| Error::StringParse(format!("invalid contract id: {e}")))
}

fn parse_32_hex(s: &str) -> Result<[u8; 32], Error> {
    let bytes =
        Vec::<u8>::from_hex(s).map_err(|e| Error::HexConversion(format!("not hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::HexConversion(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_req<T: serde::de::DeserializeOwned>(ptr: *const c_char) -> Result<T, Error> {
    Ok(serde_json::from_str(&ptr_to_string(ptr))?)
}

fn ok_void() -> Result<String, Error> {
    Ok(String::from("null"))
}

fn json<T: serde::Serialize>(t: T) -> Result<String, Error> {
    Ok(serde_json::to_string(&t)?)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

pub(crate) fn sdk_node_new(request_json: *const c_char) -> Result<SdkNode, Error> {
    let req: JsonSdkInitRequest = parse_req(request_json)?;
    Ok(SdkNode::create(req.try_into()?)?)
}

pub(crate) fn sdk_node_init(
    node: &COpaqueStruct,
    password: *const c_char,
    mnemonic_opt: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let password = ptr_to_string(password);
    let mnemonic = convert_optional_string(mnemonic_opt);
    Ok(node.init(password, mnemonic)?)
}

pub(crate) fn sdk_node_unlock(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonSdkUnlockRequest = parse_req(request_json)?;
    node.unlock(req.into())?;
    ok_void()
}

pub(crate) fn sdk_node_shutdown(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    node.shutdown();
    ok_void()
}

// ---------------------------------------------------------------------------
// Channels / peers
// ---------------------------------------------------------------------------

pub(crate) fn connect_peer(
    node: &COpaqueStruct,
    peer_pubkey_and_addr: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    node.connectpeer(ptr_to_string(peer_pubkey_and_addr))?;
    ok_void()
}

pub(crate) fn disconnect_peer(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonDisconnectPeerRequest = parse_req(request_json)?;
    node.disconnectpeer(req.try_into()?)?;
    ok_void()
}

pub(crate) fn open_channel(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonOpenChannelRequest = parse_req(request_json)?;
    let resp = node.openchannel(req.try_into()?)?;
    json(JsonOpenChannelResponse::from(resp))
}

pub(crate) fn close_channel(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonCloseChannelRequest = parse_req(request_json)?;
    node.closechannel(req.try_into()?)?;
    ok_void()
}

pub(crate) fn list_channels(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    let channels = node.list_channels()?;
    json(channels.into_iter().map(JsonChannel::from).collect::<Vec<_>>())
}

pub(crate) fn list_peers(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    let peers = node.list_peers()?;
    json(peers.into_iter().map(JsonPeer::from).collect::<Vec<_>>())
}

pub(crate) fn get_channel_id(
    node: &COpaqueStruct,
    temporary_channel_id_hex: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let temp = lightning::ln::types::ChannelId(parse_32_hex(&ptr_to_string(temporary_channel_id_hex))?);
    let result = node.get_channel_id(temp)?;
    json(JsonChannelIdResponse {
        channel_id: result.0.as_hex().to_string(),
    })
}

// ---------------------------------------------------------------------------
// Payments / invoices
// ---------------------------------------------------------------------------

pub(crate) fn send_payment(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonSendPaymentRequest = parse_req(request_json)?;
    let resp = node.sendpayment(req.try_into()?)?;
    json(JsonSendPaymentResponse::from(resp))
}

pub(crate) fn keysend(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonKeysendRequest = parse_req(request_json)?;
    let resp = node.keysend(req.try_into()?)?;
    json(JsonKeysendResponse::from(resp))
}

pub(crate) fn ln_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonLnInvoiceRequest = parse_req(request_json)?;
    let resp = node.ln_invoice(req.try_into()?)?;
    json(JsonLnInvoiceResponse::from(resp))
}

pub(crate) fn cancel_hodl_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonCancelHodlInvoiceRequest = parse_req(request_json)?;
    node.cancelhodlinvoice(req.try_into()?)?;
    ok_void()
}

pub(crate) fn claim_hodl_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonClaimHodlInvoiceRequest = parse_req(request_json)?;
    let resp = node.claimhodlinvoice(req.try_into()?)?;
    json(JsonClaimHodlInvoiceResponse::from(resp))
}

pub(crate) fn invoice_status(
    node: &COpaqueStruct,
    invoice: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let parsed = parse_bolt11(&ptr_to_string(invoice))?;
    let resp = node.invoice_status(parsed)?;
    json(JsonInvoiceStatus::from(resp))
}

pub(crate) fn decode_ln_invoice(
    node: &COpaqueStruct,
    invoice: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let parsed = parse_bolt11(&ptr_to_string(invoice))?;
    let resp = node.decode_ln_invoice(parsed)?;
    json(JsonDecodeLnInvoiceResponse::from(resp))
}

pub(crate) fn decode_rgb_invoice(
    node: &COpaqueStruct,
    invoice: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.decode_rgb_invoice(ptr_to_string(invoice))?;
    json(JsonDecodeRgbInvoiceResponse::from(resp))
}

pub(crate) fn get_payment(
    node: &COpaqueStruct,
    payment_hash_hex: *const c_char,
    payment_type: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let payment_hash = parse_payment_hash(&ptr_to_string(payment_hash_hex))?;
    // Accept either bare ("Outbound") or JSON-quoted ("\"Outbound\"") form.
    let pt_str = ptr_to_string(payment_type);
    let pt: PaymentTypeStr = serde_json::from_str(&pt_str)
        .or_else(|_| serde_json::from_str(&format!("\"{pt_str}\"")))?;
    let resp = node.get_payment(payment_hash, pt.into())?;
    json(JsonPayment::from(resp))
}

pub(crate) fn list_payments(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    let payments = node.list_payments()?;
    json(payments.into_iter().map(JsonPayment::from).collect::<Vec<_>>())
}

// ---------------------------------------------------------------------------
// RGB
// ---------------------------------------------------------------------------

pub(crate) fn rgb_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonRgbInvoiceRequest = parse_req(request_json)?;
    let resp = node.rgbinvoice(req.try_into()?)?;
    json(JsonRgbInvoiceResponse::from(resp))
}

pub(crate) fn send_rgb(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonSendRgbRequest = parse_req(request_json)?;
    let resp = node.send_rgb(req.try_into()?)?;
    json(JsonSendRgbResponse::from(resp))
}

pub(crate) fn refresh_transfers(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonRefreshTransfersRequest = parse_req(request_json)?;
    node.refreshtransfers(req.into())?;
    ok_void()
}

pub(crate) fn fail_transfers(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonFailTransfersRequest = parse_req(request_json)?;
    let resp = node.failtransfers(req.into())?;
    json(JsonFailTransfersResponse::from(resp))
}

pub(crate) fn inflate(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonInflateRequest = parse_req(request_json)?;
    let resp = node.inflate(req.try_into()?)?;
    json(JsonInflateResponse::from(resp))
}

pub(crate) fn list_transfers(
    node: &COpaqueStruct,
    asset_id: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let asset_id = parse_contract_id(&ptr_to_string(asset_id))?;
    let transfers = node.list_transfers(asset_id)?;
    json(transfers.into_iter().map(JsonTransfer::from).collect::<Vec<_>>())
}

pub(crate) fn list_unspents(
    node: &COpaqueStruct,
    skip_sync: bool,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let unspents = node.list_unspents(skip_sync)?;
    json(unspents.into_iter().map(JsonUnspent::from).collect::<Vec<_>>())
}

pub(crate) fn post_asset_media(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonPostAssetMediaRequest = parse_req(request_json)?;
    let resp = node.postassetmedia(req.into())?;
    json(JsonPostAssetMediaResponse::from(resp))
}

pub(crate) fn get_asset_media(
    node: &COpaqueStruct,
    digest: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.get_asset_media(ptr_to_string(digest))?;
    json(JsonAssetMediaResponse::from(resp))
}

// ---------------------------------------------------------------------------
// Asset issuance
// ---------------------------------------------------------------------------

pub(crate) fn issue_asset_nia(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonIssueAssetNiaRequest = parse_req(request_json)?;
    let asset = node.issueassetnia(req.into())?;
    json(JsonAssetNia::from(asset))
}

pub(crate) fn issue_asset_cfa(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonIssueAssetCfaRequest = parse_req(request_json)?;
    let asset = node.issueassetcfa(req.into())?;
    json(JsonAssetCfa::from(asset))
}

pub(crate) fn issue_asset_ifa(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonIssueAssetIfaRequest = parse_req(request_json)?;
    let asset = node.issueassetifa(req.into())?;
    json(JsonAssetIfa::from(asset))
}

pub(crate) fn issue_asset_uda(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonIssueAssetUdaRequest = parse_req(request_json)?;
    let asset = node.issueassetuda(req.into())?;
    json(JsonAssetUda::from(asset))
}

pub(crate) fn list_assets(
    node: &COpaqueStruct,
    filter_asset_schemas_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let filter: Vec<String> = parse_req(filter_asset_schemas_json)?;
    let resp = node.list_assets(filter)?;
    json(JsonListAssetsResponse::from(resp))
}

pub(crate) fn asset_balance(
    node: &COpaqueStruct,
    asset_id: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let asset_id = parse_contract_id(&ptr_to_string(asset_id))?;
    let resp = node.asset_balance(asset_id)?;
    json(JsonAssetBalanceInfo::from(resp))
}

pub(crate) fn asset_metadata(
    node: &COpaqueStruct,
    asset_id: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let asset_id = parse_contract_id(&ptr_to_string(asset_id))?;
    let resp = node.asset_metadata(asset_id)?;
    json(JsonAssetMetadataInfo::from(resp))
}

// ---------------------------------------------------------------------------
// Node info / network / btc / address / sign / fee / indexer / utxos / sync
// ---------------------------------------------------------------------------

pub(crate) fn node_info(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.node_info()?;
    json(JsonNodeInfo::from(resp))
}

pub(crate) fn network_info(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.network_info()?;
    json(JsonNetworkInfo::from(resp))
}

pub(crate) fn address(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.address()?;
    json(JsonAddressInfo::from(resp))
}

pub(crate) fn btc_balance(
    node: &COpaqueStruct,
    skip_sync: bool,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.btc_balance(skip_sync)?;
    json(JsonBtcBalanceInfo::from(resp))
}

pub(crate) fn sign_message(
    node: &COpaqueStruct,
    message: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.sign_message(ptr_to_string(message))?;
    json(JsonSignMessageResponse::from(resp))
}

pub(crate) fn estimate_fee(node: &COpaqueStruct, blocks: u16) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.estimate_fee(blocks)?;
    json(JsonEstimateFeeResponse::from(resp))
}

pub(crate) fn check_indexer_url(
    node: &COpaqueStruct,
    indexer_url: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.check_indexer_url(ptr_to_string(indexer_url))?;
    json(JsonCheckIndexerUrlResponse::from(resp))
}

pub(crate) fn check_proxy_endpoint(
    node: &COpaqueStruct,
    proxy_endpoint: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    node.check_proxy_endpoint(ptr_to_string(proxy_endpoint))?;
    ok_void()
}

pub(crate) fn send_btc(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonSendBtcRequest = parse_req(request_json)?;
    let resp = node.sendbtc(req.into())?;
    json(JsonSendBtcResponse::from(resp))
}

pub(crate) fn create_utxos(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonCreateUtxosRequest = parse_req(request_json)?;
    node.createutxos(req.into())?;
    ok_void()
}

pub(crate) fn list_transactions(
    node: &COpaqueStruct,
    skip_sync: bool,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let txs = node.list_transactions(skip_sync)?;
    json(txs.into_iter().map(JsonTransaction::from).collect::<Vec<_>>())
}

pub(crate) fn sync(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    node.sync()?;
    ok_void()
}

// ---------------------------------------------------------------------------
// Swaps / onion
// ---------------------------------------------------------------------------

pub(crate) fn maker_init(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonMakerInitRequest = parse_req(request_json)?;
    let resp = node.makerinit(req.try_into()?)?;
    json(JsonMakerInitResponse::from(resp))
}

pub(crate) fn maker_execute(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonMakerExecuteRequest = parse_req(request_json)?;
    node.makerexecute(req.try_into()?)?;
    ok_void()
}

pub(crate) fn taker(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonTakerRequest = parse_req(request_json)?;
    node.taker(req.into())?;
    ok_void()
}

pub(crate) fn send_onion_message(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let req: JsonSendOnionMessageRequest = parse_req(request_json)?;
    node.sendonionmessage(req.try_into()?)?;
    ok_void()
}

pub(crate) fn get_swap(
    node: &COpaqueStruct,
    payment_hash: *const c_char,
    taker_flag: bool,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let payment_hash = parse_payment_hash(&ptr_to_string(payment_hash))?;
    let resp = node.get_swap(payment_hash, taker_flag)?;
    json(JsonSwap::from(resp))
}

pub(crate) fn list_swaps(node: &COpaqueStruct) -> Result<String, Error> {
    let node = require_handle(node)?;
    let resp = node.list_swaps()?;
    json(JsonSwapList::from(resp))
}

// ---------------------------------------------------------------------------
// Module-level helpers (no handle): healthcheck / global init / global shutdown
// ---------------------------------------------------------------------------

pub(crate) fn uniffi_healthcheck() -> Result<String, Error> {
    Ok(rln::uniffi_healthcheck())
}

pub(crate) fn uniffi_is_initialized() -> Result<String, Error> {
    Ok(rln::uniffi_is_initialized().to_string())
}

pub(crate) fn sdk_global_initialize(request_json: *const c_char) -> Result<String, Error> {
    let req: JsonSdkInitRequest = parse_req(request_json)?;
    rln::sdk_initialize(req.try_into()?)?;
    ok_void()
}

pub(crate) fn sdk_global_shutdown() -> Result<String, Error> {
    rln::sdk_shutdown();
    ok_void()
}

// ---------------------------------------------------------------------------
// External-signer surface
// ---------------------------------------------------------------------------
//
// Native signer: RLN owns an in-process VLS signer seeded from a host-supplied
// 32-byte seed. Foreign-implemented signer (bootstrap-only) is exposed for
// UniFFI parity, but the callback transport for VLS messages is not yet wired
// through this C FFI — `unlock_with_attached_external_signer` will fail unless
// the host attaches a signer through another path first.

pub(crate) fn native_external_signer_new(
    seed_hex: *const c_char,
    network: *const c_char,
    permissive_policy: bool,
) -> Result<Arc<NativeExternalSigner>, Error> {
    let seed_hex = ptr_to_string(seed_hex);
    let network = ptr_to_string(network);
    Ok(NativeExternalSigner::new(
        seed_hex,
        network,
        Some(permissive_policy),
    )?)
}

pub(crate) fn native_external_signer_bootstrap(
    signer: &COpaqueStruct,
) -> Result<String, Error> {
    let signer = require_signer(signer)?;
    let bootstrap = signer.bootstrap()?;
    json(JsonSdkExternalSignerBootstrap::from(bootstrap))
}

pub(crate) fn sdk_node_init_with_native_external_signer(
    node: &COpaqueStruct,
    signer: &COpaqueStruct,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let signer = require_signer(signer)?;
    node.init_with_native_external_signer(Arc::clone(signer))?;
    ok_void()
}

pub(crate) fn sdk_node_attach_native_external_signer(
    node: &COpaqueStruct,
    signer: &COpaqueStruct,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let signer = require_signer(signer)?;
    node.attach_native_external_signer(Arc::clone(signer))?;
    ok_void()
}

pub(crate) fn sdk_node_unlock_with_native_external_signer(
    node: &COpaqueStruct,
    signer: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let signer = require_signer(signer)?;
    let r: JsonSdkExternalUnlockRequest = parse_req(request_json)?;
    node.unlock_with_native_external_signer(
        Arc::clone(signer),
        r.bitcoind_rpc_username,
        r.bitcoind_rpc_password,
        r.bitcoind_rpc_host,
        r.bitcoind_rpc_port,
        r.indexer_url,
        r.proxy_endpoint,
        r.announce_addresses,
        r.announce_alias,
    )?;
    ok_void()
}

pub(crate) fn sdk_node_init_with_external_signer(
    node: &COpaqueStruct,
    bootstrap_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let b: JsonSdkExternalSignerBootstrap = parse_req(bootstrap_json)?;
    node.init_with_external_signer(b.into())?;
    ok_void()
}

pub(crate) fn sdk_node_detach_external_signer(
    node: &COpaqueStruct,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    node.detach_external_signer();
    ok_void()
}

pub(crate) fn sdk_node_unlock_with_attached_external_signer(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> Result<String, Error> {
    let node = require_handle(node)?;
    let r: JsonSdkExternalUnlockRequest = parse_req(request_json)?;
    node.unlock_with_attached_external_signer(
        r.bitcoind_rpc_username,
        r.bitcoind_rpc_password,
        r.bitcoind_rpc_host,
        r.bitcoind_rpc_port,
        r.indexer_url,
        r.proxy_endpoint,
        r.announce_addresses,
        r.announce_alias,
    )?;
    ok_void()
}

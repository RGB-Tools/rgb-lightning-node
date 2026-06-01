//! C / C++ bindings for `rgb-lightning-node`.
//!
//! This crate is a thin extern-"C" shim on top of the existing UniFFI-exposed
//! API in [`rgb_lightning_node::uniffi_api`]. All complex types cross the
//! boundary as JSON strings; the same async-bridge (`block_on_sdk`) is reused,
//! so callers see a synchronous API.
//!
//! See [`README.md`](../README.md) and [`example.c`](../example.c) for usage.

mod api;
mod json_types;
mod utils;

use rgb_lightning_node::{NativeExternalSigner, SdkNode};

use std::{
    any::TypeId,
    collections::hash_map::DefaultHasher,
    ffi::{c_char, c_void, CStr, CString},
    hash::{Hash, Hasher},
    ptr::null_mut,
    sync::Arc,
};

use rgb_lightning_node::RlnError;

/// Wrap an FFI entry-point body so any panic is caught instead of unwinding
/// across `extern "C"` and aborting the process. Every `rln_*` entry point
/// must go through this macro. See `catch_panic` for the closure-type details.
macro_rules! ffi_call {
    ($label:expr, $body:expr) => {{
        let mut closure = || $body;
        utils::catch_panic($label, &mut closure).into()
    }};
}

#[repr(C)]
pub struct COpaqueStruct {
    ptr: *const c_void,
    ty: u64,
}

#[repr(C)]
pub enum CResultValue {
    Ok,
    Err,
}

#[repr(C)]
pub struct CResult {
    // Fields are `pub` so Rust consumers linking the `rlib` (e.g. the napi-rs
    // binding) can destructure. `#[repr(C)]` already fixes the ABI.
    pub result: CResultValue,
    pub inner: COpaqueStruct,
}

#[repr(C)]
pub struct CResultString {
    pub result: CResultValue,
    pub inner: *mut c_char,
}

// ---------------------------------------------------------------------------
// Drop / free
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn free_sdk_node(obj: COpaqueStruct) {
    unsafe {
        let _ = Box::from_raw(obj.ptr as *mut SdkNode);
    }
}

/// Free a string previously returned in `CResultString.inner`.
#[unsafe(no_mangle)]
pub extern "C" fn rln_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_new(request_json: *const c_char) -> CResult {
    ffi_call!("rln_sdk_node_new", api::sdk_node_new(request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_init(
    node: &COpaqueStruct,
    password: *const c_char,
    mnemonic_opt: *const c_char,
) -> CResultString {
    ffi_call!("rln_sdk_node_init", api::sdk_node_init(node, password, mnemonic_opt))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_unlock(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_sdk_node_unlock", api::sdk_node_unlock(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_shutdown(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_sdk_node_shutdown", api::sdk_node_shutdown(node))
}

// ---------------------------------------------------------------------------
// Channels / peers
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_connect_peer(
    node: &COpaqueStruct,
    peer_pubkey_and_addr: *const c_char,
) -> CResultString {
    ffi_call!("rln_connect_peer", api::connect_peer(node, peer_pubkey_and_addr))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_disconnect_peer(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_disconnect_peer", api::disconnect_peer(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_open_channel(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_open_channel", api::open_channel(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_close_channel(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_close_channel", api::close_channel(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_channels(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_list_channels", api::list_channels(node))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_peers(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_list_peers", api::list_peers(node))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_get_channel_id(
    node: &COpaqueStruct,
    temporary_channel_id_hex: *const c_char,
) -> CResultString {
    ffi_call!("rln_get_channel_id", api::get_channel_id(node, temporary_channel_id_hex))
}

// ---------------------------------------------------------------------------
// Payments / invoices
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_send_payment(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_send_payment", api::send_payment(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_keysend(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_keysend", api::keysend(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_ln_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_ln_invoice", api::ln_invoice(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_cancel_hodl_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_cancel_hodl_invoice", api::cancel_hodl_invoice(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_claim_hodl_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_claim_hodl_invoice", api::claim_hodl_invoice(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_invoice_status(
    node: &COpaqueStruct,
    invoice: *const c_char,
) -> CResultString {
    ffi_call!("rln_invoice_status", api::invoice_status(node, invoice))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_decode_ln_invoice(
    node: &COpaqueStruct,
    invoice: *const c_char,
) -> CResultString {
    ffi_call!("rln_decode_ln_invoice", api::decode_ln_invoice(node, invoice))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_decode_rgb_invoice(
    node: &COpaqueStruct,
    invoice: *const c_char,
) -> CResultString {
    ffi_call!("rln_decode_rgb_invoice", api::decode_rgb_invoice(node, invoice))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_get_payment(
    node: &COpaqueStruct,
    payment_hash_hex: *const c_char,
    payment_type: *const c_char,
) -> CResultString {
    ffi_call!("rln_get_payment", api::get_payment(node, payment_hash_hex, payment_type))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_payments(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_list_payments", api::list_payments(node))
}

// ---------------------------------------------------------------------------
// RGB
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_rgb_invoice(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_rgb_invoice", api::rgb_invoice(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_send_rgb(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_send_rgb", api::send_rgb(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_refresh_transfers(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_refresh_transfers", api::refresh_transfers(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_fail_transfers(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_fail_transfers", api::fail_transfers(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_inflate(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_inflate", api::inflate(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_transfers(
    node: &COpaqueStruct,
    asset_id: *const c_char,
) -> CResultString {
    ffi_call!("rln_list_transfers", api::list_transfers(node, asset_id))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_unspents(node: &COpaqueStruct, skip_sync: bool) -> CResultString {
    ffi_call!("rln_list_unspents", api::list_unspents(node, skip_sync))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_post_asset_media(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_post_asset_media", api::post_asset_media(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_get_asset_media(
    node: &COpaqueStruct,
    digest: *const c_char,
) -> CResultString {
    ffi_call!("rln_get_asset_media", api::get_asset_media(node, digest))
}

// ---------------------------------------------------------------------------
// Asset issuance / metadata
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_issue_asset_nia(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_issue_asset_nia", api::issue_asset_nia(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_issue_asset_cfa(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_issue_asset_cfa", api::issue_asset_cfa(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_issue_asset_ifa(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_issue_asset_ifa", api::issue_asset_ifa(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_issue_asset_uda(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_issue_asset_uda", api::issue_asset_uda(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_assets(
    node: &COpaqueStruct,
    filter_asset_schemas_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_list_assets", api::list_assets(node, filter_asset_schemas_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_asset_balance(
    node: &COpaqueStruct,
    asset_id: *const c_char,
) -> CResultString {
    ffi_call!("rln_asset_balance", api::asset_balance(node, asset_id))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_asset_metadata(
    node: &COpaqueStruct,
    asset_id: *const c_char,
) -> CResultString {
    ffi_call!("rln_asset_metadata", api::asset_metadata(node, asset_id))
}

// ---------------------------------------------------------------------------
// Node info / network / btc / address / sign / fee / indexer / utxos / sync
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_node_info(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_node_info", api::node_info(node))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_network_info(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_network_info", api::network_info(node))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_address(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_address", api::address(node))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_btc_balance(node: &COpaqueStruct, skip_sync: bool) -> CResultString {
    ffi_call!("rln_btc_balance", api::btc_balance(node, skip_sync))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sign_message(
    node: &COpaqueStruct,
    message: *const c_char,
) -> CResultString {
    ffi_call!("rln_sign_message", api::sign_message(node, message))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_estimate_fee(node: &COpaqueStruct, blocks: u16) -> CResultString {
    ffi_call!("rln_estimate_fee", api::estimate_fee(node, blocks))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_check_indexer_url(
    node: &COpaqueStruct,
    indexer_url: *const c_char,
) -> CResultString {
    ffi_call!("rln_check_indexer_url", api::check_indexer_url(node, indexer_url))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_check_proxy_endpoint(
    node: &COpaqueStruct,
    proxy_endpoint: *const c_char,
) -> CResultString {
    ffi_call!("rln_check_proxy_endpoint", api::check_proxy_endpoint(node, proxy_endpoint))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_send_btc(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_send_btc", api::send_btc(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_create_utxos(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_create_utxos", api::create_utxos(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_transactions(
    node: &COpaqueStruct,
    skip_sync: bool,
) -> CResultString {
    ffi_call!("rln_list_transactions", api::list_transactions(node, skip_sync))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sync(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_sync", api::sync(node))
}

// ---------------------------------------------------------------------------
// Swaps / onion
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_maker_init(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_maker_init", api::maker_init(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_maker_execute(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_maker_execute", api::maker_execute(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_taker(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_taker", api::taker(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_send_onion_message(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_send_onion_message", api::send_onion_message(node, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_get_swap(
    node: &COpaqueStruct,
    payment_hash: *const c_char,
    taker_flag: bool,
) -> CResultString {
    ffi_call!("rln_get_swap", api::get_swap(node, payment_hash, taker_flag))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_list_swaps(node: &COpaqueStruct) -> CResultString {
    ffi_call!("rln_list_swaps", api::list_swaps(node))
}

// ---------------------------------------------------------------------------
// Module-level (no handle): healthcheck / global init / global shutdown
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn rln_uniffi_healthcheck() -> CResultString {
    ffi_call!("rln_uniffi_healthcheck", api::uniffi_healthcheck())
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_uniffi_is_initialized() -> CResultString {
    ffi_call!("rln_uniffi_is_initialized", api::uniffi_is_initialized())
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_initialize(request_json: *const c_char) -> CResultString {
    ffi_call!("rln_sdk_initialize", api::sdk_global_initialize(request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_shutdown() -> CResultString {
    ffi_call!("rln_sdk_shutdown", api::sdk_global_shutdown())
}

// ---------------------------------------------------------------------------
// External-signer surface
// ---------------------------------------------------------------------------

/// Drop a `NativeExternalSigner` handle. Safe to call immediately after
/// attach / init / unlock succeeds: RLN holds its own `Arc` clone.
#[unsafe(no_mangle)]
pub extern "C" fn free_native_external_signer(obj: COpaqueStruct) {
    unsafe {
        let _ = Box::from_raw(obj.ptr as *mut Arc<NativeExternalSigner>);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_native_external_signer_new(
    seed_hex: *const c_char,
    network: *const c_char,
    permissive_policy: bool,
) -> CResult {
    ffi_call!("rln_native_external_signer_new", api::native_external_signer_new(seed_hex, network, permissive_policy))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_native_external_signer_bootstrap(
    signer: &COpaqueStruct,
) -> CResultString {
    ffi_call!("rln_native_external_signer_bootstrap", api::native_external_signer_bootstrap(signer))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_init_with_native_external_signer(
    node: &COpaqueStruct,
    signer: &COpaqueStruct,
) -> CResultString {
    ffi_call!("rln_sdk_node_init_with_native_external_signer", api::sdk_node_init_with_native_external_signer(node, signer))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_attach_native_external_signer(
    node: &COpaqueStruct,
    signer: &COpaqueStruct,
) -> CResultString {
    ffi_call!("rln_sdk_node_attach_native_external_signer", api::sdk_node_attach_native_external_signer(node, signer))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_unlock_with_native_external_signer(
    node: &COpaqueStruct,
    signer: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_sdk_node_unlock_with_native_external_signer", api::sdk_node_unlock_with_native_external_signer(node, signer, request_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_init_with_external_signer(
    node: &COpaqueStruct,
    bootstrap_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_sdk_node_init_with_external_signer", api::sdk_node_init_with_external_signer(node, bootstrap_json))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_detach_external_signer(
    node: &COpaqueStruct,
) -> CResultString {
    ffi_call!("rln_sdk_node_detach_external_signer", api::sdk_node_detach_external_signer(node))
}

#[unsafe(no_mangle)]
pub extern "C" fn rln_sdk_node_unlock_with_attached_external_signer(
    node: &COpaqueStruct,
    request_json: *const c_char,
) -> CResultString {
    ffi_call!("rln_sdk_node_unlock_with_attached_external_signer", api::sdk_node_unlock_with_attached_external_signer(node, request_json))
}

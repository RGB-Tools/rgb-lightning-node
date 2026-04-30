#![cfg_attr(feature = "uniffi", allow(clippy::empty_line_after_doc_comments))]
#![allow(dead_code)]
#![allow(unused_imports)]

mod args;
mod async_order;
mod auth;
mod backup;
mod bitcoind;
mod core_types;
mod database;
mod disk;
mod error;
#[cfg(test)]
#[path = "test/fee_mock.rs"]
mod fee_mock;
#[cfg(feature = "uniffi")]
pub mod ffi;
mod kv_store;
mod ldk;
mod node;
mod rgb;
mod routes;
mod runtime;
mod sdk;
mod swap;
#[cfg(feature = "test-utils")]
pub mod test_utils;
#[cfg(feature = "uniffi")]
mod uniffi_api;
mod utils;

pub use node::{NodeConfig, NodeHandle};

#[cfg(feature = "uniffi")]
pub use uniffi_api::*;
#[cfg(feature = "uniffi")]
pub(crate) use uniffi_api::{clear_uniffi_app_state, set_uniffi_app_state};

mod args;
mod bdk;
mod bitcoind;
mod disk;
mod error;
mod ldk;
mod proxy;
mod rgb;
mod routes;
mod utils;

#[cfg(test)]
mod test;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use ldk::LdkBackgroundServices;
use std::net::SocketAddr;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::trace::{self, TraceLayer};
use tracing_subscriber::{filter, prelude::*};

use crate::args::LdkUserInfo;
use crate::error::AppError;
use crate::ldk::{start_ldk, stop_ldk};
use crate::routes::{
    address, asset_balance, close_channel, connect_peer, create_utxos, decode_ln_invoice,
    disconnect_peer, invoice_status, issue_asset, keysend, list_assets, list_channels,
    list_payments, list_peers, list_unspents, ln_invoice, node_info, open_channel,
    refresh_transfers, rgb_invoice, send_asset, send_onion_message, send_payment, shutdown,
    sign_message,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = args::parse_startup_args()?;

    // stdout logger
    let stdout_log = tracing_subscriber::fmt::layer();

    // file logger
    let log_dir = format!("{}/logs", args.storage_dir_path);
    let file_appender = tracing_appender::rolling::daily(&log_dir, "rln.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let file_log = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .with(file_log.with_filter(filter::LevelFilter::DEBUG))
        .init();

    let addr = SocketAddr::from(([127, 0, 0, 1], args.daemon_listening_port));

    let (router, ldk_background_services) = app(args).await?;

    tracing::info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(router.into_make_service())
        .with_graceful_shutdown(shutdown_signal(ldk_background_services))
        .await
        .unwrap();

    Ok(())
}

pub(crate) async fn app(args: LdkUserInfo) -> Result<(Router, LdkBackgroundServices), AppError> {
    let (ldk_background_services, shared_state) = start_ldk(args).await?;

    let router = Router::new()
        .route("/address", post(address))
        .route("/assetbalance", post(asset_balance))
        .route("/closechannel", post(close_channel))
        .route("/connectpeer", post(connect_peer))
        .route("/createutxos", post(create_utxos))
        .route("/decodelninvoice", post(decode_ln_invoice))
        .route("/disconnectpeer", post(disconnect_peer))
        .route("/invoicestatus", post(invoice_status))
        .route("/issueasset", post(issue_asset))
        .route("/keysend", post(keysend))
        .route("/listassets", get(list_assets))
        .route("/listchannels", get(list_channels))
        .route("/listpayments", get(list_payments))
        .route("/listpeers", get(list_peers))
        .route("/listunspents", get(list_unspents))
        .route("/lninvoice", post(ln_invoice))
        .route("/nodeinfo", get(node_info))
        .route("/openchannel", post(open_channel))
        .route("/refreshtransfers", post(refresh_transfers))
        .route("/rgbinvoice", post(rgb_invoice))
        .route("/sendasset", post(send_asset))
        .route("/sendonionmessage", post(send_onion_message))
        .route("/sendpayment", post(send_payment))
        .route("/shutdown", post(shutdown))
        .route("/signmessage", post(sign_message))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(CorsLayer::permissive())
        .with_state(shared_state);

    Ok((router, ldk_background_services))
}

/// Tokio signal handler that will wait for a user to press CTRL+C.
/// We use this in our hyper `Server` method `with_graceful_shutdown`.
async fn shutdown_signal(ldk_background_services: LdkBackgroundServices) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    stop_ldk(ldk_background_services).await;
}

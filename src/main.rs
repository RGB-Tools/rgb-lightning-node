mod args;
mod backup;
mod bitcoind;
mod disk;
mod error;
mod ldk;
mod rgb;
mod routes;
mod swap;
mod utils;

#[cfg(test)]
mod test;

use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    http::Request,
    response::Response,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::Span;
use tracing_subscriber::{
    filter,
    fmt::{
        format::{DefaultFields, Writer},
        FormatFields,
    },
    prelude::*,
};

use crate::args::LdkUserInfo;
use crate::error::AppError;
use crate::ldk::stop_ldk;
use crate::routes::{
    address, asset_balance, asset_metadata, backup, btc_balance, change_password,
    check_indexer_url, check_proxy_endpoint, close_channel, connect_peer, create_utxos,
    decode_ln_invoice, decode_rgb_invoice, disconnect_peer, estimate_fee, fail_transfers,
    get_asset_media, get_channel_id, get_payment, get_swap, init, invoice_status, issue_asset_cfa,
    issue_asset_nia, issue_asset_uda, keysend, list_assets, list_channels, list_payments,
    list_peers, list_swaps, list_transactions, list_transfers, list_unspents, ln_invoice, lock,
    maker_execute, maker_init, network_info, node_info, open_channel, post_asset_media,
    refresh_transfers, restore, rgb_invoice, send_asset, send_btc, send_onion_message,
    send_payment, shutdown, sign_message, sync, taker, unlock,
};
use crate::utils::{start_daemon, AppState, LOGS_DIR};

#[tokio::main]
async fn main() -> Result<()> {
    let args = args::parse_startup_args()?;

    // stdout logger
    let stdout_log = tracing_subscriber::fmt::layer().fmt_fields(TypedFields::default());

    // file logger
    let log_dir = args.storage_dir_path.join(LOGS_DIR);
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

    let addr = SocketAddr::from(([0, 0, 0, 0], args.daemon_listening_port));

    let (router, app_state) = app(args).await?;

    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(app_state))
        .await
        .unwrap();

    Ok(())
}

pub(crate) async fn app(args: LdkUserInfo) -> Result<(Router, Arc<AppState>), AppError> {
    let app_state = start_daemon(&args).await?;

    let router = Router::new()
        .route(
            "/postassetmedia",
            post(post_asset_media).layer(RequestBodyLimitLayer::new(
                args.max_media_upload_size_mb as usize * 1024 * 1024,
            )),
        )
        // all routes before this will have the default body limit disabled
        .layer(DefaultBodyLimit::disable())
        .route("/address", post(address))
        .route("/assetbalance", post(asset_balance))
        .route("/assetmetadata", post(asset_metadata))
        .route("/backup", post(backup))
        .route("/btcbalance", post(btc_balance))
        .route("/changepassword", post(change_password))
        .route("/checkindexerurl", post(check_indexer_url))
        .route("/checkproxyendpoint", post(check_proxy_endpoint))
        .route("/closechannel", post(close_channel))
        .route("/connectpeer", post(connect_peer))
        .route("/createutxos", post(create_utxos))
        .route("/decodelninvoice", post(decode_ln_invoice))
        .route("/decodergbinvoice", post(decode_rgb_invoice))
        .route("/disconnectpeer", post(disconnect_peer))
        .route("/estimatefee", post(estimate_fee))
        .route("/failtransfers", post(fail_transfers))
        .route("/getassetmedia", post(get_asset_media))
        .route("/getchannelid", post(get_channel_id))
        .route("/getpayment", post(get_payment))
        .route("/getswap", post(get_swap))
        .route("/init", post(init))
        .route("/invoicestatus", post(invoice_status))
        .route("/issueassetcfa", post(issue_asset_cfa))
        .route("/issueassetnia", post(issue_asset_nia))
        .route("/issueassetuda", post(issue_asset_uda))
        .route("/keysend", post(keysend))
        .route("/listassets", post(list_assets))
        .route("/listchannels", get(list_channels))
        .route("/listpayments", get(list_payments))
        .route("/listpeers", get(list_peers))
        .route("/listswaps", get(list_swaps))
        .route("/listtransactions", post(list_transactions))
        .route("/listtransfers", post(list_transfers))
        .route("/listunspents", post(list_unspents))
        .route("/lninvoice", post(ln_invoice))
        .route("/lock", post(lock))
        .route("/makerexecute", post(maker_execute))
        .route("/makerinit", post(maker_init))
        .route("/networkinfo", get(network_info))
        .route("/nodeinfo", get(node_info))
        .route("/openchannel", post(open_channel))
        .route("/refreshtransfers", post(refresh_transfers))
        .route("/restore", post(restore))
        .route("/rgbinvoice", post(rgb_invoice))
        .route("/sendasset", post(send_asset))
        .route("/sendbtc", post(send_btc))
        .route("/sendonionmessage", post(send_onion_message))
        .route("/sendpayment", post(send_payment))
        .route("/shutdown", post(shutdown))
        .route("/signmessage", post(sign_message))
        .route("/sync", post(sync))
        .route("/taker", post(taker))
        .route("/unlock", post(unlock))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    tracing::info_span!(
                        "request",
                        status_code = tracing::field::Empty,
                        uri = tracing::field::display(request.uri()),
                        request_id = tracing::field::display(uuid::Uuid::new_v4()),
                    )
                })
                .on_request(|_request: &Request<_>, _span: &Span| {
                    tracing::info!("STARTED");
                })
                .on_response(|response: &Response, latency: Duration, span: &Span| {
                    span.record("status_code", tracing::field::display(response.status()));
                    tracing::info!("ENDED in {:?}", latency);
                }),
        )
        .layer(CorsLayer::permissive())
        .with_state(app_state.clone());

    Ok((router, app_state))
}

impl AppState {
    fn wait_state_change(&self) -> bool {
        let _unlocked_state = self.get_unlocked_app_state();
        let mut changing_state = self.get_changing_state();
        if !*changing_state {
            *changing_state = true;
            return true;
        }
        false
    }
}

/// Tokio signal handler that will wait for a user to press CTRL+C.
async fn shutdown_signal(app_state: Arc<AppState>) {
    let cancel_token = app_state.cancel_token.clone();

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
        _ = cancel_token.cancelled() => {},
    }

    tracing::info!("Received a shutdown signal");

    let app_state_copy = app_state.clone();
    loop {
        {
            if app_state_copy.wait_state_change() {
                break;
            }
        }
        tracing::info!("Will shutdown after change state is complete");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    stop_ldk(app_state.clone()).await;
}

// workaround for https://github.com/tokio-rs/tracing/issues/1372
#[derive(Default)]
struct TypedFields(DefaultFields);

impl<'writer> FormatFields<'writer> for TypedFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        writer: Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        self.0.format_fields(writer, fields)
    }
}

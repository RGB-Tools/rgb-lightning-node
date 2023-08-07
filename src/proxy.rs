use reqwest::{multipart, Body, Client};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};

use crate::error::APIError;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JsonRpcError {
    pub(crate) code: i64,
    message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcRequest<P> {
    method: String,
    jsonrpc: String,
    id: Option<String>,
    params: Option<P>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JsonRpcResponse<R> {
    id: Option<String>,
    pub(crate) result: Option<R>,
    pub(crate) error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostConsignmentParams {
    recipient_id: String,
    txid: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostConsignmentWithVoutParams {
    recipient_id: String,
    txid: String,
    vout: u32,
}

pub async fn post_consignment(
    proxy_client: Client,
    url: &str,
    recipient_id: String,
    consignment_path: PathBuf,
    txid: String,
    vout: Option<u32>,
) -> Result<JsonRpcResponse<bool>, APIError> {
    let file = File::open(consignment_path.clone()).await?;
    let stream = FramedRead::new(file, BytesCodec::new());
    let file_name = consignment_path
        .clone()
        .file_name()
        .map(|filename| filename.to_string_lossy().into_owned())
        .expect("valid file name");
    let consignment_file = multipart::Part::stream(Body::wrap_stream(stream)).file_name(file_name);

    let params = if let Some(vout) = vout {
        serde_json::to_string(&PostConsignmentWithVoutParams {
            recipient_id,
            txid,
            vout,
        })
        .expect("valid param")
    } else {
        serde_json::to_string(&PostConsignmentParams { recipient_id, txid }).expect("valid param")
    };
    let form = multipart::Form::new()
        .text("method", "consignment.post")
        .text("jsonrpc", "2.0")
        .text("id", "1")
        .text("params", params)
        .part("file", consignment_file);
    Ok(proxy_client
        .post(url)
        .multipart(form)
        .send()
        .await?
        .json::<JsonRpcResponse<bool>>()
        .await?)
}

use super::*;

const TEST_DIR_BASE: &str = "tmp/path_traversal/";

const SECRET: &[u8] = b"SECRET-OUTSIDE-THE-NODE-DIRS";

// Absolute path, and a relative traversal to the same target computed from a node
// directory. The relative form matters: an absolute path only escapes because
// `PathBuf::join` replaces the base, so a fix that just rejects a leading `/` would
// still be vulnerable to `../` traversal.
fn identifiers(target: &std::path::Path) -> [String; 2] {
    let abs = target.to_str().unwrap().to_string();
    let rel = format!("{}{}", "../".repeat(40), abs.trim_start_matches('/'));
    [abs, rel]
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn path_traversal() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;
    let good_txid = "0".repeat(64);

    // A sentinel outside every node directory. Reading it back through an endpoint
    // would prove a traversal escape. Some handlers lowercase the identifier, so the
    // path must be all lowercase: this makes the test Linux-only in practice, since
    // `TMPDIR` on macOS has uppercase components.
    let sentinel = std::env::temp_dir().join("rln_path_traversal_sentinel");
    std::fs::create_dir_all(&sentinel).unwrap();
    // for /getassetmedia and the issueasset APIs the target is the file itself
    std::fs::write(sentinel.join("secret"), SECRET).unwrap();
    // for /getconsignment the handler appends <asset_id>/consignment_out to the txid
    // directory: a bad txid with the good asset ID reaches this file
    let asset_dir = sentinel.join(asset_id.replace("rgb:", ""));
    std::fs::create_dir_all(&asset_dir).unwrap();
    std::fs::write(asset_dir.join("consignment_out"), SECRET).unwrap();
    // and a bad asset ID with a good txid reaches this one
    std::fs::write(sentinel.join("consignment_out"), SECRET).unwrap();

    for digest in identifiers(&sentinel.join("secret")) {
        // /getassetmedia: media_dir.join(digest)
        let res = reqwest::Client::new()
            .post(format!("http://{node1_addr}/getassetmedia"))
            .json(&GetAssetMediaRequest {
                digest: digest.clone(),
            })
            .send()
            .await
            .unwrap();
        check_response_is_nok(
            res,
            reqwest::StatusCode::BAD_REQUEST,
            "Invalid media digest",
            "InvalidMediaDigest",
        )
        .await;

        // /issueassetcfa: file_digest -> media_dir.join(file_digest), read as media
        let res = reqwest::Client::new()
            .post(format!("http://{node1_addr}/issueassetcfa"))
            .json(&IssueAssetCFARequest {
                amounts: vec![2000],
                name: s!("Collectible"),
                details: None,
                precision: 0,
                file_digest: Some(digest.clone()),
            })
            .send()
            .await
            .unwrap();
        check_response_is_nok(
            res,
            reqwest::StatusCode::BAD_REQUEST,
            "Invalid media digest",
            "InvalidMediaDigest",
        )
        .await;

        // /issueassetuda: media_file_digest -> media_dir.join(media_file_digest)
        let res = reqwest::Client::new()
            .post(format!("http://{node1_addr}/issueassetuda"))
            .json(&IssueAssetUDARequest {
                ticker: s!("UNIQUE"),
                name: s!("Unique"),
                details: None,
                precision: 0,
                media_file_digest: Some(digest.clone()),
                attachments_file_digests: vec![],
            })
            .send()
            .await
            .unwrap();
        check_response_is_nok(
            res,
            reqwest::StatusCode::BAD_REQUEST,
            "Invalid media digest",
            "InvalidMediaDigest",
        )
        .await;

        // /issueassetuda: attachments_file_digests -> the same join
        let res = reqwest::Client::new()
            .post(format!("http://{node1_addr}/issueassetuda"))
            .json(&IssueAssetUDARequest {
                ticker: s!("UNIQUE"),
                name: s!("Unique"),
                details: None,
                precision: 0,
                media_file_digest: None,
                attachments_file_digests: vec![digest.clone()],
            })
            .send()
            .await
            .unwrap();
        check_response_is_nok(
            res,
            reqwest::StatusCode::BAD_REQUEST,
            "Invalid media digest",
            "InvalidMediaDigest",
        )
        .await;
    }

    // /getconsignment: transfers_dir.join(txid).join(asset_id).join("consignment_out")
    for bad in identifiers(&sentinel) {
        for (asset_id, txid, msg, name) in [
            (asset_id.clone(), bad.clone(), "Invalid txid", "InvalidTxid"),
            (
                bad.clone(),
                good_txid.clone(),
                "Invalid asset ID",
                "InvalidAssetID",
            ),
        ] {
            let res = reqwest::Client::new()
                .post(format!("http://{node1_addr}/getconsignment"))
                .json(&GetConsignmentRequest { asset_id, txid })
                .send()
                .await
                .unwrap();
            check_response_is_nok(res, reqwest::StatusCode::BAD_REQUEST, msg, name).await;
        }
    }

    std::fs::remove_dir_all(&sentinel).unwrap();
}

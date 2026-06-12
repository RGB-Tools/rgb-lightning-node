use super::*;

const TEST_DIR_BASE: &str = "tmp/pagination_filters/";

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn transfers_pagination_and_filter() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}transfers/node1");
    let test_dir_node2 = format!("{TEST_DIR_BASE}transfers/node2");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    let (node2_addr, _) = start_node(&test_dir_node2, NODE2_PEER_PORT, false).await;

    fund_and_create_utxos(node1_addr, None).await;
    fund_and_create_utxos(node2_addr, None).await;

    let asset_id = issue_asset_nia(node1_addr).await.asset_id;

    let sends = 3u64;
    for _ in 0..sends {
        let recipient_id = rgb_invoice(node2_addr, Some(asset_id.clone()), false)
            .await
            .recipient_id;
        send_asset(
            node1_addr,
            &asset_id,
            Assignment::Fungible(100),
            recipient_id,
            None,
        )
        .await;
        mine(false);
        refresh_transfers(node2_addr).await;
        refresh_transfers(node1_addr).await;
    }

    let all = list_transfers_full(node1_addr, &asset_id, ListTransfersFilter::default()).await;
    let total = all.transfers.len();
    assert!(total as u64 >= sends);
    assert!(all.first_index_offset >= all.last_index_offset);
    assert_eq!(
        all.first_index_offset,
        all.transfers.first().unwrap().idx as u64
    );
    assert_eq!(
        all.last_index_offset,
        all.transfers.last().unwrap().idx as u64
    );

    let page = list_transfers_full(
        node1_addr,
        &asset_id,
        ListTransfersFilter {
            max_transfers: Some(2),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(page.transfers.len(), 2);
    assert_eq!(page.first_index_offset, all.first_index_offset);

    let mut seen = vec![];
    let mut cursor = None;
    loop {
        let resp = list_transfers_full(
            node1_addr,
            &asset_id,
            ListTransfersFilter {
                index_offset: cursor,
                max_transfers: Some(2),
                ..Default::default()
            },
        )
        .await;
        if resp.transfers.is_empty() {
            break;
        }
        for t in &resp.transfers {
            assert!(!seen.contains(&t.idx));
            seen.push(t.idx);
        }
        cursor = Some(resp.last_index_offset);
    }
    assert_eq!(seen.len(), total);

    let settled = list_transfers_full(
        node1_addr,
        &asset_id,
        ListTransfersFilter {
            status: Some(TransferStatus::Settled),
            ..Default::default()
        },
    )
    .await;
    assert!(settled
        .transfers
        .iter()
        .all(|t| t.status == TransferStatus::Settled));

    let created = all.transfers.first().unwrap().created_at as u64;
    let future = created + 1_000_000;
    let before = list_transfers_full(
        node1_addr,
        &asset_id,
        ListTransfersFilter {
            created_before: Some(future),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(before.transfers.len(), total);
    let after = list_transfers_full(
        node1_addr,
        &asset_id,
        ListTransfersFilter {
            created_after: Some(future),
            ..Default::default()
        },
    )
    .await;
    assert!(after.transfers.is_empty());
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn unspents_pagination() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}unspents/node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;

    let all = list_unspents_full(node1_addr, None, None).await;
    let total = all.unspents.len();
    assert!(total > 2);
    assert_eq!(all.first_index_offset, total as u64);
    assert_eq!(all.last_index_offset, 1);

    let page = list_unspents_full(node1_addr, None, Some(2)).await;
    assert_eq!(page.unspents.len(), 2);
    assert_eq!(page.first_index_offset, total as u64);

    let mut seen = vec![];
    let mut cursor = None;
    loop {
        let resp = list_unspents_full(node1_addr, cursor, Some(2)).await;
        if resp.unspents.is_empty() {
            break;
        }
        for u in &resp.unspents {
            assert!(!seen.contains(&u.utxo.outpoint));
            seen.push(u.utxo.outpoint.clone());
        }
        cursor = Some(resp.last_index_offset);
    }
    assert_eq!(seen.len(), total);
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[traced_test]
async fn transactions_pagination() {
    initialize();

    let test_dir_node1 = format!("{TEST_DIR_BASE}transactions/node1");
    let (node1_addr, _) = start_node(&test_dir_node1, NODE1_PEER_PORT, false).await;
    fund_and_create_utxos(node1_addr, None).await;

    let all = list_transactions_full(node1_addr, None, None).await;
    let total = all.transactions.len();
    assert!(total >= 2);
    assert_eq!(all.first_index_offset, total as u64);
    assert_eq!(all.last_index_offset, 1);

    let page = list_transactions_full(node1_addr, None, Some(1)).await;
    assert_eq!(page.transactions.len(), 1);
    assert_eq!(page.first_index_offset, total as u64);

    let mut seen = vec![];
    let mut cursor = None;
    loop {
        let resp = list_transactions_full(node1_addr, cursor, Some(1)).await;
        if resp.transactions.is_empty() {
            break;
        }
        for t in &resp.transactions {
            assert!(!seen.contains(&t.txid));
            seen.push(t.txid.clone());
        }
        cursor = Some(resp.last_index_offset);
    }
    assert_eq!(seen.len(), total);
}

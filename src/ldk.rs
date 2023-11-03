use amplify::map;
use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{psbt::Psbt as BdkPsbt, OutPoint, Script as BdkScript};
use bdk::keys::bip39::Mnemonic;
use bdk::keys::{DerivableKey, ExtendedKey};
use bdk::{FeeRate, SignOptions};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::{BlockHash, LockTime, PackedLockTime, Script, Sequence, TxIn, TxOut, Witness};
use bitcoin_30::{Address, ScriptBuf};
use bitcoin_bech32::WitnessProgram;
use lightning::chain::{chainmonitor, ChannelMonitorUpdateStatus};
use lightning::chain::{Filter, Watch};
use lightning::events::{Event, PaymentFailureReason, PaymentPurpose};
use lightning::ln::channelmanager::{self, PaymentId, RecentPaymentDetails};
use lightning::ln::channelmanager::{
    ChainParameters, ChannelManagerReadArgs, SimpleArcChannelManager,
};
use lightning::ln::peer_handler::{IgnoringMessageHandler, MessageHandler, SimpleArcPeerManager};
use lightning::ln::{ChannelId, PaymentHash, PaymentPreimage, PaymentSecret};
use lightning::onion_message::{DefaultMessageRouter, SimpleArcOnionMessenger};
use lightning::rgb_utils::{
    get_rgb_channel_info, get_rgb_runtime, read_rgb_transfer_info, STATIC_BLINDING,
    WALLET_FINGERPRINT_FNAME,
};
use lightning::routing::gossip;
use lightning::routing::gossip::{NodeId, P2PGossipSync};
use lightning::routing::router::DefaultRouter;
use lightning::routing::scoring::ProbabilisticScoringFeeParameters;
use lightning::sign::{
    DelayedPaymentOutputDescriptor, EntropySource, InMemorySigner, KeysManager,
    SpendableOutputDescriptor,
};
use lightning::util::config::UserConfig;
use lightning::util::persist::{KVStore, MonitorUpdatingPersister};
use lightning::util::ser::{Readable, ReadableArgs, WithoutLength, Writeable};
use lightning::{chain, impl_writeable_tlv_based};
use lightning_background_processor::{process_events_async, GossipSync};
use lightning_block_sync::init;
use lightning_block_sync::poll;
use lightning_block_sync::SpvClient;
use lightning_block_sync::UnboundedCache;
use lightning_net_tokio::SocketDescriptor;
use lightning_persister::fs_store::FilesystemStore;
use rand::{thread_rng, Rng, RngCore};
use rgb_lib::wallet::{DatabaseType, Recipient, RecipientData, Wallet as RgbLibWallet, WalletData};
use rgb_lib::AssetSchema;
use rgbstd::containers::{Bindle, Transfer as RgbTransfer};
use rgbstd::persistence::Inventory;
use rgbstd::Txid as RgbTxid;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use strict_encoding::{FieldName, TypeName};
use tokio::sync::watch::Sender;
use tokio::task::JoinHandle;

use crate::bdk::{broadcast_tx, get_bdk_wallet_seckey, sync_wallet};
use crate::bitcoind::BitcoindClient;
use crate::disk::{self, INBOUND_PAYMENTS_FNAME, OUTBOUND_PAYMENTS_FNAME};
use crate::disk::{FilesystemLogger, PENDING_SPENDABLE_OUTPUT_DIR};
use crate::error::APIError;
use crate::proxy::post_consignment;
use crate::rgb::{get_bitcoin_network, update_transition_beneficiary, RgbUtilities};
use crate::routes::HTLCStatus;
use crate::utils::{do_connect_peer, hex_str, AppState, StaticState, UnlockedAppState};

pub(crate) const FEE_RATE: f32 = 7.0;
pub(crate) const UTXO_SIZE_SAT: u32 = 32000;
pub(crate) const MIN_CHANNEL_CONFIRMATIONS: u8 = 6;

pub(crate) struct LdkBackgroundServices {
    stop_processing: Arc<AtomicBool>,
    peer_manager: Arc<PeerManager>,
    bp_exit: Sender<()>,
    background_processor: Option<JoinHandle<Result<(), std::io::Error>>>,
}

pub(crate) struct PaymentInfo {
    pub(crate) preimage: Option<PaymentPreimage>,
    pub(crate) secret: Option<PaymentSecret>,
    pub(crate) status: HTLCStatus,
    pub(crate) amt_msat: Option<u64>,
}

impl_writeable_tlv_based!(PaymentInfo, {
    (0, preimage, required),
    (2, secret, required),
    (4, status, required),
    (6, amt_msat, required),
});

pub(crate) struct InboundPaymentInfoStorage {
    pub(crate) payments: HashMap<PaymentHash, PaymentInfo>,
}

impl_writeable_tlv_based!(InboundPaymentInfoStorage, {
    (0, payments, required),
});

pub(crate) struct OutboundPaymentInfoStorage {
    pub(crate) payments: HashMap<PaymentId, PaymentInfo>,
}

impl_writeable_tlv_based!(OutboundPaymentInfoStorage, {
    (0, payments, required),
});

type ChainMonitor = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<BitcoindClient>,
    Arc<BitcoindClient>,
    Arc<FilesystemLogger>,
    Arc<
        MonitorUpdatingPersister<
            Arc<FilesystemStore>,
            Arc<FilesystemLogger>,
            Arc<KeysManager>,
            Arc<KeysManager>,
        >,
    >,
>;

pub(crate) type GossipVerifier = lightning_block_sync::gossip::GossipVerifier<
    lightning_block_sync::gossip::TokioSpawner,
    Arc<lightning_block_sync::rpc::RpcClient>,
    Arc<FilesystemLogger>,
    SocketDescriptor,
    Arc<ChannelManager>,
    Arc<OnionMessenger>,
    IgnoringMessageHandler,
    Arc<KeysManager>,
>;

pub(crate) type PeerManager = SimpleArcPeerManager<
    SocketDescriptor,
    ChainMonitor,
    BitcoindClient,
    BitcoindClient,
    GossipVerifier,
    FilesystemLogger,
>;

pub(crate) type ChannelManager =
    SimpleArcChannelManager<ChainMonitor, BitcoindClient, BitcoindClient, FilesystemLogger>;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<FilesystemLogger>>;

pub(crate) type OnionMessenger =
    SimpleArcOnionMessenger<ChainMonitor, BitcoindClient, BitcoindClient, FilesystemLogger>;

async fn handle_ldk_events(
    event: Event,
    unlocked_state: Arc<UnlockedAppState>,
    static_state: Arc<StaticState>,
) {
    match event {
        Event::FundingGenerationReady {
            temporary_channel_id,
            counterparty_node_id,
            channel_value_satoshis,
            output_script,
            ..
        } => {
            let addr = WitnessProgram::from_scriptpubkey(
                &output_script[..],
                match static_state.network {
                    Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
                    Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
                    Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
                    Network::Signet => bitcoin_bech32::constants::Network::Signet,
                },
            )
            .expect("Lightning funding tx should always be to a SegWit output")
            .to_scriptpubkey();
            let script_buf = ScriptBuf::from_bytes(addr);

            let (rgb_info, _) = get_rgb_channel_info(
                &temporary_channel_id,
                &PathBuf::from(&static_state.ldk_data_dir),
            );

            let channel_rgb_amount: u64 = rgb_info.local_rgb_amount;
            let asset_id = rgb_info.contract_id.to_string();

            let recipient_map = map! {
                asset_id.clone() => vec![Recipient {
                    recipient_data: RecipientData::WitnessData {
                        script_buf,
                        amount_sat: channel_value_satoshis,
                        blinding: Some(STATIC_BLINDING),
                    },
                    amount: channel_rgb_amount,
                    transport_endpoints: vec![static_state.proxy_endpoint.clone()]
                }]
            };

            let unlocked_state_copy = unlocked_state.clone();
            let online_copy = unlocked_state.rgb_online.clone();
            let unsigned_psbt = tokio::task::spawn_blocking(move || {
                unlocked_state_copy
                    .get_rgb_wallet()
                    .send_begin(
                        online_copy,
                        recipient_map,
                        true,
                        FEE_RATE,
                        MIN_CHANNEL_CONFIRMATIONS,
                    )
                    .unwrap()
            })
            .await
            .unwrap();

            let signed_psbt = unlocked_state
                .get_rgb_wallet()
                .sign_psbt(unsigned_psbt)
                .unwrap();

            let psbt = BdkPsbt::from_str(&signed_psbt).unwrap();

            let funding_tx = psbt.clone().extract_tx();
            let funding_txid = funding_tx.txid().to_string();

            let psbt_path = format!("{}/psbt_{funding_txid}", static_state.ldk_data_dir);
            fs::write(psbt_path, psbt.to_string()).unwrap();

            let consignment_path = unlocked_state
                .get_rgb_wallet()
                .get_wallet_dir()
                .join("transfers")
                .join(funding_txid.clone())
                .join(asset_id)
                .join("consignment_out");
            let proxy_ref = (*static_state.proxy_client).clone();
            let proxy_url_copy = static_state.proxy_url.clone();
            let res = post_consignment(
                proxy_ref,
                &proxy_url_copy,
                funding_txid.clone(),
                consignment_path,
                funding_txid,
                Some(0),
            )
            .await;
            if res.is_err() || res.unwrap().result.is_none() {
                tracing::error!("Cannot post consignment");
                return;
            }

            let channel_manager_copy = unlocked_state.channel_manager.clone();

            // Give the funding transaction back to LDK for opening the channel.
            if channel_manager_copy
                .funding_transaction_generated(
                    &temporary_channel_id,
                    &counterparty_node_id,
                    funding_tx,
                )
                .is_err()
            {
                tracing::error!(
                        "ERROR: Channel went away before we could fund it. The peer disconnected or refused the channel.");
            }
        }
        Event::PaymentClaimable {
            payment_hash,
            purpose,
            amount_msat,
            receiver_node_id: _,
            via_channel_id: _,
            via_user_channel_id: _,
            claim_deadline: _,
            onion_fields: _,
            counterparty_skimmed_fee_msat: _,
        } => {
            tracing::info!(
                "EVENT: received payment from payment hash {} of {} millisatoshis",
                payment_hash,
                amount_msat,
            );
            let payment_preimage = match purpose {
                PaymentPurpose::InvoicePayment {
                    payment_preimage, ..
                } => payment_preimage,
                PaymentPurpose::SpontaneousPayment(preimage) => Some(preimage),
            };
            unlocked_state
                .channel_manager
                .claim_funds(payment_preimage.unwrap());
        }
        Event::PaymentClaimed {
            payment_hash,
            purpose,
            amount_msat,
            receiver_node_id: _,
            htlcs: _,
            sender_intended_total_msat: _,
        } => {
            tracing::info!(
                "EVENT: claimed payment from payment hash {} of {} millisatoshis",
                payment_hash,
                amount_msat,
            );
            let (payment_preimage, payment_secret) = match purpose {
                PaymentPurpose::InvoicePayment {
                    payment_preimage,
                    payment_secret,
                    ..
                } => (payment_preimage, Some(payment_secret)),
                PaymentPurpose::SpontaneousPayment(preimage) => (Some(preimage), None),
            };
            let mut inbound = unlocked_state.get_inbound_payments();
            match inbound.payments.entry(payment_hash) {
                Entry::Occupied(mut e) => {
                    let payment = e.get_mut();
                    payment.status = HTLCStatus::Succeeded;
                    payment.preimage = payment_preimage;
                    payment.secret = payment_secret;
                }
                Entry::Vacant(e) => {
                    e.insert(PaymentInfo {
                        preimage: payment_preimage,
                        secret: payment_secret,
                        status: HTLCStatus::Succeeded,
                        amt_msat: Some(amount_msat),
                    });
                }
            }
            unlocked_state
                .fs_store
                .write("", "", INBOUND_PAYMENTS_FNAME, &inbound.encode())
                .unwrap();
        }
        Event::PaymentSent {
            payment_preimage,
            payment_hash,
            fee_paid_msat,
            payment_id,
            ..
        } => {
            let mut outbound = unlocked_state.get_outbound_payments();
            for (id, payment) in outbound.payments.iter_mut() {
                if *id == payment_id.unwrap() {
                    payment.preimage = Some(payment_preimage);
                    payment.status = HTLCStatus::Succeeded;
                    tracing::info!(
                        "EVENT: successfully sent payment of {:?} millisatoshis{} from \
                                payment hash {} with preimage {}",
                        payment.amt_msat,
                        if let Some(fee) = fee_paid_msat {
                            format!(" (fee {} msat)", fee)
                        } else {
                            "".to_string()
                        },
                        payment_hash,
                        payment_preimage
                    );
                }
            }
            unlocked_state
                .fs_store
                .write("", "", OUTBOUND_PAYMENTS_FNAME, &outbound.encode())
                .unwrap();
        }
        Event::OpenChannelRequest {
            ref temporary_channel_id,
            ref counterparty_node_id,
            ..
        } => {
            let mut random_bytes = [0u8; 16];
            random_bytes
                .copy_from_slice(&unlocked_state.keys_manager.get_secure_random_bytes()[..16]);
            let user_channel_id = u128::from_be_bytes(random_bytes);
            let res = unlocked_state.channel_manager.accept_inbound_channel(
                temporary_channel_id,
                counterparty_node_id,
                user_channel_id,
            );

            if let Err(e) = res {
                tracing::error!(
                    "EVENT: Failed to accept inbound channel ({}) from {}: {:?}",
                    temporary_channel_id,
                    hex_str(&counterparty_node_id.serialize()),
                    e,
                );
            } else {
                tracing::info!(
                    "EVENT: Accepted inbound channel ({}) from {}",
                    temporary_channel_id,
                    hex_str(&counterparty_node_id.serialize()),
                );
            }
        }
        Event::PaymentPathSuccessful { .. } => {}
        Event::PaymentPathFailed { .. } => {}
        Event::ProbeSuccessful { .. } => {}
        Event::ProbeFailed { .. } => {}
        Event::PaymentFailed {
            payment_hash,
            reason,
            payment_id,
            ..
        } => {
            tracing::error!(
                "EVENT: Failed to send payment to payment hash {:?}: {:?}",
                payment_hash,
                if let Some(r) = reason {
                    r
                } else {
                    PaymentFailureReason::RetriesExhausted
                }
            );

            let mut outbound = unlocked_state.get_outbound_payments();
            if outbound.payments.contains_key(&payment_id) {
                let payment = outbound.payments.get_mut(&payment_id).unwrap();
                payment.status = HTLCStatus::Failed;
            }
            unlocked_state
                .fs_store
                .write("", "", OUTBOUND_PAYMENTS_FNAME, &outbound.encode())
                .unwrap();
        }
        Event::InvoiceRequestFailed { payment_id } => {
            tracing::error!(
                "EVENT: Failed to request invoice to send payment with id {}",
                payment_id,
            );

            let mut outbound = unlocked_state.get_outbound_payments();
            if outbound.payments.contains_key(&payment_id) {
                let payment = outbound.payments.get_mut(&payment_id).unwrap();
                payment.status = HTLCStatus::Failed;
            }
            unlocked_state
                .fs_store
                .write("", "", OUTBOUND_PAYMENTS_FNAME, &outbound.encode())
                .unwrap();
        }
        Event::PaymentForwarded {
            prev_channel_id,
            next_channel_id,
            fee_earned_msat,
            claim_from_onchain_tx,
            outbound_amount_forwarded_msat,
        } => {
            let read_only_network_graph = unlocked_state.network_graph.read_only();
            let nodes = read_only_network_graph.nodes();
            let channels = unlocked_state.channel_manager.list_channels();

            let node_str = |channel_id: &Option<ChannelId>| match channel_id {
                None => String::new(),
                Some(channel_id) => match channels.iter().find(|c| c.channel_id == *channel_id) {
                    None => String::new(),
                    Some(channel) => {
                        match nodes.get(&NodeId::from_pubkey(&channel.counterparty.node_id)) {
                            None => "private node".to_string(),
                            Some(node) => match &node.announcement_info {
                                None => "unnamed node".to_string(),
                                Some(announcement) => {
                                    format!("node {}", announcement.alias)
                                }
                            },
                        }
                    }
                },
            };
            let channel_str = |channel_id: &Option<ChannelId>| {
                channel_id
                    .map(|channel_id| format!(" with channel {}", channel_id))
                    .unwrap_or_default()
            };
            let from_prev_str = format!(
                " from {}{}",
                node_str(&prev_channel_id),
                channel_str(&prev_channel_id)
            );
            let to_next_str = format!(
                " to {}{}",
                node_str(&next_channel_id),
                channel_str(&next_channel_id)
            );

            let from_onchain_str = if claim_from_onchain_tx {
                "from onchain downstream claim"
            } else {
                "from HTLC fulfill message"
            };
            let amt_args = if let Some(v) = outbound_amount_forwarded_msat {
                format!("{}", v)
            } else {
                "?".to_string()
            };
            if let Some(fee_earned) = fee_earned_msat {
                tracing::info!(
                    "EVENT: Forwarded payment for {} msat{}{}, earning {} msat {}",
                    amt_args,
                    from_prev_str,
                    to_next_str,
                    fee_earned,
                    from_onchain_str
                );
            } else {
                tracing::info!(
                    "EVENT: Forwarded payment for {} msat{}{}, claiming onchain {}",
                    amt_args,
                    from_prev_str,
                    to_next_str,
                    from_onchain_str
                );
            }
        }
        Event::HTLCHandlingFailed { .. } => {}
        Event::PendingHTLCsForwardable { time_forwardable } => {
            let forwarding_channel_manager = unlocked_state.channel_manager.clone();
            let min = time_forwardable.as_millis() as u64;
            tokio::spawn(async move {
                let millis_to_sleep = thread_rng().gen_range(min..(min * 5));
                tokio::time::sleep(Duration::from_millis(millis_to_sleep)).await;
                forwarding_channel_manager.process_pending_htlc_forwards();
            });
        }
        Event::SpendableOutputs {
            outputs,
            channel_id: _,
        } => {
            // SpendableOutputDescriptors, of which outputs is a vec of, are critical to keep track
            // of! While a `StaticOutput` descriptor is just an output to a static, well-known key,
            // other descriptors are not currently ever regenerated for you by LDK. Once we return
            // from this method, the descriptor will be gone, and you may lose track of some funds.
            //
            // Here we simply persist them to disk, with a background task running which will try
            // to spend them regularly (possibly duplicatively/RBF'ing them). These can just be
            // treated as normal funds where possible - they are only spendable by us and there is
            // no rush to claim them.
            for output in outputs {
                let key = hex_str(&unlocked_state.keys_manager.get_secure_random_bytes());
                // Note that if the type here changes our read code needs to change as well.
                let output: SpendableOutputDescriptor = output;
                unlocked_state
                    .fs_store
                    .write(PENDING_SPENDABLE_OUTPUT_DIR, "", &key, &output.encode())
                    .unwrap();
            }
        }
        Event::ChannelPending {
            channel_id,
            counterparty_node_id,
            funding_txo,
            ..
        } => {
            tracing::info!(
                "EVENT: Channel {} with peer {} is pending awaiting funding lock-in!",
                channel_id,
                hex_str(&counterparty_node_id.serialize()),
            );

            let funding_txid = funding_txo.txid.to_string();
            let psbt_path = format!("{}/psbt_{funding_txid}", static_state.ldk_data_dir);

            if Path::new(&psbt_path).exists() {
                let psbt_str = fs::read_to_string(psbt_path).unwrap();

                let state_copy = unlocked_state.clone();
                let online_copy = unlocked_state.rgb_online.clone();
                let psbt_str_copy = psbt_str.clone();
                let _txid = tokio::task::spawn_blocking(move || {
                    state_copy
                        .get_rgb_wallet()
                        .send_end(online_copy, psbt_str_copy)
                        .unwrap()
                })
                .await
                .unwrap();
            } else {
                // acceptor
                let consignment_path =
                    format!("{}/consignment_{funding_txid}", static_state.ldk_data_dir);
                let consignment = Bindle::<RgbTransfer>::load(consignment_path)
                    .expect("successful consignment load");
                let contract_id = consignment.contract_id();
                let schema_id = consignment.schema_id().to_string();
                let asset_schema = AssetSchema::from_schema_id(schema_id).unwrap();
                let mut runtime = get_rgb_runtime(Path::new(&static_state.ldk_data_dir));

                match unlocked_state.get_rgb_wallet().save_new_asset(
                    &mut runtime,
                    &asset_schema,
                    contract_id,
                ) {
                    Ok(_) => {}
                    Err(e) if e.to_string().contains("UNIQUE constraint failed") => {}
                    Err(e) => panic!("Failed saving asset: {}", e),
                }
            }
        }
        Event::ChannelReady {
            ref channel_id,
            user_channel_id: _,
            ref counterparty_node_id,
            channel_type: _,
        } => {
            tracing::info!(
                "EVENT: Channel {} with peer {} is ready to be used!",
                channel_id,
                hex_str(&counterparty_node_id.serialize()),
            );

            tokio::task::spawn_blocking(move || {
                unlocked_state
                    .get_rgb_wallet()
                    .refresh(unlocked_state.rgb_online.clone(), None, vec![])
                    .unwrap();
                unlocked_state
                    .get_rgb_wallet()
                    .refresh(unlocked_state.rgb_online.clone(), None, vec![])
                    .unwrap()
            })
            .await
            .unwrap();
        }
        Event::ChannelClosed {
            channel_id,
            reason,
            user_channel_id: _,
            counterparty_node_id,
            channel_capacity_sats: _,
        } => {
            tracing::info!(
                "EVENT: Channel {} with counterparty {} closed due to: {:?}",
                channel_id,
                counterparty_node_id
                    .map(|id| format!("{}", id))
                    .unwrap_or("".to_owned()),
                reason
            );
        }
        Event::DiscardFunding { .. } => {
            // A "real" node should probably "lock" the UTXOs spent in funding transactions until
            // the funding transaction either confirms, or this event is generated.
        }
        Event::HTLCIntercepted { .. } => {}
        Event::BumpTransaction(_event) => {
            unreachable!("BumpTxEventHandler needs to be implemented")
        }
    }
}

async fn _spend_outputs(
    outputs: Vec<SpendableOutputDescriptor>,
    unlocked_state: Arc<UnlockedAppState>,
    static_state: Arc<StaticState>,
) {
    let secp_ctx = Secp256k1::new();
    let output_descriptors = &outputs.iter().collect::<Vec<_>>();
    let tx_feerate = FEE_RATE as u32 * 250; // 1 sat/vB = 250 sat/kw

    let mut vanilla_output_descriptors = vec![];
    let mut need_rgb_refresh = false;

    for outp in output_descriptors {
        let outpoint = match outp {
            SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => descriptor.outpoint,
            SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => descriptor.outpoint,
            SpendableOutputDescriptor::StaticOutput {
                ref outpoint,
                output: _,
            } => *outpoint,
        };

        let txid = outpoint.txid;
        let witness_txid = RgbTxid::from_str(&txid.to_string()).unwrap();

        let transfer_info_path = format!("{}/{txid}_transfer_info", static_state.ldk_data_dir);
        if !Path::new(&transfer_info_path).exists() {
            vanilla_output_descriptors.push(*outp);
            continue;
        };

        let transfer_info = read_rgb_transfer_info(&transfer_info_path);
        if transfer_info.rgb_amount == 0 {
            vanilla_output_descriptors.push(*outp);
            continue;
        }

        need_rgb_refresh = true;

        let contract_id = transfer_info.contract_id;

        let receive_data = unlocked_state
            .get_rgb_wallet()
            .witness_receive(
                None,
                None,
                None,
                vec![static_state.proxy_endpoint.clone()],
                0,
            )
            .unwrap();
        let script_buf_str = receive_data.recipient_id;
        let script_buf = ScriptBuf::from_hex(&script_buf_str).unwrap();
        let bdk_script = BdkScript::from(script_buf.clone().into_bytes());

        let mut runtime = get_rgb_runtime(Path::new(&static_state.ldk_data_dir));

        runtime
            .runtime
            .consume_anchor(transfer_info.anchor)
            .expect("should consume anchor");
        for (id, bundle) in transfer_info.bundles {
            runtime
                .runtime
                .consume_bundle(id, bundle, witness_txid)
                .expect("should consume bundle");
        }

        let rgb_inputs: Vec<OutPoint> = vec![OutPoint {
            txid: outpoint.txid,
            vout: outpoint.index as u32,
        }];

        let amt_rgb = transfer_info.rgb_amount;

        let asset_transition_builder = runtime
            .runtime
            .transition_builder(
                contract_id,
                TypeName::try_from("RGB20").unwrap(),
                None::<&str>,
            )
            .expect("ok");
        let assignment_id = asset_transition_builder
            .assignments_type(&FieldName::from("beneficiary"))
            .expect("valid assignment");
        let mut beneficiaries = vec![];

        let (tx, vout, consignment) = match outp {
            SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => {
                let signer = unlocked_state.keys_manager.derive_channel_keys(
                    descriptor.channel_value_satoshis,
                    &descriptor.channel_keys_id,
                );
                let intermediate_wallet =
                    get_bdk_wallet_seckey(static_state.network, signer.payment_key);
                sync_wallet(&intermediate_wallet, static_state.electrum_url.clone());
                let mut builder = intermediate_wallet.build_tx();
                builder
                    .add_utxos(&rgb_inputs)
                    .expect("valid utxos")
                    .fee_rate(FeeRate::from_sat_per_vb(FEE_RATE))
                    .manually_selected_only()
                    .ordering(bdk::wallet::tx_builder::TxOrdering::Untouched)
                    .add_data(&[1])
                    .drain_to(bdk_script);
                let psbt = builder.finish().expect("valid psbt finish").0;

                let (vout, asset_transition_builder) = update_transition_beneficiary(
                    &psbt,
                    &mut beneficiaries,
                    asset_transition_builder,
                    assignment_id,
                    amt_rgb,
                );
                let (mut psbt, consignment) =
                    runtime.send_rgb(contract_id, psbt, asset_transition_builder, beneficiaries);

                intermediate_wallet
                    .sign(&mut psbt, SignOptions::default())
                    .expect("able to sign");

                (psbt.extract_tx(), vout, consignment)
            }
            SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => {
                let signer = unlocked_state.keys_manager.derive_channel_keys(
                    descriptor.channel_value_satoshis,
                    &descriptor.channel_keys_id,
                );
                let input = vec![TxIn {
                    previous_output: descriptor.outpoint.into_bitcoin_outpoint(),
                    script_sig: Script::new(),
                    sequence: Sequence(descriptor.to_self_delay as u32),
                    witness: Witness::new(),
                }];
                let witness_weight = DelayedPaymentOutputDescriptor::MAX_WITNESS_LENGTH;
                let input_value = descriptor.output.value;
                let output = vec![TxOut {
                    value: 0,
                    script_pubkey: Script::new_op_return(&[1]),
                }];
                let mut spend_tx = Transaction {
                    version: 2,
                    lock_time: PackedLockTime(0),
                    input,
                    output,
                };
                let _expected_max_weight =
                    lightning::util::transaction_utils::maybe_add_change_output(
                        &mut spend_tx,
                        input_value,
                        witness_weight,
                        tx_feerate,
                        bdk_script,
                    )
                    .expect("can add change");

                let psbt = PartiallySignedTransaction::from_unsigned_tx(spend_tx.clone())
                    .expect("valid transaction");

                let (vout, asset_transition_builder) = update_transition_beneficiary(
                    &psbt,
                    &mut beneficiaries,
                    asset_transition_builder,
                    assignment_id,
                    amt_rgb,
                );
                let (psbt, consignment) =
                    runtime.send_rgb(contract_id, psbt, asset_transition_builder, beneficiaries);

                let mut spend_tx = psbt.extract_tx();
                let input_idx = 0;
                let witness_vec = signer
                    .sign_dynamic_p2wsh_input(&spend_tx, input_idx, descriptor, &secp_ctx)
                    .expect("possible dynamic sign");
                spend_tx.input[input_idx].witness = Witness::from_vec(witness_vec);

                (spend_tx, vout, consignment)
            }
            SpendableOutputDescriptor::StaticOutput {
                outpoint: _,
                ref output,
            } => {
                let derivation_idx =
                    if output.script_pubkey == unlocked_state.keys_manager.destination_script {
                        1
                    } else {
                        2
                    };
                let secret = unlocked_state
                    .keys_manager
                    .master_key
                    .ckd_priv(
                        &secp_ctx,
                        ChildNumber::from_hardened_idx(derivation_idx).unwrap(),
                    )
                    .unwrap();
                let intermediate_wallet =
                    get_bdk_wallet_seckey(static_state.network, secret.private_key);
                sync_wallet(&intermediate_wallet, static_state.electrum_url.clone());
                let mut builder = intermediate_wallet.build_tx();
                builder
                    .add_utxos(&rgb_inputs)
                    .expect("valid utxos")
                    .fee_rate(FeeRate::from_sat_per_vb(FEE_RATE))
                    .manually_selected_only()
                    .ordering(bdk::wallet::tx_builder::TxOrdering::Untouched)
                    .add_data(&[1])
                    .drain_to(bdk_script);
                let psbt = builder.finish().expect("valid psbt finish").0;

                let (vout, asset_transition_builder) = update_transition_beneficiary(
                    &psbt,
                    &mut beneficiaries,
                    asset_transition_builder,
                    assignment_id,
                    amt_rgb,
                );
                let (mut psbt, consignment) =
                    runtime.send_rgb(contract_id, psbt, asset_transition_builder, beneficiaries);

                intermediate_wallet
                    .sign(&mut psbt, SignOptions::default())
                    .expect("able to sign");

                (psbt.extract_tx(), vout, consignment)
            }
        };

        broadcast_tx(&tx, static_state.electrum_url.clone());

        let closing_txid = tx.txid().to_string();
        let consignment_path = format!("{}/consignment_{closing_txid}", static_state.ldk_data_dir);
        consignment
            .save(&consignment_path)
            .expect("successful save");
        let proxy_ref = (*static_state.proxy_client).clone();
        let proxy_url_copy = static_state.proxy_url.clone();
        let res = post_consignment(
            proxy_ref,
            &proxy_url_copy,
            script_buf_str,
            consignment_path.into(),
            closing_txid,
            Some(vout),
        )
        .await;
        if res.is_err() || res.unwrap().result.is_none() {
            tracing::error!("Cannot post consignment");
            return;
        }
    }

    if !vanilla_output_descriptors.is_empty() {
        let address_str = unlocked_state.get_rgb_wallet().get_address().unwrap();
        let address = Address::from_str(&address_str).unwrap().assume_checked();
        let script_buf = address.script_pubkey();
        let bdk_script = BdkScript::from(script_buf.into_bytes());

        // We set nLockTime to the current height to discourage fee sniping.
        // Occasionally randomly pick a nLockTime even further back, so
        // that transactions that are delayed after signing for whatever reason,
        // e.g. high-latency mix networks and some CoinJoin implementations, have
        // better privacy.
        // Logic copied from core: https://github.com/bitcoin/bitcoin/blob/1d4846a8443be901b8a5deb0e357481af22838d0/src/wallet/spend.cpp#L936
        let mut cur_height = unlocked_state.channel_manager.current_best_block().height();

        // 10% of the time
        if thread_rng().gen_range(0..10) == 0 {
            // subtract random number between 0 and 100
            cur_height = cur_height.saturating_sub(thread_rng().gen_range(0..100));
        }

        let locktime: PackedLockTime =
            LockTime::from_height(cur_height).map_or(PackedLockTime::ZERO, |l| l.into());

        if let Ok(spending_tx) = unlocked_state.keys_manager.spend_spendable_outputs(
            output_descriptors,
            Vec::new(),
            bdk_script,
            tx_feerate,
            Some(locktime),
            &Secp256k1::new(),
        ) {
            // Note that, most likely, we've already sweeped this set of outputs
            // and they're already confirmed on-chain, so this broadcast will fail.
            broadcast_tx(&spending_tx, static_state.electrum_url.clone());
        } else {
            tracing::error!("Failed to sweep spendable outputs! This may indicate the outputs are dust. Will try again in a day.");
        }
    }

    if need_rgb_refresh {
        tokio::task::spawn_blocking(move || {
            unlocked_state
                .get_rgb_wallet()
                .refresh(unlocked_state.rgb_online.clone(), None, vec![])
                .unwrap();
            unlocked_state
                .get_rgb_wallet()
                .refresh(unlocked_state.rgb_online.clone(), None, vec![])
                .unwrap()
        })
        .await
        .unwrap();
    }
}

/// If we have any pending claimable outputs, we should slowly sweep them to our BDK
/// wallet. We technically don't need to do this - they're ours to spend when we want and can just
/// use them to build new transactions instead, but we cannot feed them direclty into BDK's
/// wallet so we have to sweep.
async fn periodic_sweep(
    unlocked_state: Arc<UnlockedAppState>,
    static_state: Arc<StaticState>,
    stop_processing: Arc<AtomicBool>,
) {
    // Regularly claim outputs which are exclusively spendable by us and send them to BDK.
    // Note that if you more tightly integrate your wallet with LDK you may not need to do this -
    // these outputs can just be treated as normal outputs during coin selection.
    let pending_spendables_dir = format!(
        "{}/{}",
        static_state.ldk_data_dir, PENDING_SPENDABLE_OUTPUT_DIR
    );
    let processing_spendables_dir =
        format!("{}/processing_spendable_outputs", static_state.ldk_data_dir);
    let spendables_dir = format!("{}/spendable_outputs", static_state.ldk_data_dir);

    // We batch together claims of all spendable outputs generated each day, however only after
    // batching any claims of spendable outputs which were generated prior to restart. On a mobile
    // device we likely won't ever be online for more than a minute, so we have to ensure we sweep
    // any pending claims on startup, but for an always-online node you may wish to sweep even less
    // frequently than this (or move the interval await to the top of the loop)!
    //
    // There is no particular rush here, we just have to ensure funds are availably by the time we
    // need to send funds.
    #[cfg(test)]
    let interval_secs = 5;
    #[cfg(not(test))]
    let interval_secs = 60 * 60 * 24;
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await; // Note that the first tick completes immediately
        if stop_processing.load(Ordering::Acquire) {
            return;
        }
        if let Ok(dir_iter) = fs::read_dir(&pending_spendables_dir) {
            // Move any spendable descriptors from pending folder so that we don't have any
            // races with new files being added.
            for file_res in dir_iter {
                let file = file_res.unwrap();
                // Only move a file if its a 32-byte-hex'd filename, otherwise it might be a
                // temporary file.
                if file.file_name().len() == 64 {
                    fs::create_dir_all(&processing_spendables_dir).unwrap();
                    let mut holding_path = PathBuf::new();
                    holding_path.push(&processing_spendables_dir);
                    holding_path.push(&file.file_name());
                    fs::rename(file.path(), holding_path).unwrap();
                }
            }
            // Now concatenate all the pending files we moved into one file in the
            // `spendable_outputs` directory and drop the processing directory.
            let mut outputs = Vec::new();
            if let Ok(processing_iter) = fs::read_dir(&processing_spendables_dir) {
                for file_res in processing_iter {
                    outputs.append(&mut fs::read(file_res.unwrap().path()).unwrap());
                }
            }
            if !outputs.is_empty() {
                let key = hex_str(
                    &Arc::clone(&unlocked_state)
                        .keys_manager
                        .get_secure_random_bytes(),
                );
                unlocked_state
                    .persister
                    .write(
                        "spendable_outputs",
                        "",
                        &key,
                        &WithoutLength(&outputs).encode(),
                    )
                    .unwrap();
                fs::remove_dir_all(&processing_spendables_dir).unwrap();
            }
        }
        // Iterate over all the sets of spendable outputs in `spendables_dir` and try to claim
        // them.
        // Note that here we try to claim each set of spendable outputs over and over again
        // forever, even long after its been claimed. While this isn't an issue per se, in practice
        // you may wish to track when the claiming transaction has confirmed and remove the
        // spendable outputs set. You may also wish to merge groups of unspent spendable outputs to
        // combine batches.
        if let Ok(dir_iter) = fs::read_dir(&spendables_dir) {
            for file_res in dir_iter {
                let mut outputs: Vec<SpendableOutputDescriptor> = Vec::new();
                let file_path = file_res.unwrap().path();
                let mut file = fs::File::open(&file_path).unwrap();
                loop {
                    // Check if there are any bytes left to read, and if so read a descriptor.
                    match file.read_exact(&mut [0; 1]) {
                        Ok(_) => {
                            file.seek(SeekFrom::Current(-1)).unwrap();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => Err(e).unwrap(),
                    }
                    outputs.push(Readable::read(&mut file).unwrap());
                }

                _spend_outputs(
                    outputs,
                    Arc::clone(&unlocked_state),
                    Arc::clone(&static_state),
                )
                .await;
                // TODO: Removing file for now but should be addressed properly in the future.
                fs::remove_file(file_path).unwrap();
            }
        }
    }
}

pub(crate) async fn start_ldk(
    app_state: Arc<AppState>,
    mnemonic: Mnemonic,
) -> Result<(LdkBackgroundServices, Arc<UnlockedAppState>), APIError> {
    let static_state = &app_state.static_state;

    let bitcoind_client = static_state.bitcoind_client.clone();
    let ldk_data_dir = static_state.ldk_data_dir.clone();
    let ldk_data_dir_path = PathBuf::from(&ldk_data_dir);
    let logger = static_state.logger.clone();
    let network = static_state.network;
    let ldk_peer_listening_port = static_state.ldk_peer_listening_port;
    let ldk_announced_listen_addr = static_state.ldk_announced_listen_addr.clone();
    let ldk_announced_node_name = static_state.ldk_announced_node_name;
    let electrum_url = static_state.electrum_url.clone();
    let bitcoin_network = get_bitcoin_network(&network);

    // Initialize the FeeEstimator
    // BitcoindClient implements the FeeEstimator trait, so it'll act as our fee estimator.
    let fee_estimator = bitcoind_client.clone();

    // Initialize the BroadcasterInterface
    // BitcoindClient implements the BroadcasterInterface trait, so it'll act as our transaction
    // broadcaster.
    let broadcaster = bitcoind_client.clone();

    // Initialize the KeysManager
    // The key seed that we use to derive the node privkey (that corresponds to the node pubkey) and
    // other secret key material.
    let xkey: ExtendedKey = mnemonic
        .clone()
        .into_extended_key()
        .expect("a valid key should have been provided");
    let master_xprv = &xkey
        .into_xprv(network)
        .expect("should be possible to get an extended private key");
    let secp = Secp256k1::new();
    let xprv: ExtendedPrivKey = master_xprv
        .ckd_priv(&secp, ChildNumber::Hardened { index: 535 })
        .unwrap();
    let ldk_seed: [u8; 32] = xprv.private_key.secret_bytes();
    let cur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let keys_manager = Arc::new(KeysManager::new(
        &ldk_seed,
        cur.as_secs(),
        cur.subsec_nanos(),
        ldk_data_dir_path.clone(),
    ));

    // Initialize Persistence
    let fs_store = Arc::new(FilesystemStore::new(ldk_data_dir.clone().into()));
    let persister = Arc::new(MonitorUpdatingPersister::new(
        Arc::clone(&fs_store),
        Arc::clone(&logger),
        1000,
        Arc::clone(&keys_manager),
        Arc::clone(&keys_manager),
        ldk_data_dir_path.clone(),
    ));

    // Initialize the ChainMonitor
    let chain_monitor: Arc<ChainMonitor> = Arc::new(chainmonitor::ChainMonitor::new(
        None,
        Arc::clone(&broadcaster),
        Arc::clone(&logger),
        Arc::clone(&fee_estimator),
        Arc::clone(&persister),
    ));

    // Read ChannelMonitor state from disk
    let mut channelmonitors = persister
        .read_all_channel_monitors_with_updates(&bitcoind_client, &bitcoind_client)
        .unwrap();

    // Poll for the best chain tip, which may be used by the channel manager & spv client
    let polled_chain_tip = init::validate_best_block_header(bitcoind_client.as_ref())
        .await
        .expect("Failed to fetch best block header and best block");

    // Initialize routing ProbabilisticScorer
    let network_graph_path = format!("{}/network_graph", ldk_data_dir.clone());
    let network_graph = Arc::new(disk::read_network(
        Path::new(&network_graph_path),
        network,
        logger.clone(),
    ));

    let scorer_path = format!("{}/scorer", ldk_data_dir.clone());
    let scorer = Arc::new(RwLock::new(disk::read_scorer(
        Path::new(&scorer_path),
        Arc::clone(&network_graph),
        Arc::clone(&logger),
    )));

    // Create Router
    let scoring_fee_params = ProbabilisticScoringFeeParameters::default();
    let router = Arc::new(DefaultRouter::new(
        network_graph.clone(),
        logger.clone(),
        keys_manager.get_secure_random_bytes(),
        scorer.clone(),
        scoring_fee_params,
    ));

    // Initialize the ChannelManager
    let mut user_config = UserConfig::default();
    user_config
        .channel_handshake_limits
        .force_announced_channel_preference = false;
    // TODO: set to true after implementing BumpTxEventHandler
    user_config
        .channel_handshake_config
        .negotiate_anchors_zero_fee_htlc_tx = false;
    user_config.manually_accept_inbound_channels = true;
    let mut restarting_node = true;
    let (channel_manager_blockhash, channel_manager) = {
        if let Ok(mut f) = fs::File::open(format!("{}/manager", ldk_data_dir.clone())) {
            let mut channel_monitor_mut_references = Vec::new();
            for (_, channel_monitor) in channelmonitors.iter_mut() {
                channel_monitor_mut_references.push(channel_monitor);
            }
            let read_args = ChannelManagerReadArgs::new(
                keys_manager.clone(),
                keys_manager.clone(),
                keys_manager.clone(),
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                router,
                logger.clone(),
                user_config,
                channel_monitor_mut_references,
                ldk_data_dir_path.clone(),
            );
            <(BlockHash, ChannelManager)>::read(&mut f, read_args).unwrap()
        } else {
            // We're starting a fresh node.
            restarting_node = false;

            let polled_best_block = polled_chain_tip.to_best_block();
            let polled_best_block_hash = polled_best_block.block_hash();
            let chain_params = ChainParameters {
                network,
                best_block: polled_best_block,
            };
            let fresh_channel_manager = channelmanager::ChannelManager::new(
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                router,
                logger.clone(),
                keys_manager.clone(),
                keys_manager.clone(),
                keys_manager.clone(),
                user_config,
                chain_params,
                cur.as_secs() as u32,
                ldk_data_dir_path.clone(),
            );
            (polled_best_block_hash, fresh_channel_manager)
        }
    };

    // Sync ChannelMonitors and ChannelManager to chain tip
    let mut chain_listener_channel_monitors = Vec::new();
    let mut cache = UnboundedCache::new();
    let chain_tip = if restarting_node {
        let mut chain_listeners = vec![(
            channel_manager_blockhash,
            &channel_manager as &(dyn chain::Listen + Send + Sync),
        )];

        for (blockhash, channel_monitor) in channelmonitors.drain(..) {
            let outpoint = channel_monitor.get_funding_txo().0;
            chain_listener_channel_monitors.push((
                blockhash,
                (
                    channel_monitor,
                    broadcaster.clone(),
                    fee_estimator.clone(),
                    logger.clone(),
                ),
                outpoint,
            ));
        }

        for monitor_listener_info in chain_listener_channel_monitors.iter_mut() {
            chain_listeners.push((
                monitor_listener_info.0,
                &monitor_listener_info.1 as &(dyn chain::Listen + Send + Sync),
            ));
        }

        init::synchronize_listeners(
            bitcoind_client.as_ref(),
            network,
            &mut cache,
            chain_listeners,
        )
        .await
        .unwrap()
    } else {
        polled_chain_tip
    };

    // Give ChannelMonitors to ChainMonitor
    for item in chain_listener_channel_monitors.drain(..) {
        let channel_monitor = item.1 .0;
        let funding_outpoint = item.2;
        assert_eq!(
            chain_monitor.watch_channel(funding_outpoint, channel_monitor),
            Ok(ChannelMonitorUpdateStatus::Completed)
        );
    }

    // Optional: Initialize the P2PGossipSync
    let gossip_sync = Arc::new(P2PGossipSync::new(
        Arc::clone(&network_graph),
        None,
        Arc::clone(&logger),
    ));

    // Initialize the PeerManager
    let channel_manager: Arc<ChannelManager> = Arc::new(channel_manager);
    let onion_messenger: Arc<OnionMessenger> = Arc::new(OnionMessenger::new(
        Arc::clone(&keys_manager),
        Arc::clone(&keys_manager),
        Arc::clone(&logger),
        Arc::new(DefaultMessageRouter {}),
        Arc::clone(&channel_manager),
        IgnoringMessageHandler {},
    ));
    let mut ephemeral_bytes = [0; 32];
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    rand::thread_rng().fill_bytes(&mut ephemeral_bytes);
    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: gossip_sync.clone(),
        onion_message_handler: onion_messenger.clone(),
        custom_message_handler: IgnoringMessageHandler {},
    };
    let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
        lightning_msg_handler,
        current_time.try_into().unwrap(),
        &ephemeral_bytes,
        logger.clone(),
        Arc::clone(&keys_manager),
    ));

    // Install a GossipVerifier in in the P2PGossipSync
    let utxo_lookup = GossipVerifier::new(
        Arc::clone(&bitcoind_client.bitcoind_rpc_client),
        lightning_block_sync::gossip::TokioSpawner,
        Arc::clone(&gossip_sync),
        Arc::clone(&peer_manager),
    );
    gossip_sync.add_utxo_lookup(Some(utxo_lookup));

    // ## Running LDK
    // Initialize networking

    let peer_manager_connection_handler = peer_manager.clone();
    let listening_port = ldk_peer_listening_port;
    let stop_processing = Arc::new(AtomicBool::new(false));
    let stop_listen = Arc::clone(&stop_processing);
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("[::]:{}", listening_port))
            .await
            .expect("Failed to bind to listen port - is something else already listening on it?");
        loop {
            let peer_mgr = peer_manager_connection_handler.clone();
            let tcp_stream = listener.accept().await.unwrap().0;
            if stop_listen.load(Ordering::Acquire) {
                return;
            }
            tokio::spawn(async move {
                lightning_net_tokio::setup_inbound(
                    peer_mgr.clone(),
                    tcp_stream.into_std().unwrap(),
                )
                .await;
            });
        }
    });

    // Connect and Disconnect Blocks
    let channel_manager_listener = channel_manager.clone();
    let chain_monitor_listener = chain_monitor.clone();
    let bitcoind_block_source = bitcoind_client.clone();
    tokio::spawn(async move {
        let chain_poller = poll::ChainPoller::new(bitcoind_block_source.as_ref(), network);
        let chain_listener = (chain_monitor_listener, channel_manager_listener);
        let mut spv_client = SpvClient::new(chain_tip, chain_poller, &mut cache, &chain_listener);
        loop {
            spv_client.poll_best_tip().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let inbound_payments = Arc::new(Mutex::new(disk::read_inbound_payment_info(Path::new(
        &format!("{}/{}", ldk_data_dir, INBOUND_PAYMENTS_FNAME),
    ))));
    let outbound_payments = Arc::new(Mutex::new(disk::read_outbound_payment_info(Path::new(
        &format!("{}/{}", ldk_data_dir, OUTBOUND_PAYMENTS_FNAME),
    ))));
    let recent_payments_payment_ids = channel_manager
        .list_recent_payments()
        .into_iter()
        .map(|p| match p {
            RecentPaymentDetails::Pending { payment_id, .. } => payment_id,
            RecentPaymentDetails::Fulfilled { payment_id, .. } => payment_id,
            RecentPaymentDetails::Abandoned { payment_id, .. } => payment_id,
            RecentPaymentDetails::AwaitingInvoice { payment_id } => payment_id,
        })
        .collect::<Vec<PaymentId>>();
    for (payment_id, payment_info) in outbound_payments
        .lock()
        .unwrap()
        .payments
        .iter_mut()
        .filter(|(_, i)| matches!(i.status, HTLCStatus::Pending))
    {
        if !recent_payments_payment_ids.contains(payment_id) {
            payment_info.status = HTLCStatus::Failed;
        }
    }
    fs_store
        .write(
            "",
            "",
            OUTBOUND_PAYMENTS_FNAME,
            &outbound_payments.lock().unwrap().encode(),
        )
        .unwrap();

    let xkey: ExtendedKey = mnemonic
        .clone()
        .into_extended_key()
        .expect("a valid key should have been provided");
    let xpub = xkey.into_xpub(network, &secp);
    let pubkey = xpub.to_string();
    let data_dir = static_state.storage_dir_path.clone();
    let mut rgb_wallet = tokio::task::spawn_blocking(move || {
        RgbLibWallet::new(WalletData {
            data_dir,
            bitcoin_network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: 1,
            pubkey,
            mnemonic: Some(mnemonic.to_string()),
            vanilla_keychain: None,
        })
        .expect("valid rgb-lib wallet")
    })
    .await
    .unwrap();
    let rgb_online = rgb_wallet
        .go_online(false, electrum_url.clone())
        .map_err(|e| APIError::FailedStartingLDK(e.to_string()))?;
    fs::write(
        format!(
            "{}/{WALLET_FINGERPRINT_FNAME}",
            static_state.storage_dir_path
        ),
        xpub.fingerprint().to_string(),
    )
    .expect("able to write");

    // Persist ChannelManager and NetworkGraph
    let persister = Arc::new(FilesystemStore::new(ldk_data_dir_path.clone()));

    let unlocked_state = Arc::new(UnlockedAppState {
        channel_manager: Arc::clone(&channel_manager),
        inbound_payments,
        keys_manager,
        network_graph,
        onion_messenger,
        outbound_payments,
        peer_manager: Arc::clone(&peer_manager),
        fs_store: Arc::clone(&fs_store),
        persister: Arc::clone(&persister),
        rgb_wallet: Arc::new(Mutex::new(rgb_wallet)),
        rgb_online,
    });

    // Handle LDK Events
    let unlocked_state_copy = Arc::clone(&unlocked_state);
    let static_state_copy = Arc::clone(static_state);
    let event_handler = move |event: Event| {
        let unlocked_state_copy = Arc::clone(&unlocked_state_copy);
        let static_state_copy = Arc::clone(&static_state_copy);
        async move {
            handle_ldk_events(event, unlocked_state_copy, static_state_copy).await;
        }
    };

    // Background Processing
    let (bp_exit, bp_exit_check) = tokio::sync::watch::channel(());
    let background_processor = tokio::spawn(process_events_async(
        persister,
        event_handler,
        chain_monitor.clone(),
        channel_manager.clone(),
        GossipSync::p2p(gossip_sync),
        peer_manager.clone(),
        logger.clone(),
        Some(scorer.clone()),
        move |t| {
            let mut bp_exit_fut_check = bp_exit_check.clone();
            Box::pin(async move {
                tokio::select! {
                    _ = tokio::time::sleep(t) => false,
                    _ = bp_exit_fut_check.changed() => true,
                }
            })
        },
        false,
    ));

    // Regularly reconnect to channel peers.
    let connect_cm = Arc::clone(&channel_manager);
    let connect_pm = Arc::clone(&peer_manager);
    let peer_data_path = format!("{}/channel_peer_data", ldk_data_dir.clone());
    let stop_connect = Arc::clone(&stop_processing);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match disk::read_channel_peer_data(Path::new(&peer_data_path)) {
                Ok(info) => {
                    let peers = connect_pm.get_peer_node_ids();
                    for node_id in connect_cm
                        .list_channels()
                        .iter()
                        .map(|chan| chan.counterparty.node_id)
                        .filter(|id| !peers.iter().any(|(pk, _)| id == pk))
                    {
                        if stop_connect.load(Ordering::Acquire) {
                            return;
                        }
                        for (pubkey, peer_addr) in info.iter() {
                            if *pubkey == node_id {
                                let _ =
                                    do_connect_peer(*pubkey, *peer_addr, Arc::clone(&connect_pm))
                                        .await;
                            }
                        }
                    }
                }
                Err(e) => tracing::error!(
                    "ERROR: errored reading channel peer info from disk: {:?}",
                    e
                ),
            }
        }
    });

    // Regularly broadcast our node_announcement. This is only required (or possible) if we have
    // some public channels.
    let peer_man = Arc::clone(&peer_manager);
    let chan_man = Arc::clone(&channel_manager);
    tokio::spawn(async move {
        // First wait a minute until we have some peers and maybe have opened a channel.
        tokio::time::sleep(Duration::from_secs(60)).await;
        // Then, update our announcement once an hour to keep it fresh but avoid unnecessary churn
        // in the global gossip network.
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            // Don't bother trying to announce if we don't have any public channls, though our
            // peers should drop such an announcement anyway. Note that announcement may not
            // propagate until we have a channel with 6+ confirmations.
            if chan_man.list_channels().iter().any(|chan| chan.is_public) {
                peer_man.broadcast_node_announcement(
                    [0; 3],
                    ldk_announced_node_name,
                    ldk_announced_listen_addr.clone(),
                );
            }
        }
    });

    tokio::spawn(periodic_sweep(
        Arc::clone(&unlocked_state),
        Arc::clone(static_state),
        Arc::clone(&stop_processing),
    ));

    tracing::info!("LDK logs are available at <your-supplied-ldk-data-dir-path>/.ldk/logs");
    tracing::info!("Local Node ID is {}", channel_manager.get_our_node_id());

    Ok((
        LdkBackgroundServices {
            stop_processing,
            peer_manager: peer_manager.clone(),
            bp_exit,
            background_processor: Some(background_processor),
        },
        unlocked_state,
    ))
}

pub(crate) async fn stop_ldk(app_state: Arc<AppState>) {
    tracing::info!("Stopping LDK");

    let join_handle = {
        let mut ldk_background_services = app_state.ldk_background_services.lock().unwrap();

        if ldk_background_services.is_none() {
            // node is locked
            tracing::info!("LDK is not running");
            return;
        }

        let ldk_background_services = ldk_background_services.as_mut().unwrap();

        // Disconnect our peers and stop accepting new connections. This ensures we don't continue
        // updating our channel data after we've stopped the background processor.
        ldk_background_services
            .stop_processing
            .store(true, Ordering::Release);
        ldk_background_services.peer_manager.disconnect_all_peers();

        // Stop the background processor.
        if !ldk_background_services.bp_exit.is_closed() {
            ldk_background_services.bp_exit.send(()).unwrap();
            ldk_background_services.background_processor.take()
        } else {
            None
        }
    };

    if let Some(join_handle) = join_handle {
        join_handle.await.unwrap().unwrap();
    }

    tracing::info!("Stopped LDK");
}

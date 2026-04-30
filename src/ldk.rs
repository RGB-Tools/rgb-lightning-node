use crate::async_order::{
    AsyncOrderAccessControl, AsyncOrderMessageHandler, AsyncPaymentsPreimageRoot,
};
use crate::kv_store::SeaOrmKvStore;
use amplify::{map, s};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash as BitcoinHash};
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::{io, Amount, Network};
use bitcoin::{BlockHash, TxOut};
use bitcoin_bech32::WitnessProgram;
use hex::DisplayHex;
use lightning::chain::{chainmonitor, transaction::OutPoint, ChannelMonitorUpdateStatus};
use lightning::chain::{BestBlock, Filter};
use lightning::events::bump_transaction::{BumpTransactionEventHandler, Wallet};
use lightning::events::{Event, PaymentFailureReason, PaymentPurpose, ReplayEvent};
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{self, ChannelFundingType, PaymentId, RecentPaymentDetails};
use lightning::ln::channelmanager::{
    ChainParameters, ChannelManagerReadArgs, SimpleArcChannelManager,
};
use lightning::ln::msgs::SocketAddress;
use lightning::ln::peer_handler::{
    IgnoringMessageHandler, MessageHandler, PeerManager as LdkPeerManager,
};
use lightning::ln::types::ChannelId;
use lightning::onion_message::messenger::{
    DefaultMessageRouter, OnionMessenger as LdkOnionMessenger,
};
use lightning::rgb_utils::{
    get_rgb_channel_info_pending, is_channel_rgb, update_rgb_channel_amount, RgbKvStoreExt,
    RgbPaymentInfo, RGB_PAYMENT_INFO_INBOUND_NS, RGB_PAYMENT_INFO_OUTBOUND_NS, RGB_PRIMARY_NS,
    STATIC_BLINDING,
};
use lightning::routing::gossip;
use lightning::routing::gossip::{NodeId, P2PGossipSync};
use lightning::routing::router::DefaultRouter;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters};
use lightning::sign::{
    EntropySource, InMemorySigner, KeysManager, NodeSigner, OutputSpender,
    SpendableOutputDescriptor,
};
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning::util::config::UserConfig;
use lightning::util::hash_tables::hash_map::Entry;
use lightning::util::hash_tables::{new_hash_map, HashMap as LdkHashMap};
use lightning::util::persist::{
    KVStoreSync, KVStoreSyncWrapper, MonitorUpdatingPersister, CHANNEL_MANAGER_PERSISTENCE_KEY,
    CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
    OUTPUT_SWEEPER_PERSISTENCE_KEY, OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
    OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
};
use lightning::util::ser::{Readable, ReadableArgs, Writeable};
use lightning::util::sweep as ldk_sweep;
use lightning::{chain, impl_writeable_tlv_based, impl_writeable_tlv_based_enum};
use lightning_background_processor::{process_events_async, GossipSync, NO_LIQUIDITY_MANAGER};
use lightning_block_sync::gossip::TokioSpawner;
use lightning_block_sync::init;
use lightning_block_sync::poll;
use lightning_block_sync::SpvClient;
use lightning_block_sync::UnboundedCache;
use lightning_dns_resolver::OMDomainResolver;
use lightning_invoice::PaymentSecret;
use lightning_net_tokio::SocketDescriptor;
use rand::RngCore;
use rgb_lib::{
    bdk_wallet::keys::{bip39::Mnemonic, DerivableKey, ExtendedKey},
    bitcoin::{
        bip32::{ChildNumber, Xpriv},
        psbt::Psbt as RgbLibPsbt,
        secp256k1::Secp256k1 as Secp256k1_30,
        ScriptBuf,
    },
    utils::{get_account_data, recipient_id_from_script_buf, script_buf_from_recipient_id},
    wallet::{
        rust_only::{check_indexer_url, AssetColoringInfo, ColoringInfo},
        DatabaseType, Recipient, SinglesigKeys, TransportEndpoint, Wallet as RgbLibWallet,
        WalletData, WitnessData,
    },
    AssetSchema, Assignment, BitcoinNetwork, ConsignmentExt, ContractId, Fascia, FileContent,
    RgbTransfer, RgbTxid, WitnessOrd,
};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::ToSocketAddrs;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tokio::runtime::Handle;
use tokio::sync::watch::Sender;
use tokio::task::JoinHandle;

use crate::bitcoind::BitcoindClient;
use crate::core_types::{
    HTLCStatus, SwapStatus, UnlockRequest, DUST_LIMIT_MSAT, FEE_RATE, MIN_CHANNEL_CONFIRMATIONS,
};
use crate::database::RlnDatabase;
use crate::disk::{self, FilesystemLogger};

pub(crate) const INBOUND_PAYMENTS_KEY: &str = "inbound_payments";
const OUTBOUND_PAYMENTS_KEY: &str = "outbound_payments";
const CHANNEL_IDS_KEY: &str = "channel_ids";
const MAKER_SWAPS_KEY: &str = "maker_swaps";
const TAKER_SWAPS_KEY: &str = "taker_swaps";
const OUTPUT_SPENDER_TXES_KEY: &str = "output_spender_txes";
const PSBT_NAMESPACE: &str = "psbt";
const CONFIG_INDEXER_URL: &str = "indexer_url";
const CONFIG_BITCOIN_NETWORK: &str = "bitcoin_network";
const CONFIG_WALLET_FINGERPRINT: &str = "wallet_fingerprint";
const CONFIG_WALLET_ACCOUNT_XPUB_VANILLA: &str = "wallet_account_xpub_vanilla";
const CONFIG_WALLET_ACCOUNT_XPUB_COLORED: &str = "wallet_account_xpub_colored";
const CONFIG_WALLET_MASTER_FINGERPRINT: &str = "wallet_master_fingerprint";
const VIRTUAL_CHANNEL_DRAFTS_KEY: &str = "virtual_channel_drafts";
const VIRTUAL_CHANNEL_SESSIONS_KEY: &str = "virtual_channel_sessions";
use crate::error::APIError;
use crate::rgb::{check_rgb_proxy_endpoint, get_rgb_channel_info_optional, RgbLibWalletWrapper};
use crate::swap::SwapData;
use crate::utils::{
    check_port_is_available, connect_peer_if_necessary, do_connect_peer, get_current_timestamp,
    hex_str, AppState, StaticState, UnlockedAppState, ELECTRUM_URL_MAINNET, ELECTRUM_URL_REGTEST,
    ELECTRUM_URL_SIGNET, ELECTRUM_URL_TESTNET, ELECTRUM_URL_TESTNET4, PROXY_ENDPOINT_LOCAL,
    PROXY_ENDPOINT_PUBLIC,
};

const VIRTUAL_CHANNEL_DOMAIN_SEPARATOR: &[u8] = b"rln_virtual_channels_v0";

pub(crate) fn virtual_channel_synthetic_outpoint(
    network: BitcoinNetwork,
    local_node_id: &PublicKey,
    peer_node_id: &PublicKey,
) -> OutPoint {
    let mut ordered = [local_node_id.serialize(), peer_node_id.serialize()];
    ordered.sort();
    let network_tag = match network {
        BitcoinNetwork::Mainnet => b"mainnet".as_slice(),
        BitcoinNetwork::Testnet => b"testnet".as_slice(),
        BitcoinNetwork::Testnet4 => b"testnet4".as_slice(),
        BitcoinNetwork::Regtest => b"regtest".as_slice(),
        BitcoinNetwork::Signet | BitcoinNetwork::SignetCustom => b"signet".as_slice(),
    };

    let mut preimage = Vec::with_capacity(
        VIRTUAL_CHANNEL_DOMAIN_SEPARATOR.len() + network_tag.len() + ordered[0].len() * 2,
    );
    preimage.extend_from_slice(VIRTUAL_CHANNEL_DOMAIN_SEPARATOR);
    preimage.extend_from_slice(network_tag);
    preimage.extend_from_slice(&ordered[0]);
    preimage.extend_from_slice(&ordered[1]);

    let txid = bitcoin::Txid::from_byte_array(
        <sha256::Hash as BitcoinHash>::hash(&preimage).to_byte_array(),
    );
    OutPoint { txid, index: 0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvoiceType {
    AutoClaim,
    Hodl,
}

impl_writeable_tlv_based_enum!(InvoiceType,
    (0, AutoClaim) => {},
    (1, Hodl) => {},
);

/// Save config to database (source of truth) and sync to KVStore for rust-lightning.
fn save_config(
    database: &sea_orm::DatabaseConnection,
    kv_store: &dyn KVStoreSync,
    key: &str,
    value: &str,
) -> Result<(), APIError> {
    let db = RlnDatabase::new(database.clone());
    db.set_config(key, value)?;
    kv_store.write_config(key, value);
    Ok(())
}

/// Sync config from database to KVStore on startup.
fn sync_config_to_kvstore(
    database: &sea_orm::DatabaseConnection,
    kv_store: &dyn KVStoreSync,
) -> Result<(), APIError> {
    let db = RlnDatabase::new(database.clone());

    for key in [
        CONFIG_INDEXER_URL,
        CONFIG_BITCOIN_NETWORK,
        CONFIG_WALLET_FINGERPRINT,
        CONFIG_WALLET_ACCOUNT_XPUB_VANILLA,
        CONFIG_WALLET_ACCOUNT_XPUB_COLORED,
        CONFIG_WALLET_MASTER_FINGERPRINT,
    ] {
        if let Some(value) = db.get_config(key)? {
            kv_store.write_config(key, &value);
        }
    }

    Ok(())
}

pub(crate) struct LdkBackgroundServices {
    stop_processing: Arc<AtomicBool>,
    peer_manager: Arc<PeerManager>,
    bp_exit: Sender<()>,
    background_processor: Option<JoinHandle<Result<(), io::Error>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct PaymentInfo {
    pub(crate) preimage: Option<PaymentPreimage>,
    pub(crate) secret: Option<PaymentSecret>,
    pub(crate) status: HTLCStatus,
    pub(crate) amt_msat: Option<u64>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    pub(crate) payee_pubkey: PublicKey,
    pub(crate) expires_at: Option<u64>,
    pub(crate) claim_deadline_height: Option<u32>,
    pub(crate) invoice_type: Option<InvoiceType>,
}

impl_writeable_tlv_based!(PaymentInfo, {
    (0, preimage, required),
    (2, secret, required),
    (4, status, required),
    (6, amt_msat, required),
    (8, created_at, required),
    (10, updated_at, required),
    (12, payee_pubkey, required),
    (14, expires_at, option),
    (16, claim_deadline_height, option),
    (18, invoice_type, option),
});

pub(crate) struct InboundPaymentInfoStorage {
    pub(crate) payments: LdkHashMap<PaymentHash, PaymentInfo>,
}

impl_writeable_tlv_based!(InboundPaymentInfoStorage, {
    (0, payments, required),
});

pub(crate) struct OutboundPaymentInfoStorage {
    pub(crate) payments: LdkHashMap<PaymentId, PaymentInfo>,
}

impl_writeable_tlv_based!(OutboundPaymentInfoStorage, {
    (0, payments, required),
});

pub(crate) struct SwapMap {
    pub(crate) swaps: LdkHashMap<PaymentHash, SwapData>,
}

impl_writeable_tlv_based!(SwapMap, {
    (0, swaps, required),
});

pub(crate) struct ChannelIdsMap {
    pub(crate) channel_ids: LdkHashMap<ChannelId, ChannelId>,
}

impl_writeable_tlv_based!(ChannelIdsMap, {
    (0, channel_ids, required),
});

#[derive(Clone, Debug)]
pub(crate) struct VirtualChannelDraft {
    pub(crate) created_at: u64,
    pub(crate) peer_id: PublicKey,
    pub(crate) temporary_channel_id: ChannelId,
}

impl_writeable_tlv_based!(VirtualChannelDraft, {
    (0, created_at, required),
    (2, peer_id, required),
    (4, temporary_channel_id, required),
});

pub(crate) struct VirtualChannelDraftStore {
    pub(crate) entries: LdkHashMap<ChannelId, VirtualChannelDraft>,
}

impl_writeable_tlv_based!(VirtualChannelDraftStore, {
    (0, entries, required),
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VirtualChannelSessionStatus {
    Active,
    AbandonPending,
    Abandoned,
}

impl_writeable_tlv_based_enum!(VirtualChannelSessionStatus,
    (0, Active) => {},
    (2, AbandonPending) => {},
    (4, Abandoned) => {},
);

#[derive(Clone, Debug)]
pub(crate) struct VirtualChannelSession {
    pub(crate) channel_id: ChannelId,
    pub(crate) created_at: u64,
    pub(crate) former_temporary_channel_id: ChannelId,
    pub(crate) peer_id: PublicKey,
    pub(crate) status: VirtualChannelSessionStatus,
    pub(crate) virtual_funding_txo: OutPoint,
    pub(crate) updated_at: u64,
}

impl_writeable_tlv_based!(VirtualChannelSession, {
    (0, channel_id, required),
    (2, created_at, required),
    (4, former_temporary_channel_id, required),
    (6, peer_id, required),
    (8, status, (default_value, VirtualChannelSessionStatus::Active)),
    (10, virtual_funding_txo, required),
    (12, updated_at, (default_value, created_at)),
});

pub(crate) struct VirtualChannelSessionStore {
    pub(crate) entries: LdkHashMap<ChannelId, VirtualChannelSession>,
}

impl_writeable_tlv_based!(VirtualChannelSessionStore, {
    (0, entries, required),
});

impl VirtualChannelSessionStore {
    pub(crate) fn contains_virtual_funding_txo(&self, virtual_funding_txo: &OutPoint) -> bool {
        self.entries
            .values()
            .any(|session| session.virtual_funding_txo == *virtual_funding_txo)
    }
}

impl UnlockedAppState {
    pub(crate) fn add_maker_swap(&self, payment_hash: PaymentHash, swap: SwapData) {
        let mut maker_swaps = self.get_maker_swaps();
        maker_swaps.swaps.insert(payment_hash, swap);
        self.save_maker_swaps(maker_swaps);
    }

    pub(crate) fn update_maker_swap_status(&self, payment_hash: &PaymentHash, status: SwapStatus) {
        let mut maker_swaps = self.get_maker_swaps();
        let maker_swap = maker_swaps.swaps.get_mut(payment_hash).unwrap();
        match &status {
            SwapStatus::Succeeded | SwapStatus::Failed | SwapStatus::Expired => {
                maker_swap.completed_at = Some(get_current_timestamp())
            }
            SwapStatus::Pending => maker_swap.initiated_at = Some(get_current_timestamp()),
            SwapStatus::Waiting => panic!("this doesn't make sense: swap starts in Waiting status"),
        }
        maker_swap.status = status;
        self.save_maker_swaps(maker_swaps);
    }

    pub(crate) fn is_maker_swap(&self, payment_hash: &PaymentHash) -> bool {
        self.maker_swaps().contains_key(payment_hash)
    }

    pub(crate) fn add_taker_swap(&self, payment_hash: PaymentHash, swap: SwapData) {
        let mut taker_swaps = self.get_taker_swaps();
        taker_swaps.swaps.insert(payment_hash, swap);
        self.save_taker_swaps(taker_swaps);
    }

    pub(crate) fn update_taker_swap_status(&self, payment_hash: &PaymentHash, status: SwapStatus) {
        let mut taker_swaps = self.get_taker_swaps();
        let taker_swap = taker_swaps.swaps.get_mut(payment_hash).unwrap();
        match &status {
            SwapStatus::Succeeded | SwapStatus::Failed | SwapStatus::Expired => {
                taker_swap.completed_at = Some(get_current_timestamp())
            }
            SwapStatus::Pending => taker_swap.initiated_at = Some(get_current_timestamp()),
            SwapStatus::Waiting => panic!("this doesn't make sense: swap starts in Waiting status"),
        }
        taker_swap.status = status;
        self.save_taker_swaps(taker_swaps);
    }

    pub(crate) fn is_taker_swap(&self, payment_hash: &PaymentHash) -> bool {
        self.taker_swaps().contains_key(payment_hash)
    }

    fn save_maker_swaps(&self, swaps: MutexGuard<SwapMap>) {
        self.kv_store
            .write("", "", MAKER_SWAPS_KEY, swaps.encode())
            .unwrap();
    }

    fn save_taker_swaps(&self, swaps: MutexGuard<SwapMap>) {
        self.kv_store
            .write("", "", TAKER_SWAPS_KEY, swaps.encode())
            .unwrap();
    }

    pub(crate) fn maker_swaps(&self) -> LdkHashMap<PaymentHash, SwapData> {
        self.get_maker_swaps().swaps.clone()
    }

    pub(crate) fn taker_swaps(&self) -> LdkHashMap<PaymentHash, SwapData> {
        self.get_taker_swaps().swaps.clone()
    }

    pub(crate) fn add_inbound_payment(&self, payment_hash: PaymentHash, payment_info: PaymentInfo) {
        let mut inbound = self.get_inbound_payments();
        inbound.payments.insert(payment_hash, payment_info);
        self.save_inbound_payments(inbound);
    }

    pub(crate) fn add_outbound_payment(
        &self,
        payment_id: PaymentId,
        payment_info: PaymentInfo,
    ) -> Result<(), APIError> {
        let mut outbound = self.get_outbound_payments();
        if let Some(existing_payment) = outbound.payments.get(&payment_id) {
            if !matches!(existing_payment.status, HTLCStatus::Failed) {
                return Err(APIError::DuplicatePayment(
                    existing_payment.status.to_string(),
                ));
            }
        }
        outbound.payments.insert(payment_id, payment_info);
        self.save_outbound_payments(outbound);
        Ok(())
    }

    pub(crate) fn fail_htlc_backwards_and_update_inbound_payment(
        &self,
        payment_hash: PaymentHash,
        status: HTLCStatus,
    ) {
        self.channel_manager.fail_htlc_backwards(&payment_hash);
        self.upsert_inbound_payment(
            payment_hash,
            status,
            None,
            None,
            None,
            self.channel_manager.get_our_node_id(),
            None,
            None,
        );
    }

    fn fail_outbound_pending_payments(&self, recent_payments_payment_ids: Vec<PaymentId>) {
        let mut outbound = self.get_outbound_payments();
        let mut failed = false;
        for (payment_id, payment_info) in outbound
            .payments
            .iter_mut()
            .filter(|(_, i)| matches!(i.status, HTLCStatus::Pending))
        {
            if !recent_payments_payment_ids.contains(payment_id) {
                payment_info.status = HTLCStatus::Failed;
                payment_info.updated_at = get_current_timestamp();
                failed = true;
            }
        }
        if failed {
            self.save_outbound_payments(outbound);
        }
    }

    pub(crate) fn list_updated_inbound_payments(&self) -> LdkHashMap<PaymentHash, PaymentInfo> {
        let now = get_current_timestamp();
        let height = self.channel_manager.current_best_block().height;
        let mut inbound = self.get_inbound_payments();
        let mut failed = false;
        let mut claimables_to_fail = vec![];
        for (payment_hash, payment_info) in inbound.payments.iter_mut() {
            match payment_info.status {
                HTLCStatus::Pending => {
                    if let Some(expires_at) = payment_info.expires_at {
                        if now > expires_at {
                            payment_info.status = HTLCStatus::Failed;
                            payment_info.updated_at = now;
                            failed = true;
                        }
                    }
                }
                HTLCStatus::Claimable => {
                    let deadline_passed = payment_info
                        .claim_deadline_height
                        .map(|h| height >= h)
                        .unwrap_or(false);
                    let invoice_expired = payment_info
                        .expires_at
                        .map(|expires_at| now >= expires_at)
                        .unwrap_or(false);

                    if deadline_passed || invoice_expired {
                        claimables_to_fail.push((
                            *payment_hash,
                            payment_info.claim_deadline_height,
                            payment_info.expires_at,
                        ));
                    }
                }
                _ => {}
            }
        }

        if claimables_to_fail.is_empty() {
            let payments = inbound.payments.clone();
            if failed {
                self.save_inbound_payments(inbound);
            }
            return payments;
        }

        if failed {
            self.save_inbound_payments(inbound);
        } else {
            drop(inbound);
        }

        for (payment_hash, claim_deadline_height, expires_at) in claimables_to_fail {
            tracing::info!(
                "Expiring claimable payment {:?} (deadline: {:?}, expiry: {:?})",
                payment_hash,
                claim_deadline_height,
                expires_at
            );
            self.fail_htlc_backwards_and_update_inbound_payment(payment_hash, HTLCStatus::Failed);
        }

        self.inbound_payments()
    }

    pub(crate) fn inbound_payments(&self) -> LdkHashMap<PaymentHash, PaymentInfo> {
        self.get_inbound_payments().payments.clone()
    }

    pub(crate) fn outbound_payments(&self) -> LdkHashMap<PaymentId, PaymentInfo> {
        self.get_outbound_payments().payments.clone()
    }

    pub(crate) fn save_inbound_payments(&self, inbound: MutexGuard<InboundPaymentInfoStorage>) {
        self.kv_store
            .write("", "", INBOUND_PAYMENTS_KEY, inbound.encode())
            .unwrap();
    }

    fn save_outbound_payments(&self, outbound: MutexGuard<OutboundPaymentInfoStorage>) {
        self.kv_store
            .write("", "", OUTBOUND_PAYMENTS_KEY, outbound.encode())
            .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn upsert_inbound_payment(
        &self,
        payment_hash: PaymentHash,
        status: HTLCStatus,
        preimage: Option<PaymentPreimage>,
        secret: Option<PaymentSecret>,
        amt_msat: Option<u64>,
        payee_pubkey: PublicKey,
        claim_deadline_height: Option<u32>,
        invoice_type: Option<InvoiceType>,
    ) {
        let mut inbound = self.get_inbound_payments();
        match inbound.payments.entry(payment_hash) {
            Entry::Occupied(mut e) => {
                let payment_info = e.get_mut();
                payment_info.status = status;
                payment_info.preimage = preimage;
                payment_info.secret = secret;
                if amt_msat.is_some() {
                    payment_info.amt_msat = amt_msat;
                }
                payment_info.updated_at = get_current_timestamp();
                if claim_deadline_height.is_some() {
                    payment_info.claim_deadline_height = claim_deadline_height;
                }
            }
            Entry::Vacant(e) => {
                let created_at = get_current_timestamp();
                e.insert(PaymentInfo {
                    preimage,
                    secret,
                    status,
                    amt_msat,
                    created_at,
                    updated_at: created_at,
                    payee_pubkey,
                    expires_at: None,
                    claim_deadline_height,
                    invoice_type,
                });
            }
        }
        self.save_inbound_payments(inbound);
    }

    pub(crate) fn update_outbound_payment(
        &self,
        payment_id: PaymentId,
        status: HTLCStatus,
        preimage: Option<PaymentPreimage>,
    ) -> PaymentInfo {
        let mut outbound = self.get_outbound_payments();
        let payment_info = outbound.payments.get_mut(&payment_id).unwrap();
        payment_info.status = status;
        payment_info.preimage = preimage;
        payment_info.updated_at = get_current_timestamp();
        let payment = (*payment_info).clone();
        self.save_outbound_payments(outbound);
        payment
    }

    pub(crate) fn update_outbound_payment_status(&self, payment_id: PaymentId, status: HTLCStatus) {
        let mut outbound = self.get_outbound_payments();
        let payment_info = outbound.payments.get_mut(&payment_id).unwrap();
        payment_info.status = status;
        payment_info.updated_at = get_current_timestamp();
        self.save_outbound_payments(outbound);
    }

    pub(crate) fn channel_ids(&self) -> LdkHashMap<ChannelId, ChannelId> {
        self.get_channel_ids_map().channel_ids.clone()
    }

    pub(crate) fn add_channel_id(
        &self,
        former_temporary_channel_id: ChannelId,
        channel_id: ChannelId,
    ) {
        let mut channel_ids_map = self.get_channel_ids_map();
        channel_ids_map
            .channel_ids
            .insert(former_temporary_channel_id, channel_id);
        self.save_channel_ids_map(channel_ids_map);
    }

    pub(crate) fn delete_channel_id(&self, channel_id: ChannelId) -> Option<ChannelId> {
        let mut channel_ids_map = self.get_channel_ids_map();
        if let Some(temporary_channel_id) = channel_ids_map
            .channel_ids
            .clone()
            .into_iter()
            .find_map(|(tmp_chan_id, chan_id)| {
                if chan_id == channel_id {
                    Some(tmp_chan_id)
                } else {
                    None
                }
            })
        {
            channel_ids_map.channel_ids.remove(&temporary_channel_id);
            self.save_channel_ids_map(channel_ids_map);
            Some(temporary_channel_id)
        } else {
            None
        }
    }

    fn save_channel_ids_map(&self, channel_ids: MutexGuard<ChannelIdsMap>) {
        self.kv_store
            .write("", "", CHANNEL_IDS_KEY, channel_ids.encode())
            .unwrap();
    }

    pub(crate) fn virtual_channel_add_intent(
        &self,
        peer_id: PublicKey,
        temporary_channel_id: Option<ChannelId>,
    ) -> Result<ChannelId, APIError> {
        let mut drafts = self.get_virtual_channel_draft_store();
        let duplicate_virtual_draft = drafts
            .entries
            .values()
            .any(|draft| draft.peer_id == peer_id);
        if duplicate_virtual_draft {
            return Err(APIError::InvalidRequest(
                "virtual channel draft already exists for this peer pair".to_string(),
            ));
        }

        let duplicate_virtual_session = self
            .get_virtual_channel_session_store()
            .entries
            .values()
            .any(|session| session.peer_id == peer_id);
        if duplicate_virtual_session {
            return Err(APIError::InvalidRequest(
                "virtual channel session already exists for this peer pair".to_string(),
            ));
        }

        let channel_ids = self.channel_ids();
        let temporary_channel_id = if let Some(temporary_channel_id) = temporary_channel_id {
            if channel_ids.contains_key(&temporary_channel_id)
                || drafts.entries.contains_key(&temporary_channel_id)
            {
                return Err(APIError::TemporaryChannelIdAlreadyUsed);
            }
            temporary_channel_id
        } else {
            loop {
                let mut tmp_channel_id_bytes = [0u8; 32];
                tmp_channel_id_bytes
                    .copy_from_slice(&self.keys_manager.get_secure_random_bytes()[..32]);
                let candidate = ChannelId::from_bytes(tmp_channel_id_bytes);
                if !channel_ids.contains_key(&candidate) && !drafts.entries.contains_key(&candidate)
                {
                    break candidate;
                }
            }
        };

        drafts.entries.insert(
            temporary_channel_id,
            VirtualChannelDraft {
                temporary_channel_id,
                peer_id,
                created_at: get_current_timestamp(),
            },
        );
        self.virtual_channel_draft_store_save(drafts);

        Ok(temporary_channel_id)
    }

    pub(crate) fn virtual_channel_draft_delete(&self, temporary_channel_id: &ChannelId) {
        let mut drafts = self.get_virtual_channel_draft_store();
        drafts.entries.remove(temporary_channel_id);
        self.virtual_channel_draft_store_save(drafts);
    }

    pub(crate) fn virtual_channel_draft_get(
        &self,
        temporary_channel_id: &ChannelId,
    ) -> Option<VirtualChannelDraft> {
        self.get_virtual_channel_draft_store()
            .entries
            .get(temporary_channel_id)
            .cloned()
    }

    pub(crate) fn virtual_channel_draft_store(&self) -> LdkHashMap<ChannelId, VirtualChannelDraft> {
        self.get_virtual_channel_draft_store().entries.clone()
    }

    fn virtual_channel_draft_store_save(&self, drafts: MutexGuard<VirtualChannelDraftStore>) {
        self.kv_store
            .write("", "", VIRTUAL_CHANNEL_DRAFTS_KEY, drafts.encode())
            .unwrap();
    }

    pub(crate) fn virtual_channel_ensure_no_client_value(
        &self,
        chan_details: &ChannelDetails,
    ) -> Result<(), String> {
        if chan_details.has_inflight_htlcs {
            return Err("virtual cleanup is blocked while HTLCs are still in flight".to_string());
        }
        let channel_id_hex = chan_details.channel_id.0.as_hex().to_string();
        let kv = self.kv_store.as_ref();

        for namespace in [RGB_PAYMENT_INFO_INBOUND_NS, RGB_PAYMENT_INFO_OUTBOUND_NS] {
            let keys = kv
                .list(RGB_PRIMARY_NS, namespace)
                .map_err(|_| "virtual cleanup could not inspect RGB temp artifacts".to_string())?;
            for key in keys {
                if key.starts_with(&channel_id_hex)
                    && key.len() > channel_id_hex.len()
                    && key.ends_with("_pending")
                {
                    return Err(
                        "virtual cleanup is blocked while RGB payment temp artifacts remain"
                            .to_string(),
                    );
                }
            }
        }

        match chan_details.counterparty_balance_sats_floor {
            Some(0) => {}
            Some(balance_floor) => {
                return Err(format!(
                    "virtual cleanup is blocked while counterparty BTC balance floor is {balance_floor} sat"
                ))
            }
            None => {
                return Err(
                    "virtual cleanup requires an exact counterparty BTC balance floor proof"
                        .to_string(),
                )
            }
        }

        let final_rgb_state = kv.read_rgb_channel_info(&channel_id_hex, false);
        let pending_rgb_state = kv.read_rgb_channel_info(&channel_id_hex, true);

        let is_rgb_backed = final_rgb_state.is_ok() || pending_rgb_state.is_ok();
        if !is_rgb_backed {
            return Ok(());
        }

        let final_rgb_state = final_rgb_state.map_err(|_| {
            "virtual cleanup requires both final and pending RGB channel state".to_string()
        })?;
        let pending_rgb_state = pending_rgb_state.map_err(|_| {
            "virtual cleanup requires both final and pending RGB channel state".to_string()
        })?;

        if final_rgb_state.contract_id != pending_rgb_state.contract_id
            || final_rgb_state.schema != pending_rgb_state.schema
            || final_rgb_state.local_rgb_amount != pending_rgb_state.local_rgb_amount
            || final_rgb_state.remote_rgb_amount != pending_rgb_state.remote_rgb_amount
        {
            return Err(
                "virtual cleanup is blocked while RGB channel state is still diverged".to_string(),
            );
        }

        if final_rgb_state.remote_rgb_amount != 0 {
            return Err(format!(
                "virtual cleanup is blocked while counterparty RGB balance is {}",
                final_rgb_state.remote_rgb_amount
            ));
        }

        Ok(())
    }

    pub(crate) fn virtual_channel_session_add(&self, session: VirtualChannelSession) {
        let mut sessions = self.get_virtual_channel_session_store();
        sessions.entries.insert(session.channel_id, session);
        self.virtual_channel_session_store_save(sessions);
    }

    pub(crate) fn virtual_channel_session_get(
        &self,
        channel_id: &ChannelId,
    ) -> Option<VirtualChannelSession> {
        self.get_virtual_channel_session_store()
            .entries
            .get(channel_id)
            .cloned()
    }

    pub(crate) fn virtual_channel_session_update(&self, session: VirtualChannelSession) {
        let mut sessions = self.get_virtual_channel_session_store();
        sessions.entries.insert(session.channel_id, session);
        self.virtual_channel_session_store_save(sessions);
    }

    pub(crate) fn virtual_channel_session_update_status(
        &self,
        session: &VirtualChannelSession,
        status: VirtualChannelSessionStatus,
    ) {
        let mut updated_session = session.clone();
        updated_session.status = status;
        updated_session.updated_at = get_current_timestamp();
        self.virtual_channel_session_update(updated_session);
    }

    pub(crate) fn virtual_channel_session_store(
        &self,
    ) -> LdkHashMap<ChannelId, VirtualChannelSession> {
        self.get_virtual_channel_session_store().entries.clone()
    }

    fn virtual_channel_session_store_save(&self, sessions: MutexGuard<VirtualChannelSessionStore>) {
        self.kv_store
            .write("", "", VIRTUAL_CHANNEL_SESSIONS_KEY, sessions.encode())
            .unwrap();
    }
}

pub(crate) type ChainMonitor = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<BitcoindClient>,
    Arc<BitcoindClient>,
    Arc<FilesystemLogger>,
    Arc<
        MonitorUpdatingPersister<
            Arc<SeaOrmKvStore>,
            Arc<FilesystemLogger>,
            Arc<KeysManager>,
            Arc<KeysManager>,
            Arc<BitcoindClient>,
            Arc<BitcoindClient>,
        >,
    >,
    Arc<KeysManager>,
>;

pub(crate) type GossipVerifier = lightning_block_sync::gossip::GossipVerifier<
    TokioSpawner,
    Arc<lightning_block_sync::rpc::RpcClient>,
    Arc<FilesystemLogger>,
>;

pub(crate) type PeerManager = LdkPeerManager<
    SocketDescriptor,
    Arc<ChannelManager>,
    Arc<P2PGossipSync<Arc<NetworkGraph>, Arc<GossipVerifier>, Arc<FilesystemLogger>>>,
    Arc<OnionMessenger>,
    Arc<FilesystemLogger>,
    Arc<AsyncOrderMessageHandler>,
    Arc<KeysManager>,
    Arc<ChainMonitor>,
>;

pub(crate) type Scorer = ProbabilisticScorer<Arc<NetworkGraph>, Arc<FilesystemLogger>>;

pub(crate) type Router = DefaultRouter<
    Arc<NetworkGraph>,
    Arc<FilesystemLogger>,
    Arc<KeysManager>,
    Arc<RwLock<Scorer>>,
    ProbabilisticScoringFeeParameters,
    Scorer,
>;

pub(crate) type ChannelManager =
    SimpleArcChannelManager<ChainMonitor, BitcoindClient, BitcoindClient, FilesystemLogger>;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<FilesystemLogger>>;

pub(crate) type OnionMessenger = LdkOnionMessenger<
    Arc<KeysManager>,
    Arc<KeysManager>,
    Arc<FilesystemLogger>,
    Arc<ChannelManager>,
    Arc<DefaultMessageRouter<Arc<NetworkGraph>, Arc<FilesystemLogger>, Arc<KeysManager>>>,
    Arc<ChannelManager>,
    Arc<ChannelManager>,
    Arc<OMDomainResolver<Arc<ChannelManager>>>,
    IgnoringMessageHandler,
>;

pub(crate) type BumpTxEventHandler = BumpTransactionEventHandler<
    Arc<BitcoindClient>,
    Arc<Wallet<Arc<RgbLibWalletWrapper>, Arc<FilesystemLogger>>>,
    Arc<KeysManager>,
    Arc<FilesystemLogger>,
>;

pub(crate) type OutputSpenderTxes = LdkHashMap<u64, bitcoin::Transaction>;

pub(crate) struct RgbOutputSpender {
    static_state: Arc<StaticState>,
    rgb_wallet_wrapper: Arc<RgbLibWalletWrapper>,
    keys_manager: Arc<KeysManager>,
    kv_store: Arc<SeaOrmKvStore>,
    txes: Arc<Mutex<OutputSpenderTxes>>,
    proxy_endpoint: String,
}

pub(crate) type OutputSweeper = ldk_sweep::OutputSweeper<
    Arc<BitcoindClient>,
    Arc<RgbLibWalletWrapper>,
    Arc<BitcoindClient>,
    Arc<dyn Filter + Send + Sync>,
    KVStoreSyncWrapper<Arc<SeaOrmKvStore>>,
    Arc<FilesystemLogger>,
    Arc<RgbOutputSpender>,
>;

struct VirtualChannelAccess {
    trusted_no_broadcast: bool,
    virtual_peer_pubkeys: Vec<PublicKey>,
    channel_manager: Arc<ChannelManager>,
}

impl VirtualChannelAccess {
    fn new(static_state: &StaticState, channel_manager: Arc<ChannelManager>) -> Self {
        Self {
            trusted_no_broadcast: static_state.enable_virtual_channels_v0,
            virtual_peer_pubkeys: static_state.virtual_peer_pubkeys.clone(),
            channel_manager,
        }
    }

    fn is_virtual_peer(&self, peer: &PublicKey) -> bool {
        self.virtual_peer_pubkeys.is_empty()
            || self
                .virtual_peer_pubkeys
                .iter()
                .any(|virtual_peer| virtual_peer == peer)
    }
}

impl AsyncOrderAccessControl for VirtualChannelAccess {
    fn allows_peer(&self, peer: &PublicKey) -> bool {
        self.trusted_no_broadcast
            && self.is_virtual_peer(peer)
            && self.channel_manager.list_channels().iter().any(|channel| {
                channel.counterparty.node_id == *peer && channel.trusted_no_broadcast
            })
    }
}

fn _safe_update_rgb_channel_amount(
    channel_id: &str,
    rgb_offered_htlc: u64,
    rgb_received_htlc: u64,
    kv_store: &dyn KVStoreSync,
) -> io::Result<bool> {
    match kv_store.read_rgb_channel_info(channel_id, false) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::warn!(
                "Skipping RGB channel balance update for channel {} because channel RGB info is missing",
                channel_id
            );
            return Ok(false);
        }
        Err(e) => return Err(e),
    }
    update_rgb_channel_amount(
        channel_id,
        rgb_offered_htlc,
        rgb_received_htlc,
        false,
        kv_store,
    );
    Ok(true)
}

fn _finalize_rgb_channel_payment(
    payment_hash: &PaymentHash,
    receiver: bool,
    kv_store: &Arc<dyn KVStoreSync + Send + Sync>,
) -> io::Result<()> {
    let payment_hash_str = hex_str(&payment_hash.0);
    let pending_suffix = format!("{payment_hash_str}_pending");
    let mut applied_any = false;

    for inbound in [true, false] {
        let namespace = if inbound {
            RGB_PAYMENT_INFO_INBOUND_NS
        } else {
            RGB_PAYMENT_INFO_OUTBOUND_NS
        };

        let keys = kv_store.list(RGB_PRIMARY_NS, namespace)?;

        let mut applied_keys = Vec::new();

        for key in &keys {
            if !key.ends_with(&pending_suffix) || key.len() <= pending_suffix.len() {
                continue;
            }
            let channel_id_str = &key[..key.len() - pending_suffix.len()];
            if channel_id_str.len() != 64 {
                continue;
            }

            let data = match kv_store.read(RGB_PRIMARY_NS, namespace, key) {
                Ok(data) => data,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };

            let rgb_payment_info: RgbPaymentInfo = match bincode::deserialize(&data) {
                Ok(info) => info,
                Err(e) => {
                    tracing::warn!("failed to parse payment info for key {key}: {e}");
                    continue;
                }
            };

            if rgb_payment_info.swap_payment && receiver != rgb_payment_info.inbound {
                continue;
            }

            let (offered, received) = if receiver {
                (0, rgb_payment_info.amount)
            } else {
                (rgb_payment_info.amount, 0)
            };
            if _safe_update_rgb_channel_amount(
                channel_id_str,
                offered,
                received,
                kv_store.as_ref(),
            )? {
                applied_keys.push(key.clone());
                applied_any = true;
            }
        }

        for key in &applied_keys {
            let _ = kv_store.remove(RGB_PRIMARY_NS, namespace, key, false);
        }
    }

    if applied_any {
        let raw_pending_key = format!("{payment_hash_str}_pending");
        for namespace in [RGB_PAYMENT_INFO_INBOUND_NS, RGB_PAYMENT_INFO_OUTBOUND_NS] {
            let keys = kv_store.list(RGB_PRIMARY_NS, namespace)?;
            let remaining = keys
                .iter()
                .any(|k| k.ends_with(&pending_suffix) && k.len() > pending_suffix.len());
            if !remaining {
                let _ = kv_store.remove(RGB_PRIMARY_NS, namespace, &raw_pending_key, false);
            }
        }
    } else {
        tracing::warn!("no matching payment info found for payment_hash={payment_hash_str}");
    }

    Ok(())
}

fn _finalize_virtual_rgb_channel_info(
    temporary_channel_id: &ChannelId,
    channel_id: &ChannelId,
    kv_store: &dyn KVStoreSync,
) {
    let tmp_id = temporary_channel_id.to_string();
    let final_id = channel_id.to_string();
    for pending in [false, true] {
        match kv_store.read_rgb_channel_info(&tmp_id, pending) {
            Ok(rgb_info) => {
                if kv_store.read_rgb_channel_info(&final_id, pending).is_err() {
                    kv_store.write_rgb_channel_info(&final_id, &rgb_info, pending);
                }
                let _ = kv_store.remove_rgb_channel_info(&tmp_id, pending);
            }
            Err(_) => continue,
        }
    }
}

async fn handle_ldk_events(
    event: Event,
    unlocked_state: Arc<UnlockedAppState>,
    static_state: Arc<StaticState>,
) -> Result<(), ReplayEvent> {
    match event {
        Event::FundingGenerationReady {
            temporary_channel_id,
            counterparty_node_id,
            channel_value_satoshis,
            output_script,
            ..
        } => {
            let is_colored =
                is_channel_rgb(&temporary_channel_id, unlocked_state.kv_store.as_ref());

            let addr = WitnessProgram::from_scriptpubkey(
                output_script.as_bytes(),
                match static_state.network {
                    BitcoinNetwork::Mainnet => bitcoin_bech32::constants::Network::Bitcoin,
                    BitcoinNetwork::Testnet | BitcoinNetwork::Testnet4 => {
                        bitcoin_bech32::constants::Network::Testnet
                    }
                    BitcoinNetwork::Regtest => bitcoin_bech32::constants::Network::Regtest,
                    BitcoinNetwork::Signet | BitcoinNetwork::SignetCustom => {
                        bitcoin_bech32::constants::Network::Signet
                    }
                },
            )
            .expect("Lightning funding tx should always be to a SegWit output");
            let script_buf = ScriptBuf::from_bytes(addr.to_scriptpubkey());

            if let Some(virtual_draft) =
                unlocked_state.virtual_channel_draft_get(&temporary_channel_id)
            {
                let reject_virtual_open = |reason: String| {
                    tracing::error!(
                        "rejecting virtual channel {} with {}: {}",
                        temporary_channel_id,
                        hex_str(&counterparty_node_id.serialize()),
                        reason,
                    );
                    let _ = unlocked_state.kv_store.remove(
                        "",
                        "",
                        &format!("virtual_channel_{}", temporary_channel_id),
                        false,
                    );
                    unlocked_state.virtual_channel_draft_delete(&temporary_channel_id);
                    *unlocked_state.rgb_send_lock.lock().unwrap() = false;
                };

                let mut virtual_funding_txo = virtual_channel_synthetic_outpoint(
                    static_state.network,
                    &unlocked_state.channel_manager.get_our_node_id(),
                    &counterparty_node_id,
                );
                let duplicate_synthetic_funding_txo = {
                    let session_store = unlocked_state.get_virtual_channel_session_store();
                    session_store.contains_virtual_funding_txo(&virtual_funding_txo)
                };
                if duplicate_synthetic_funding_txo {
                    reject_virtual_open(format!(
                        "duplicate synthetic funding outpoint {} already exists in session store",
                        virtual_funding_txo,
                    ));
                    return Ok(());
                }
                let mut channel_id = ChannelId::v1_from_funding_outpoint(virtual_funding_txo);

                if is_colored {
                    let rgb_info = get_rgb_channel_info_pending(
                        &temporary_channel_id,
                        unlocked_state.kv_store.as_ref(),
                    );
                    let channel_rgb_amount = rgb_info.local_rgb_amount;
                    let asset_id = rgb_info.contract_id.to_string();
                    let assignment = match rgb_info.schema {
                        AssetSchema::Nia | AssetSchema::Cfa => {
                            Assignment::Fungible(channel_rgb_amount)
                        }
                        AssetSchema::Uda => Assignment::NonFungible,
                        AssetSchema::Ifa => todo!(),
                    };
                    let recipient_id =
                        recipient_id_from_script_buf(script_buf, static_state.network);
                    let recipient_map = map! {
                        asset_id.clone() => vec![Recipient {
                            recipient_id,
                            witness_data: Some(WitnessData {
                                amount_sat: channel_value_satoshis,
                                blinding: Some(STATIC_BLINDING),
                            }),
                            assignment,
                            transport_endpoints: vec![unlocked_state.proxy_endpoint.clone()]
                    }]};
                    let unlocked_state_copy = unlocked_state.clone();
                    let res = tokio::task::spawn_blocking(move || -> Result<String, String> {
                        let res = unlocked_state_copy
                            .rgb_send_begin(recipient_map, true, FEE_RATE, 0, None, false)
                            .map_err(|e| e.to_string())?;
                        let fascia_str = fs::read_to_string(&res.details.fascia_path)
                            .map_err(|e| e.to_string())?;
                        let fascia: Fascia =
                            serde_json::from_str(&fascia_str).map_err(|e| e.to_string())?;
                        unlocked_state_copy
                            .rgb_consume_fascia(fascia, None)
                            .map_err(|e| e.to_string())?;
                        unlocked_state_copy
                            .rgb_create_consignments(res.psbt.clone())
                            .map_err(|e| e.to_string())?;
                        Ok(res.psbt)
                    })
                    .await
                    .unwrap();

                    let unsigned_psbt = match res {
                        Ok(psbt) => psbt,
                        Err(e) => {
                            tracing::error!("cannot prepare virtual funding transfer: {e}");
                            return Err(ReplayEvent());
                        }
                    };

                    let signed_psbt = match unlocked_state.rgb_sign_psbt(unsigned_psbt) {
                        Ok(psbt) => psbt,
                        Err(e) => {
                            tracing::error!("cannot sign virtual funding transfer PSBT: {e}");
                            return Err(ReplayEvent());
                        }
                    };
                    let psbt = match Psbt::from_str(&signed_psbt) {
                        Ok(psbt) => psbt,
                        Err(e) => {
                            tracing::error!(
                                "cannot parse signed virtual funding transfer PSBT: {e}"
                            );
                            return Err(ReplayEvent());
                        }
                    };
                    let funding_psbt = match psbt.extract_tx() {
                        Ok(tx) => tx,
                        Err(e) => {
                            tracing::error!("cannot extract virtual funding transaction: {e}");
                            return Err(ReplayEvent());
                        }
                    };
                    let Some(virtual_funding_vout) = funding_psbt
                        .output
                        .iter()
                        .position(|txout| {
                            txout.script_pubkey.as_bytes() == output_script.as_bytes()
                        })
                        .map(|vout| vout as u16)
                    else {
                        tracing::error!(
                            "cannot find virtual funding output in extracted transaction"
                        );
                        return Err(ReplayEvent());
                    };
                    virtual_funding_txo = OutPoint {
                        txid: funding_psbt.compute_txid(),
                        index: virtual_funding_vout,
                    };
                    channel_id = ChannelId::v1_from_funding_outpoint(virtual_funding_txo);

                    let duplicate_virtual_funding_txo = {
                        let session_store = unlocked_state.get_virtual_channel_session_store();
                        session_store.contains_virtual_funding_txo(&virtual_funding_txo)
                    };
                    if duplicate_virtual_funding_txo {
                        reject_virtual_open(format!(
                            "duplicate virtual funding outpoint {} already exists in session store",
                            virtual_funding_txo,
                        ));
                        return Ok(());
                    }

                    let witness_id = virtual_funding_txo.txid.to_string();

                    let witness_id_clone = witness_id.clone();
                    let unlocked_state_copy = unlocked_state.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        unlocked_state_copy.rgb_upsert_witness(
                            RgbTxid::from_str(&witness_id_clone).unwrap(),
                            WitnessOrd::Tentative,
                        )
                    })
                    .await
                    .unwrap();

                    if let Err(e) = res {
                        tracing::error!("cannot register virtual funding witness: {e}");
                        return Err(ReplayEvent());
                    }

                    let consignment_path =
                        unlocked_state.rgb_get_send_consignment_path(&asset_id, &witness_id);
                    let proxy_url = TransportEndpoint::new(unlocked_state.proxy_endpoint.clone())
                        .unwrap()
                        .endpoint;
                    let consignment_path_copy = consignment_path.clone();
                    let unlocked_state_copy = unlocked_state.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        unlocked_state_copy.rgb_post_consignment(
                            &proxy_url,
                            witness_id.clone(),
                            &consignment_path_copy,
                            witness_id,
                            None,
                        )
                    })
                    .await
                    .unwrap();

                    if let Err(e) = res {
                        tracing::error!("cannot post virtual funding consignment: {e}");
                        return Err(ReplayEvent());
                    }
                    let _ = fs::remove_file(&consignment_path);
                }

                match unlocked_state
                    .channel_manager
                    .unsafe_manual_funding_transaction_generated(
                        temporary_channel_id,
                        counterparty_node_id,
                        virtual_funding_txo,
                        ChannelFundingType::Virtual,
                    ) {
                    Ok(()) => {
                        _finalize_virtual_rgb_channel_info(
                            &temporary_channel_id,
                            &channel_id,
                            unlocked_state.kv_store.as_ref(),
                        );
                        unlocked_state
                            .kv_store
                            .write("", "", &format!("virtual_channel_{}", channel_id), vec![])
                            .expect("able to persist virtual channel marker");
                        unlocked_state.virtual_channel_session_add(VirtualChannelSession {
                            channel_id,
                            created_at: virtual_draft.created_at,
                            former_temporary_channel_id: temporary_channel_id,
                            peer_id: virtual_draft.peer_id,
                            status: VirtualChannelSessionStatus::Active,
                            virtual_funding_txo,
                            updated_at: get_current_timestamp(),
                        });
                        unlocked_state.virtual_channel_draft_delete(&temporary_channel_id);
                        *unlocked_state.rgb_send_lock.lock().unwrap() = false;
                        tracing::info!(
                            "EVENT: registered trusted no-broadcast funding {} for virtual channel {}",
                            virtual_funding_txo,
                            channel_id,
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "ERROR: Failed trusted no-broadcast funding registration for {}: {:?}",
                            temporary_channel_id,
                            e,
                        );
                        let _ = unlocked_state.kv_store.remove(
                            "",
                            "",
                            &format!("virtual_channel_{}", temporary_channel_id),
                            false,
                        );
                        unlocked_state.virtual_channel_draft_delete(&temporary_channel_id);
                        *unlocked_state.rgb_send_lock.lock().unwrap() = false;
                    }
                }
                return Ok(());
            }

            let (unsigned_psbt, asset_id) = if is_colored {
                let rgb_info = get_rgb_channel_info_pending(
                    &temporary_channel_id,
                    unlocked_state.kv_store.as_ref(),
                );

                let channel_rgb_amount = rgb_info.local_rgb_amount + rgb_info.remote_rgb_amount;
                let asset_id = rgb_info.contract_id.to_string();
                let assignment = match rgb_info.schema {
                    AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => {
                        Assignment::Fungible(channel_rgb_amount)
                    }
                    AssetSchema::Uda => Assignment::NonFungible,
                };

                let recipient_id = recipient_id_from_script_buf(script_buf, static_state.network);

                let recipient_map = map! {
                    asset_id.clone() => vec![Recipient {
                        recipient_id: recipient_id.clone(),
                        witness_data: Some(WitnessData {
                            amount_sat: channel_value_satoshis,
                            blinding: Some(STATIC_BLINDING),
                        }),
                        assignment,
                        transport_endpoints: vec![unlocked_state.proxy_endpoint.clone()]
                }]};

                let unlocked_state_copy = unlocked_state.clone();
                let res = tokio::task::spawn_blocking(move || -> Result<String, String> {
                    let res = unlocked_state_copy
                        .rgb_send_begin(
                            recipient_map,
                            true,
                            FEE_RATE,
                            MIN_CHANNEL_CONFIRMATIONS,
                            None,
                            false,
                        )
                        .map_err(|e| e.to_string())?;
                    let fascia_str =
                        fs::read_to_string(&res.details.fascia_path).map_err(|e| e.to_string())?;
                    let fascia: Fascia =
                        serde_json::from_str(&fascia_str).map_err(|e| e.to_string())?;
                    unlocked_state_copy
                        .rgb_consume_fascia(fascia, None)
                        .map_err(|e| e.to_string())?;
                    unlocked_state_copy
                        .rgb_create_consignments(res.psbt.clone())
                        .map_err(|e| e.to_string())?;
                    Ok(res.psbt)
                })
                .await
                .unwrap();
                let unsigned_psbt = match res {
                    Ok(psbt) => psbt,
                    Err(e) => {
                        tracing::error!("cannot prepare channel funding transfer: {e}");
                        return Err(ReplayEvent());
                    }
                };
                (unsigned_psbt, Some(asset_id))
            } else {
                let unsigned_psbt = unlocked_state
                    .rgb_send_btc_begin(addr.to_address(), channel_value_satoshis, FEE_RATE)
                    .unwrap();
                (unsigned_psbt, None)
            };

            let signed_psbt = unlocked_state.rgb_sign_psbt(unsigned_psbt).unwrap();
            let psbt = Psbt::from_str(&signed_psbt).unwrap();

            let funding_tx = psbt.clone().extract_tx().unwrap();
            let funding_txid = funding_tx.compute_txid().to_string();
            tracing::info!("Funding TXID: {funding_txid}");

            // Store PSBT in database for later use when channel is funded
            unlocked_state
                .kv_store
                .write(
                    PSBT_NAMESPACE,
                    "",
                    &funding_txid,
                    psbt.to_string().into_bytes(),
                )
                .unwrap();

            if let Some(asset_id) = asset_id {
                let unlocked_state_copy = unlocked_state.clone();
                let witness_id = funding_txid.clone();
                tokio::task::spawn_blocking(move || {
                    unlocked_state_copy
                        .rgb_upsert_witness(
                            RgbTxid::from_str(&witness_id).unwrap(),
                            WitnessOrd::Tentative,
                        )
                        .unwrap()
                })
                .await
                .unwrap();

                let consignment_path =
                    unlocked_state.rgb_get_send_consignment_path(&asset_id, &funding_txid);
                let proxy_url = TransportEndpoint::new(unlocked_state.proxy_endpoint.clone())
                    .unwrap()
                    .endpoint;
                let consignment_path_copy = consignment_path.clone();
                let unlocked_state_copy = unlocked_state.clone();
                let res = tokio::task::spawn_blocking(move || {
                    unlocked_state_copy.rgb_post_consignment(
                        &proxy_url,
                        funding_txid.clone(),
                        &consignment_path_copy,
                        funding_txid,
                        None,
                    )
                })
                .await
                .unwrap();

                if let Err(e) = res {
                    tracing::error!("cannot post consignment: {e}");
                    return Err(ReplayEvent());
                }
                tracing::debug!(
                    asset_id,
                    consignment_path = %consignment_path.display(),
                    "Preserving consignment_out for rgb_send_end"
                );
            }

            let channel_manager_copy = unlocked_state.channel_manager.clone();

            // Give the funding transaction back to LDK for opening the channel.
            if channel_manager_copy
                .funding_transaction_generated(
                    temporary_channel_id,
                    counterparty_node_id,
                    funding_tx,
                )
                .is_err()
            {
                tracing::error!(
                        "ERROR: Channel went away before we could fund it. The peer disconnected or refused the channel.");
                *unlocked_state.rgb_send_lock.lock().unwrap() = false;
            }
        }
        Event::FundingTxBroadcastSafe { .. } => {
            // We don't use the manual broadcasting feature, so this event should never be seen.
        }
        Event::PaymentClaimable {
            payment_hash,
            purpose,
            amount_msat,
            receiver_node_id: _,
            claim_deadline,
            onion_fields: _,
            counterparty_skimmed_fee_msat: _,
            receiving_channel_ids,
            payment_id: _,
        } => {
            tracing::info!(
                "EVENT: received payment from payment hash {} of {} millisatoshis",
                payment_hash,
                amount_msat,
            );

            // `color_commitment` writes the authoritative per-HTLC record under
            // `chan_id || payment_hash` but never under the bare `<payment_hash>` key — that would
            // poison sibling channels in atomic RGB swaps. As the final hop we know exactly which
            // receiving channel delivered this HTLC, so project that scoped record to the bare
            // inbound key that `get_payment`/`list_payments` consume.
            let kv_store = &unlocked_state.kv_store;
            let htlc_payment_hash = hex_str(&payment_hash.0);
            for (chan_id, _) in &receiving_channel_ids {
                let chan_id_hex = hex_str(&chan_id.0);
                let htlc_proxy_id = format!("{chan_id_hex}{htlc_payment_hash}");
                if let Ok(data) =
                    kv_store.read(RGB_PRIMARY_NS, RGB_PAYMENT_INFO_INBOUND_NS, &htlc_proxy_id)
                {
                    if kv_store
                        .write(
                            RGB_PRIMARY_NS,
                            RGB_PAYMENT_INFO_INBOUND_NS,
                            &htlc_payment_hash,
                            data,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
            }

            let (payment_preimage, payment_secret, invoice) = match purpose {
                PaymentPurpose::SpontaneousPayment(preimage) => {
                    unlocked_state.channel_manager.claim_funds(preimage);
                    return Ok(());
                }
                PaymentPurpose::Bolt11InvoicePayment {
                    payment_preimage,
                    payment_secret,
                    ..
                }
                | PaymentPurpose::Bolt12OfferPayment {
                    payment_preimage,
                    payment_secret,
                    ..
                }
                | PaymentPurpose::Bolt12RefundPayment {
                    payment_preimage,
                    payment_secret,
                    ..
                } => {
                    let Some(invoice) = unlocked_state
                        .get_inbound_payments()
                        .payments
                        .get(&payment_hash)
                        .cloned()
                    else {
                        tracing::error!(
                            "Missing inbound payment state for claimable payment {:?}",
                            payment_hash
                        );
                        return Err(ReplayEvent());
                    };

                    (payment_preimage, Some(payment_secret), invoice)
                }
            };

            let now_ts = get_current_timestamp();
            if let Some(expiry) = invoice.expires_at {
                if now_ts >= expiry {
                    tracing::warn!(
                        "Received HTLC for expired invoice {payment_hash:?} (expiry {expiry})"
                    );
                    unlocked_state.fail_htlc_backwards_and_update_inbound_payment(
                        payment_hash,
                        HTLCStatus::Failed,
                    );
                    return Ok(());
                }
            }

            if let Some(expected) = invoice.amt_msat {
                if amount_msat < expected {
                    tracing::warn!(
                        "Received {} msat for invoice {} but expected at least {} msat",
                        amount_msat,
                        payment_hash,
                        expected
                    );
                    unlocked_state.fail_htlc_backwards_and_update_inbound_payment(
                        payment_hash,
                        HTLCStatus::Failed,
                    );
                    return Ok(());
                }
            }

            match invoice.invoice_type.unwrap_or(InvoiceType::AutoClaim) {
                InvoiceType::AutoClaim => {
                    unlocked_state
                        .channel_manager
                        .claim_funds(payment_preimage.unwrap());
                }
                InvoiceType::Hodl => {
                    unlocked_state.upsert_inbound_payment(
                        payment_hash,
                        HTLCStatus::Claimable,
                        payment_preimage,
                        payment_secret,
                        Some(amount_msat),
                        unlocked_state.channel_manager.get_our_node_id(),
                        claim_deadline,
                        None,
                    );
                }
            }
        }
        Event::PaymentClaimed {
            payment_hash,
            purpose,
            amount_msat,
            receiver_node_id,
            htlcs: _,
            sender_intended_total_msat: _,
            onion_fields: _,
            payment_id: _,
        } => {
            tracing::info!(
                "EVENT: claimed payment from payment hash {} of {} millisatoshis",
                payment_hash,
                amount_msat,
            );
            let (payment_preimage, payment_secret) = match purpose {
                PaymentPurpose::Bolt11InvoicePayment {
                    payment_preimage,
                    payment_secret,
                    ..
                } => (payment_preimage, Some(payment_secret)),
                PaymentPurpose::Bolt12OfferPayment {
                    payment_preimage,
                    payment_secret,
                    ..
                } => (payment_preimage, Some(payment_secret)),
                PaymentPurpose::Bolt12RefundPayment {
                    payment_preimage,
                    payment_secret,
                    ..
                } => (payment_preimage, Some(payment_secret)),
                PaymentPurpose::SpontaneousPayment(preimage) => (Some(preimage), None),
            };

            // check if already claimed
            let is_maker_swap = unlocked_state.is_maker_swap(&payment_hash);
            if is_maker_swap {
                if let Some(swap) = unlocked_state.maker_swaps().get(&payment_hash) {
                    if swap.status == SwapStatus::Succeeded {
                        tracing::info!("EVENT: payment already claimed, skipping");
                        return Ok(());
                    }
                }
            } else if let Some(payment) = unlocked_state
                .get_inbound_payments()
                .payments
                .get(&payment_hash)
            {
                if payment.status == HTLCStatus::Succeeded {
                    tracing::info!("EVENT: payment already claimed, skipping");
                    return Ok(());
                }
            }

            let kv_store_dyn: Arc<dyn KVStoreSync + Send + Sync> =
                Arc::clone(&unlocked_state.kv_store) as Arc<dyn KVStoreSync + Send + Sync>;
            if let Err(e) = _finalize_rgb_channel_payment(&payment_hash, true, &kv_store_dyn) {
                tracing::error!(
                    "RGB balance update failed for claimed payment {}: {e}",
                    hex_str(&payment_hash.0)
                );
                return Err(ReplayEvent());
            }
            if is_maker_swap {
                unlocked_state.update_maker_swap_status(&payment_hash, SwapStatus::Succeeded);
            } else {
                unlocked_state.upsert_inbound_payment(
                    payment_hash,
                    HTLCStatus::Succeeded,
                    payment_preimage,
                    payment_secret,
                    Some(amount_msat),
                    receiver_node_id.unwrap(),
                    None,
                    None,
                );
            }
        }
        Event::PaymentSent {
            payment_preimage,
            payment_hash,
            fee_paid_msat,
            payment_id,
            ..
        } => {
            let kv_store_dyn: Arc<dyn KVStoreSync + Send + Sync> =
                Arc::clone(&unlocked_state.kv_store) as Arc<dyn KVStoreSync + Send + Sync>;
            if let Err(e) = _finalize_rgb_channel_payment(&payment_hash, false, &kv_store_dyn) {
                tracing::error!(
                    "RGB balance update failed for sent payment {}: {e}",
                    hex_str(&payment_hash.0)
                );
                return Err(ReplayEvent());
            }

            if unlocked_state.is_maker_swap(&payment_hash) {
                tracing::info!(
                    "EVENT: successfully swapped payment with hash {} and preimage {}",
                    payment_hash,
                    payment_preimage
                );
                unlocked_state.update_maker_swap_status(&payment_hash, SwapStatus::Succeeded);
            } else {
                let payment = unlocked_state.update_outbound_payment(
                    payment_id.unwrap(),
                    HTLCStatus::Succeeded,
                    Some(payment_preimage),
                );
                tracing::info!(
                    "EVENT: successfully sent payment of {:?} millisatoshis{} from \
                            payment hash {} with preimage {}",
                    payment.amt_msat,
                    if let Some(fee) = fee_paid_msat {
                        format!(" (fee {fee} msat)")
                    } else {
                        "".to_string()
                    },
                    payment_hash,
                    payment_preimage
                );
            }
        }
        Event::OpenChannelRequest {
            ref temporary_channel_id,
            ref counterparty_node_id,
            ref channel_type,
            ..
        } => {
            let mut random_bytes = [0u8; 16];
            random_bytes
                .copy_from_slice(&unlocked_state.keys_manager.get_secure_random_bytes()[..16]);
            let user_channel_id = u128::from_be_bytes(random_bytes);

            let (res, accepted) = if static_state.enable_virtual_channels_v0 {
                let trusted_virtual_peer = static_state.virtual_peer_pubkeys.is_empty()
                    || static_state
                        .virtual_peer_pubkeys
                        .iter()
                        .any(|trusted_peer| trusted_peer == counterparty_node_id);
                if !trusted_virtual_peer {
                    let err = "untrusted_virtual_peer".to_string();
                    tracing::error!(
                        "EVENT: Rejected inbound trusted virtual channel ({}) from {}: {}",
                        temporary_channel_id,
                        hex_str(&counterparty_node_id.serialize()),
                        err,
                    );
                    (
                        unlocked_state
                            .channel_manager
                            .force_close_broadcasting_latest_txn(
                                temporary_channel_id,
                                counterparty_node_id,
                                err,
                            ),
                        false,
                    )
                } else if !channel_type.supports_scid_privacy() {
                    let err = "unsupported_scid_alias".to_string();
                    tracing::error!(
                        "EVENT: Rejected inbound channel ({}) from {}: {}",
                        temporary_channel_id,
                        hex_str(&counterparty_node_id.serialize()),
                        err,
                    );
                    (
                        unlocked_state
                            .channel_manager
                            .force_close_broadcasting_latest_txn(
                                temporary_channel_id,
                                counterparty_node_id,
                                err,
                            ),
                        false,
                    )
                } else {
                    (
                        unlocked_state
                            .channel_manager
                            .accept_inbound_channel_from_trusted_peer_0conf(
                                temporary_channel_id,
                                counterparty_node_id,
                                user_channel_id,
                                None,
                                ChannelFundingType::Virtual,
                            ),
                        true,
                    )
                }
            } else {
                (
                    unlocked_state.channel_manager.accept_inbound_channel(
                        temporary_channel_id,
                        counterparty_node_id,
                        user_channel_id,
                        None,
                    ),
                    true,
                )
            };

            if let Err(e) = res {
                tracing::error!(
                    "EVENT: Failed to accept inbound channel ({}) from {}: {:?}",
                    temporary_channel_id,
                    hex_str(&counterparty_node_id.serialize()),
                    e,
                );
            } else if accepted {
                tracing::info!(
                    "EVENT: Accepted inbound channel ({}) from {}",
                    temporary_channel_id,
                    hex_str(&counterparty_node_id.serialize()),
                );
            } else {
                tracing::info!(
                    "EVENT: Rejected inbound channel ({}) from {}",
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
            if let Some(hash) = payment_hash {
                clear_rgb_payment_pending(&hash, unlocked_state.kv_store.as_ref());
                tracing::error!(
                    "EVENT: Failed to send payment to payment ID {}, payment hash {}: {:?}",
                    payment_id,
                    hash,
                    if let Some(r) = reason {
                        r
                    } else {
                        PaymentFailureReason::RetriesExhausted
                    }
                );
                if unlocked_state.is_maker_swap(&hash) {
                    unlocked_state.update_maker_swap_status(&hash, SwapStatus::Failed);
                } else {
                    unlocked_state.update_outbound_payment_status(payment_id, HTLCStatus::Failed);
                }
            } else {
                tracing::error!(
                    "EVENT: Failed fetch invoice for payment ID {}: {:?}",
                    payment_id,
                    if let Some(r) = reason {
                        r
                    } else {
                        PaymentFailureReason::RetriesExhausted
                    }
                );
                unlocked_state.update_outbound_payment_status(payment_id, HTLCStatus::Failed);
            }
        }
        Event::InvoiceReceived { .. } => {
            // We don't use the manual invoice payment logic, so this event should never be seen.
        }
        Event::PaymentForwarded {
            prev_channel_id,
            next_channel_id,
            total_fee_earned_msat,
            claim_from_onchain_tx,
            outbound_amount_forwarded_msat,
            skimmed_fee_msat: _,
            prev_user_channel_id: _,
            next_user_channel_id: _,
            prev_node_id: _,
            next_node_id: _,
            outbound_amount_forwarded_rgb,
            inbound_amount_forwarded_rgb,
            payment_hash,
        } => {
            clear_rgb_payment_pending(&payment_hash, unlocked_state.kv_store.as_ref());
            let prev_channel_id_str = prev_channel_id.expect("prev_channel_id").to_string();
            let next_channel_id_str = next_channel_id.expect("next_channel_id").to_string();

            if let Some(outbound_amount_forwarded_rgb) = outbound_amount_forwarded_rgb {
                if let Err(e) = _safe_update_rgb_channel_amount(
                    &next_channel_id_str,
                    outbound_amount_forwarded_rgb,
                    0,
                    unlocked_state.kv_store.as_ref(),
                ) {
                    tracing::error!(
                        "RGB outbound balance update failed for forwarded payment on channel {}: {e}",
                        next_channel_id_str
                    );
                    return Err(ReplayEvent());
                }
            }
            if let Some(inbound_amount_forwarded_rgb) = inbound_amount_forwarded_rgb {
                if let Err(e) = _safe_update_rgb_channel_amount(
                    &prev_channel_id_str,
                    0,
                    inbound_amount_forwarded_rgb,
                    unlocked_state.kv_store.as_ref(),
                ) {
                    tracing::error!(
                        "RGB inbound balance update failed for forwarded payment on channel {}: {e}",
                        prev_channel_id_str
                    );
                    return Err(ReplayEvent());
                }
            }

            if unlocked_state.is_taker_swap(&payment_hash) {
                unlocked_state.update_taker_swap_status(&payment_hash, SwapStatus::Succeeded);
            }

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
                                    format!("node {}", announcement.alias())
                                }
                            },
                        }
                    }
                },
            };
            let channel_str = |channel_id: &Option<ChannelId>| {
                channel_id
                    .map(|channel_id| format!(" with channel {channel_id}"))
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
                format!("{v}")
            } else {
                "?".to_string()
            };
            if let Some(fee_earned) = total_fee_earned_msat {
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
        Event::SpendableOutputs {
            outputs,
            channel_id,
        } => {
            tracing::info!("EVENT: tracking {} spendable outputs", outputs.len(),);

            unlocked_state
                .output_sweeper
                .track_spendable_outputs(outputs, channel_id, false, None)
                .await
                .unwrap();
        }
        Event::ChannelPending {
            channel_id,
            counterparty_node_id,
            funding_txo,
            former_temporary_channel_id,
            ..
        } => {
            tracing::info!(
                "EVENT: Channel {} with peer {} is pending awaiting funding lock-in!",
                channel_id,
                hex_str(&counterparty_node_id.serialize()),
            );

            unlocked_state.add_channel_id(former_temporary_channel_id.unwrap(), channel_id);

            if unlocked_state
                .virtual_channel_session_store()
                .contains_key(&channel_id)
            {
                *unlocked_state.rgb_send_lock.lock().unwrap() = false;
                tracing::info!(
                    "EVENT: virtual channel {} is pending in trusted no-broadcast mode",
                    channel_id,
                );
                return Ok(());
            }

            let funding_txid = funding_txo.txid.to_string();

            // Check if we have a stored PSBT (initiator case)
            match unlocked_state
                .kv_store
                .read(PSBT_NAMESPACE, "", &funding_txid)
            {
                Ok(psbt_bytes) => {
                    let psbt_str = String::from_utf8(psbt_bytes).unwrap();

                    let state_copy = unlocked_state.clone();
                    let psbt_str_copy = psbt_str.clone();

                    let is_chan_colored =
                        is_channel_rgb(&channel_id, unlocked_state.kv_store.as_ref());
                    tracing::info!("Initiator of the channel (colored: {})", is_chan_colored);

                    let join_result = tokio::task::spawn_blocking(move || {
                        if is_chan_colored {
                            state_copy.rgb_send_end(psbt_str_copy).map(|r| r.txid)
                        } else {
                            state_copy.rgb_send_btc_end(psbt_str_copy)
                        }
                    })
                    .await;

                    *unlocked_state.rgb_send_lock.lock().unwrap() = false;

                    let finalize_result = join_result.map_err(|join_err| {
                        tracing::error!("Channel opening finalization task failed: {join_err:?}");
                        ReplayEvent()
                    })?;

                    let _txid = finalize_result.map_err(|e| {
                        tracing::error!("Error completing channel opening: {e:?}");
                        ReplayEvent()
                    })?;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // acceptor — read consignment from KVStore
                    let consignment_data =
                        match unlocked_state.kv_store.read_rgb_consignment(&funding_txid) {
                            Ok(data) => data,
                            Err(_) => {
                                // vanilla channel — no consignment
                                return Ok(());
                            }
                        };
                    let consignment =
                        RgbTransfer::load(&mut std::io::Cursor::new(consignment_data))
                            .expect("successful consignment load");
                    unlocked_state
                        .kv_store
                        .remove_rgb_consignment(&funding_txid);

                    match unlocked_state.rgb_save_new_asset(consignment, funding_txid) {
                        Ok(_) => {}
                        Err(e) if e.to_string().contains("UNIQUE constraint failed") => {}
                        Err(e) => panic!("Failed saving asset: {e}"),
                    }
                }
                Err(e) => panic!("Failed to read PSBT from KVStore: {e}"),
            }
        }
        Event::ChannelReady {
            ref channel_id,
            user_channel_id: _,
            ref counterparty_node_id,
            funding_txo: _,
            channel_type: _,
        } => {
            tracing::info!(
                "EVENT: Channel {} with peer {} is ready to be used!",
                channel_id,
                hex_str(&counterparty_node_id.serialize()),
            );

            tokio::task::spawn_blocking(move || {
                unlocked_state.rgb_refresh(false).unwrap();
                unlocked_state.rgb_refresh(true).unwrap()
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
            channel_funding_txo: _,
            last_local_balance_msat: _,
        } => {
            tracing::info!(
                "EVENT: Channel {} with counterparty {} closed due to: {:?}",
                channel_id,
                counterparty_node_id
                    .map(|id| format!("{id}"))
                    .unwrap_or("".to_owned()),
                reason
            );

            *unlocked_state.rgb_send_lock.lock().unwrap() = false;

            let former_temporary_channel_id = unlocked_state.delete_channel_id(channel_id);
            let virtual_draft_temporary_channel_id = if unlocked_state
                .virtual_channel_draft_get(&channel_id)
                .is_some()
            {
                Some(channel_id)
            } else {
                former_temporary_channel_id.filter(|temporary_channel_id| {
                    unlocked_state
                        .virtual_channel_draft_get(temporary_channel_id)
                        .is_some()
                })
            };

            if let Some(temporary_channel_id) = virtual_draft_temporary_channel_id {
                unlocked_state.virtual_channel_draft_delete(&temporary_channel_id);
                let _ = unlocked_state.kv_store.remove(
                    "",
                    "",
                    &format!("virtual_channel_{}", temporary_channel_id),
                    false,
                );
                let _ = unlocked_state.kv_store.remove(
                    "",
                    "",
                    &format!("virtual_channel_{}", channel_id),
                    false,
                );
                *unlocked_state.rgb_send_lock.lock().unwrap() = false;

                tracing::warn!(
                    "EVENT: cleaned up failed virtual open draft {} after channel close {}",
                    temporary_channel_id,
                    channel_id,
                );
            }
        }
        Event::DiscardFunding { channel_id, .. } => {
            // A "real" node should probably "lock" the UTXOs spent in funding transactions until
            // the funding transaction either confirms, or this event is generated.
            tracing::info!(
                "EVENT: Discarded funding for channel with ID {}",
                channel_id
            );

            unlocked_state.delete_channel_id(channel_id);
            let _ = unlocked_state.kv_store.remove(
                "",
                "",
                &format!("virtual_channel_{}", channel_id),
                false,
            );
        }
        Event::HTLCIntercepted {
            is_swap,
            payment_hash,
            intercept_id,
            inbound_amount_msat,
            expected_outbound_amount_msat,
            inbound_rgb_amount,
            expected_outbound_rgb_payment,
            requested_next_hop_scid,
            prev_outbound_scid_alias,
        } => {
            if !is_swap {
                tracing::warn!("Intercepted an HTLC that's not related to a swap");
                unlocked_state
                    .channel_manager
                    .fail_intercepted_htlc(intercept_id)
                    .unwrap();
                return Ok(());
            }

            let get_rgb_info = |channel_id| {
                get_rgb_channel_info_optional(channel_id, true, unlocked_state.kv_store.as_ref())
                    .map(|rgb_info| {
                        (
                            rgb_info.contract_id,
                            rgb_info.local_rgb_amount,
                            rgb_info.remote_rgb_amount,
                        )
                    })
            };

            let inbound_channel = unlocked_state
                .channel_manager
                .list_channels()
                .into_iter()
                .find(|details| details.outbound_scid_alias == Some(prev_outbound_scid_alias))
                .expect("Should always be a valid channel");
            let outbound_channel = unlocked_state
                .channel_manager
                .list_channels()
                .into_iter()
                .find(|details| details.short_channel_id == Some(requested_next_hop_scid))
                .expect("Should always be a valid channel");

            let inbound_rgb_info = get_rgb_info(&inbound_channel.channel_id);
            let outbound_rgb_info = get_rgb_info(&outbound_channel.channel_id);

            tracing::debug!("EVENT: Requested swap with params inbound_msat={} outbound_msat={} inbound_rgb={:?} outbound_rgb={:?} inbound_contract_id={:?}, outbound_contract_id={:?}", inbound_amount_msat, expected_outbound_amount_msat, inbound_rgb_amount, expected_outbound_rgb_payment.map(|(_, a)| a), inbound_rgb_info.map(|i| i.0), expected_outbound_rgb_payment.map(|(c, _)| c));

            let swaps_lock = unlocked_state.taker_swaps.lock().unwrap();
            let whitelist_swap = match swaps_lock.swaps.get(&payment_hash) {
                None => {
                    tracing::error!("ERROR: rejecting non-whitelisted swap");
                    unlocked_state
                        .channel_manager
                        .fail_intercepted_htlc(intercept_id)
                        .unwrap();
                    return Ok(());
                }
                Some(x) => x,
            };

            let mut fail = false;
            if whitelist_swap.swap_info.is_from_btc() {
                let net_msat_diff = expected_outbound_amount_msat.checked_sub(inbound_amount_msat);

                if inbound_rgb_amount != Some(whitelist_swap.swap_info.qty_to)
                    || inbound_rgb_info.map(|x| x.0) != whitelist_swap.swap_info.to_asset
                    || net_msat_diff != Some(whitelist_swap.swap_info.qty_from)
                {
                    fail = true;
                }
            } else if whitelist_swap.swap_info.is_to_btc() {
                let net_msat_diff =
                    inbound_amount_msat.saturating_sub(expected_outbound_amount_msat);

                if expected_outbound_rgb_payment.map(|(_, a)| a)
                    != Some(whitelist_swap.swap_info.qty_from)
                    || outbound_rgb_info.map(|x| x.0) != whitelist_swap.swap_info.from_asset
                    || net_msat_diff != whitelist_swap.swap_info.qty_to
                {
                    fail = true;
                }
            } else {
                let net_msat_diff = inbound_amount_msat.checked_sub(expected_outbound_amount_msat);

                if net_msat_diff != Some(0)
                    || expected_outbound_rgb_payment.map(|(_, a)| a)
                        != Some(whitelist_swap.swap_info.qty_from)
                    || outbound_rgb_info.map(|x| x.0) != whitelist_swap.swap_info.from_asset
                    || inbound_rgb_amount != Some(whitelist_swap.swap_info.qty_to)
                    || inbound_rgb_info.map(|x| x.0) != whitelist_swap.swap_info.to_asset
                {
                    fail = true;
                }
            }

            drop(swaps_lock);

            if fail {
                tracing::error!("ERROR: swap doesn't match the whitelisted info, rejecting it");
                unlocked_state.update_taker_swap_status(&payment_hash, SwapStatus::Failed);
                unlocked_state
                    .channel_manager
                    .fail_intercepted_htlc(intercept_id)
                    .unwrap();
                return Ok(());
            }

            tracing::debug!("Swap is whitelisted, forwarding the htlc...");
            unlocked_state.update_taker_swap_status(&payment_hash, SwapStatus::Pending);

            unlocked_state
                .channel_manager
                .forward_intercepted_htlc(
                    intercept_id,
                    channelmanager::NextHopForward::ShortChannelId(requested_next_hop_scid),
                    outbound_channel.counterparty.node_id,
                    expected_outbound_amount_msat,
                    expected_outbound_rgb_payment,
                )
                .expect("Forward should be valid");
        }
        Event::OnionMessageIntercepted { .. } => {
            // We don't use the onion message interception feature, so this event should never be
            // seen.
        }
        Event::OnionMessagePeerConnected { .. } => {
            // We don't use the onion message interception feature, so we have no use for this
            // event.
        }
        Event::BumpTransaction(event) => {
            unlocked_state
                .bump_tx_event_handler
                .handle_event(&event)
                .await
        }
        Event::ConnectionNeeded { node_id, addresses } => {
            tokio::spawn(async move {
                for address in addresses {
                    if let Ok(sockaddrs) = address.to_socket_addrs() {
                        for addr in sockaddrs {
                            let pm = Arc::clone(&unlocked_state.peer_manager);
                            if connect_peer_if_necessary(node_id, addr, pm).await.is_ok() {
                                return;
                            }
                        }
                    }
                }
            });
        }
        Event::SplicePending { .. } => {
            // We don't use the splice feature, so this event should never be seen.
        }
        Event::SpliceFailed { .. } => {
            // We don't use the splice feature, so this event should never be seen.
        }
        Event::PersistStaticInvoice { .. } => {
            // We don't use the static invoice feature, so this event should never be seen.
        }
        Event::StaticInvoiceRequested { .. } => {
            // We don't use the static invoice feature, so this event should never be seen.
        }
        Event::FundingTransactionReadyForSigning { .. } => {
            // We don't use the interactive funding transaction construction feature, so this event should never be seen.
        }
    }
    Ok(())
}

impl OutputSpender for RgbOutputSpender {
    fn spend_spendable_outputs(
        &self,
        descriptors: &[&SpendableOutputDescriptor],
        outputs: Vec<TxOut>,
        change_destination_script: ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        locktime: Option<LockTime>,
        secp_ctx: &Secp256k1<All>,
    ) -> Result<bitcoin::Transaction, ()> {
        let mut hasher = DefaultHasher::new();
        descriptors.hash(&mut hasher);
        let descriptors_hash = hasher.finish();
        let mut txes = self.txes.lock().unwrap();
        if let Some(tx) = txes.get(&descriptors_hash) {
            return Ok(tx.clone());
        }

        let mut vout = 0;
        let mut vanilla_descriptor = true;

        let mut txouts = outputs.clone();
        let mut asset_info: HashMap<ContractId, (u32, u64, String)> = map![];

        for outp in descriptors {
            let outpoint = match outp {
                SpendableOutputDescriptor::StaticPaymentOutput(descriptor) => descriptor.outpoint,
                SpendableOutputDescriptor::DelayedPaymentOutput(descriptor) => descriptor.outpoint,
                SpendableOutputDescriptor::StaticOutput { ref outpoint, .. } => *outpoint,
            };

            let txid = outpoint.txid;
            let txid_str = txid.to_string();

            let transfer_info_exists = self
                .kv_store
                .read(
                    RGB_PRIMARY_NS,
                    lightning::rgb_utils::RGB_TRANSFER_INFO_NS,
                    &txid_str,
                )
                .is_ok();
            if !transfer_info_exists {
                continue;
            }
            let transfer_info = self.kv_store.read_rgb_transfer_info(&txid_str);
            if transfer_info.rgb_amount == 0 {
                continue;
            }

            vanilla_descriptor = false;

            let closing_height = self
                .rgb_wallet_wrapper
                .get_tx_height(txid_str.clone())
                .map_err(|_| ())?;
            let update_res = self
                .rgb_wallet_wrapper
                .update_witnesses(
                    closing_height.unwrap(),
                    vec![RgbTxid::from_str(&txid_str).unwrap()],
                )
                .unwrap();
            if !update_res.failed.is_empty() {
                return Err(());
            }

            let contract_id = transfer_info.contract_id;

            let mut new_asset = false;
            let recipient_id = if let Some((_, _, recipient_id)) = asset_info.get(&contract_id) {
                recipient_id.clone()
            } else {
                new_asset = true;
                let receive_data = self
                    .rgb_wallet_wrapper
                    .witness_receive(
                        None,
                        Assignment::Any,
                        None,
                        vec![self.proxy_endpoint.clone()],
                        0,
                    )
                    .unwrap();
                let script_pubkey = script_buf_from_recipient_id(receive_data.recipient_id.clone())
                    .unwrap()
                    .unwrap();
                txouts.push(TxOut {
                    value: Amount::from_sat(DUST_LIMIT_MSAT / 1000),
                    script_pubkey,
                });
                receive_data.recipient_id
            };

            let amt_rgb = transfer_info.rgb_amount;

            asset_info
                .entry(contract_id)
                .and_modify(|(_, a, _)| {
                    *a += amt_rgb;
                })
                .or_insert_with(|| (vout, amt_rgb, recipient_id));

            if new_asset {
                vout += 1;
            }
        }

        if vanilla_descriptor {
            return self.keys_manager.spend_spendable_outputs(
                descriptors.as_ref(),
                txouts,
                change_destination_script,
                feerate_sat_per_1000_weight,
                locktime,
                secp_ctx,
            );
        }

        let feerate_sat_per_1000_weight = FEE_RATE as u32 * 250; // 1 sat/vB = 250 sat/kw
        let (psbt, _expected_max_weight) =
            SpendableOutputDescriptor::create_spendable_outputs_psbt(
                secp_ctx,
                descriptors,
                txouts,
                change_destination_script,
                feerate_sat_per_1000_weight,
                locktime,
            )
            .unwrap();

        let mut asset_info_map = map![];
        for (contract_id, (vout, amt_rgb, _)) in asset_info.clone() {
            asset_info_map.insert(
                contract_id,
                AssetColoringInfo {
                    output_map: HashMap::from_iter([(vout, amt_rgb)]),
                    static_blinding: None,
                },
            );
        }

        let coloring_info = ColoringInfo {
            asset_info_map,
            static_blinding: None,
            nonce: None,
        };

        let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
        let consignments = self
            .rgb_wallet_wrapper
            .color_psbt_and_consume(&mut psbt, coloring_info)
            .unwrap();

        let mut psbt = Psbt::from_str(&psbt.to_string()).expect("valid transaction");

        psbt = self
            .keys_manager
            .sign_spendable_outputs_psbt(descriptors, psbt, secp_ctx)
            .unwrap();

        let spending_tx = match psbt.extract_tx() {
            Ok(tx) => tx,
            Err(ExtractTxError::MissingInputValue { tx }) => tx,
            Err(e) => panic!("should never happen: {e}"),
        };

        let closing_txid = spending_tx.compute_txid().to_string();

        let handle = Handle::current();
        let _ = handle.enter();

        for consignment in consignments {
            let contract_id = consignment.contract_id();

            let (mut vout, _, recipient_id) = asset_info[&contract_id].clone();
            vout += 1;

            let consignment_path = self
                .static_state
                .ldk_data_dir
                .join(format!("consignment_{}", closing_txid.clone()));
            consignment
                .save_file(&consignment_path)
                .expect("successful save");
            let proxy_url = TransportEndpoint::new(self.proxy_endpoint.clone())
                .unwrap()
                .endpoint;
            let rgb_wallet_wrapper_copy = self.rgb_wallet_wrapper.clone();
            let closing_txid_copy = closing_txid.clone();
            let consignment_path_copy = consignment_path.clone();
            let res = crate::runtime::block_on(tokio::task::spawn_blocking(move || {
                rgb_wallet_wrapper_copy.post_consignment(
                    &proxy_url,
                    recipient_id,
                    &consignment_path_copy,
                    closing_txid_copy,
                    Some(vout),
                )
            }));
            if let Err(e) = res {
                tracing::error!("cannot post consignment: {e}");
                return Err(());
            }
            fs::remove_file(&consignment_path).unwrap();
        }

        txes.insert(descriptors_hash, spending_tx.clone());
        self.kv_store
            .write("", "", OUTPUT_SPENDER_TXES_KEY, txes.encode())
            .unwrap();

        Ok(spending_tx)
    }
}

pub(crate) async fn start_ldk(
    app_state: Arc<AppState>,
    mnemonic: Mnemonic,
    unlock_request: UnlockRequest,
) -> Result<(LdkBackgroundServices, Arc<UnlockedAppState>), APIError> {
    let static_state = &app_state.static_state;

    // Initialize Persistence using shared database connection
    let kv_store = Arc::new(SeaOrmKvStore::from_connection(Arc::clone(
        &static_state.database,
    )));
    let kv_store_dyn: Arc<dyn KVStoreSync + Send + Sync> =
        Arc::clone(&kv_store) as Arc<dyn KVStoreSync + Send + Sync>;

    // Sync config from database to KVStore
    sync_config_to_kvstore(&static_state.database, kv_store.as_ref())?;

    let ldk_data_dir = static_state.ldk_data_dir.clone();
    let ldk_data_dir_path = PathBuf::from(&ldk_data_dir);
    let logger = static_state.logger.clone();
    let bitcoin_network = static_state.network;
    let network: Network = bitcoin_network.into();
    let ldk_peer_listening_port = static_state.ldk_peer_listening_port;

    // Initialize our bitcoind client.
    let bitcoind_client = match BitcoindClient::new(
        unlock_request.bitcoind_rpc_host.clone(),
        unlock_request.bitcoind_rpc_port,
        unlock_request.bitcoind_rpc_username.clone(),
        unlock_request.bitcoind_rpc_password.clone(),
        tokio::runtime::Handle::current(),
        Arc::clone(&logger),
    )
    .await
    {
        Ok(client) => Arc::new(client),
        Err(e) => {
            return Err(APIError::FailedBitcoindConnection(e.to_string()));
        }
    };

    // Check that the bitcoind we've connected to is running the network we expect
    let bitcoind_chain = bitcoind_client.get_blockchain_info().await.chain;
    if bitcoind_chain
        != match bitcoin_network {
            BitcoinNetwork::Mainnet => "main",
            BitcoinNetwork::Testnet => "test",
            BitcoinNetwork::Testnet4 => "testnet4",
            BitcoinNetwork::Regtest => "regtest",
            BitcoinNetwork::Signet | BitcoinNetwork::SignetCustom => "signet",
        }
    {
        return Err(APIError::NetworkMismatch(bitcoind_chain, bitcoin_network));
    }

    // RGB setup
    let indexer_url = if let Some(indexer_url) = &unlock_request.indexer_url {
        let indexer_protocol = check_indexer_url(indexer_url, bitcoin_network)?;
        tracing::info!(
            "Connected to an indexer with the {} protocol",
            indexer_protocol
        );
        indexer_url
    } else {
        tracing::info!("Using the default indexer");
        match bitcoin_network {
            BitcoinNetwork::Regtest => ELECTRUM_URL_REGTEST,
            BitcoinNetwork::Signet => ELECTRUM_URL_SIGNET,
            BitcoinNetwork::Testnet => ELECTRUM_URL_TESTNET,
            BitcoinNetwork::Testnet4 => ELECTRUM_URL_TESTNET4,
            BitcoinNetwork::Mainnet => ELECTRUM_URL_MAINNET,
            BitcoinNetwork::SignetCustom => {
                return Err(APIError::InvalidIndexer(s!(
                    "with custom signet indexer must be provided"
                )))
            }
        }
    };
    let proxy_endpoint = if let Some(proxy_endpoint) = &unlock_request.proxy_endpoint {
        check_rgb_proxy_endpoint(proxy_endpoint).await?;
        tracing::info!("Using a custom proxy");
        proxy_endpoint
    } else {
        tracing::info!("Using the default proxy");
        match bitcoin_network {
            BitcoinNetwork::Signet
            | BitcoinNetwork::SignetCustom
            | BitcoinNetwork::Testnet
            | BitcoinNetwork::Testnet4
            | BitcoinNetwork::Mainnet => PROXY_ENDPOINT_PUBLIC,
            BitcoinNetwork::Regtest => PROXY_ENDPOINT_LOCAL,
        }
    };
    save_config(
        &app_state.static_state.database,
        kv_store.as_ref(),
        CONFIG_INDEXER_URL,
        indexer_url,
    )?;
    save_config(
        &app_state.static_state.database,
        kv_store.as_ref(),
        CONFIG_BITCOIN_NETWORK,
        &bitcoin_network.to_string(),
    )?;

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
    let xprv: Xpriv = master_xprv
        .derive_priv(&Secp256k1_30::new(), &ChildNumber::Hardened { index: 535 })
        .unwrap();
    let ldk_seed: [u8; 32] = xprv.private_key.secret_bytes();
    let cur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();

    let keys_manager = Arc::new(KeysManager::new(
        &ldk_seed,
        cur.as_secs(),
        cur.subsec_nanos(),
        true,
        ldk_data_dir_path.clone(),
        kv_store_dyn.clone(),
    ));

    let persister = Arc::new(MonitorUpdatingPersister::new(
        Arc::clone(&kv_store),
        Arc::clone(&logger),
        1000,
        Arc::clone(&keys_manager),
        Arc::clone(&keys_manager),
        Arc::clone(&bitcoind_client),
        Arc::clone(&bitcoind_client),
    ));

    // Initialize the ChainMonitor
    let chain_monitor: Arc<ChainMonitor> = Arc::new(chainmonitor::ChainMonitor::new(
        None,
        Arc::clone(&broadcaster),
        Arc::clone(&logger),
        Arc::clone(&fee_estimator),
        Arc::clone(&persister),
        Arc::clone(&keys_manager),
        keys_manager.get_peer_storage_key(),
    ));

    // Read ChannelMonitor state from disk
    let mut channelmonitors = persister.read_all_channel_monitors_with_updates().unwrap();

    // Poll for the best chain tip, which may be used by the channel manager & spv client
    let polled_chain_tip = init::validate_best_block_header(bitcoind_client.as_ref())
        .await
        .expect("Failed to fetch best block header and best block");

    // Initialize routing ProbabilisticScorer
    let network_graph_path = ldk_data_dir.join("network_graph");
    let network_graph = Arc::new(disk::read_network(
        &network_graph_path,
        network,
        logger.clone(),
    ));

    let scorer_path = ldk_data_dir.join("scorer");
    let scorer = Arc::new(RwLock::new(disk::read_scorer(
        &scorer_path,
        Arc::clone(&network_graph),
        Arc::clone(&logger),
    )));

    // Create Routers
    let scoring_fee_params = ProbabilisticScoringFeeParameters::default();
    let router = Arc::new(DefaultRouter::new(
        network_graph.clone(),
        logger.clone(),
        keys_manager.clone(),
        scorer.clone(),
        scoring_fee_params,
    ));
    let message_router = Arc::new(DefaultMessageRouter::new(
        Arc::clone(&network_graph),
        Arc::clone(&keys_manager),
    ));

    // Initialize the ChannelManager
    let mut user_config = UserConfig::default();
    user_config
        .channel_handshake_limits
        .force_announced_channel_preference = false;
    user_config
        .channel_handshake_config
        .negotiate_anchors_zero_fee_htlc_tx = true;
    user_config.accept_forwards_to_priv_channels = static_state.enable_virtual_channels_v0;
    user_config.manually_accept_inbound_channels = true;
    let mut restarting_node = true;
    let (channel_manager_blockhash, channel_manager) = {
        match kv_store.read(
            CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
            CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
            CHANNEL_MANAGER_PERSISTENCE_KEY,
        ) {
            Ok(bytes) => {
                let mut channel_monitor_references = Vec::new();
                for (_, channel_monitor) in channelmonitors.iter() {
                    channel_monitor_references.push(channel_monitor);
                }
                let read_args = ChannelManagerReadArgs::new(
                    keys_manager.clone(),
                    keys_manager.clone(),
                    keys_manager.clone(),
                    fee_estimator.clone(),
                    chain_monitor.clone(),
                    broadcaster.clone(),
                    router.clone(),
                    Arc::clone(&message_router),
                    logger.clone(),
                    user_config,
                    channel_monitor_references,
                    ldk_data_dir_path.clone(),
                    Arc::clone(&kv_store) as Arc<dyn KVStoreSync + Send + Sync>,
                );
                <(BlockHash, ChannelManager)>::read(&mut &bytes[..], read_args).unwrap()
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // We're starting a fresh node.
                restarting_node = false;

                let polled_best_block = polled_chain_tip.to_best_block();
                let polled_best_block_hash = polled_best_block.block_hash;
                let chain_params = ChainParameters {
                    network,
                    best_block: polled_best_block,
                };
                let fresh_channel_manager = channelmanager::ChannelManager::new(
                    fee_estimator.clone(),
                    chain_monitor.clone(),
                    broadcaster.clone(),
                    router.clone(),
                    Arc::clone(&message_router),
                    logger.clone(),
                    keys_manager.clone(),
                    keys_manager.clone(),
                    keys_manager.clone(),
                    user_config,
                    chain_params,
                    cur.as_secs() as u32,
                    ldk_data_dir_path.clone(),
                    Arc::clone(&kv_store) as Arc<dyn KVStoreSync + Send + Sync>,
                );
                (polled_best_block_hash, fresh_channel_manager)
            }
            Err(e) => {
                panic!("Failed to read channel manager from KVStore: {e}");
            }
        }
    };

    // Prepare the RGB wallet
    let mnemonic_str = mnemonic.to_string();
    let (_, account_xpub_vanilla, _) =
        get_account_data(&bitcoin_network, &mnemonic_str, false).unwrap();
    let (_, account_xpub_colored, master_fingerprint) =
        get_account_data(&bitcoin_network, &mnemonic_str, true).unwrap();
    let data_dir = static_state
        .storage_dir_path
        .clone()
        .to_string_lossy()
        .to_string();
    let keys = SinglesigKeys {
        account_xpub_vanilla: account_xpub_vanilla.to_string(),
        account_xpub_colored: account_xpub_colored.to_string(),
        vanilla_keychain: None,
        master_fingerprint: master_fingerprint.to_string(),
        mnemonic: Some(mnemonic.to_string()),
    };
    let mut rgb_wallet = tokio::task::spawn_blocking(move || {
        RgbLibWallet::new(
            WalletData {
                data_dir,
                bitcoin_network,
                database_type: DatabaseType::Sqlite,
                max_allocations_per_utxo: 1,
                supported_schemas: vec![
                    AssetSchema::Nia,
                    AssetSchema::Cfa,
                    AssetSchema::Uda,
                    AssetSchema::Ifa,
                ],
                reuse_addresses: false,
            },
            keys,
        )
        .expect("valid rgb-lib wallet")
    })
    .await
    .unwrap();
    let rgb_online = rgb_wallet.go_online(false, indexer_url.to_string())?;
    save_config(
        &static_state.database,
        kv_store.as_ref(),
        CONFIG_WALLET_FINGERPRINT,
        &account_xpub_colored.fingerprint().to_string(),
    )?;
    save_config(
        &static_state.database,
        kv_store.as_ref(),
        CONFIG_WALLET_ACCOUNT_XPUB_COLORED,
        &account_xpub_colored.to_string(),
    )?;
    save_config(
        &static_state.database,
        kv_store.as_ref(),
        CONFIG_WALLET_ACCOUNT_XPUB_VANILLA,
        &account_xpub_vanilla.to_string(),
    )?;
    save_config(
        &static_state.database,
        kv_store.as_ref(),
        CONFIG_WALLET_MASTER_FINGERPRINT,
        &master_fingerprint.to_string(),
    )?;

    let rgb_wallet_wrapper = Arc::new(RgbLibWalletWrapper::new(
        Arc::new(Mutex::new(rgb_wallet)),
        rgb_online,
    ));

    // Initialize the OutputSweeper.
    let txes: OutputSpenderTxes = match kv_store.read("", "", OUTPUT_SPENDER_TXES_KEY) {
        Ok(bytes) => OutputSpenderTxes::read(&mut &bytes[..]).unwrap_or_else(|_| new_hash_map()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => new_hash_map(),
        Err(e) => panic!("Failed to read output spender txes from KVStore: {e}"),
    };
    let txes = Arc::new(Mutex::new(txes));
    let rgb_output_spender = Arc::new(RgbOutputSpender {
        static_state: static_state.clone(),
        rgb_wallet_wrapper: rgb_wallet_wrapper.clone(),
        keys_manager: keys_manager.clone(),
        kv_store: kv_store.clone(),
        txes,
        proxy_endpoint: proxy_endpoint.to_string(),
    });
    let (sweeper_best_block, output_sweeper) = match kv_store.read(
        OUTPUT_SWEEPER_PERSISTENCE_PRIMARY_NAMESPACE,
        OUTPUT_SWEEPER_PERSISTENCE_SECONDARY_NAMESPACE,
        OUTPUT_SWEEPER_PERSISTENCE_KEY,
    ) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let sweeper = OutputSweeper::new(
                channel_manager.current_best_block(),
                broadcaster.clone(),
                fee_estimator.clone(),
                None,
                rgb_output_spender,
                rgb_wallet_wrapper.clone(),
                KVStoreSyncWrapper(kv_store.clone()),
                logger.clone(),
            );
            (channel_manager.current_best_block(), sweeper)
        }
        Ok(mut bytes) => {
            let read_args = (
                broadcaster.clone(),
                fee_estimator.clone(),
                None,
                rgb_output_spender.clone(),
                rgb_wallet_wrapper.clone(),
                KVStoreSyncWrapper(kv_store.clone()),
                logger.clone(),
            );
            let mut reader = io::Cursor::new(&mut bytes);
            <(BestBlock, OutputSweeper)>::read(&mut reader, read_args)
                .expect("Failed to deserialize OutputSweeper")
        }
        Err(e) => panic!("Failed to read OutputSweeper with {e}"),
    };

    // Sync ChannelMonitors, ChannelManager and OutputSweeper to chain tip
    let mut chain_listener_channel_monitors = Vec::new();
    let mut cache = UnboundedCache::new();
    let chain_tip = if restarting_node {
        let mut chain_listeners = vec![
            (
                channel_manager_blockhash,
                &channel_manager as &(dyn chain::Listen + Send + Sync),
            ),
            (
                sweeper_best_block.block_hash,
                &output_sweeper as &(dyn chain::Listen + Send + Sync),
            ),
        ];

        for (blockhash, channel_monitor) in channelmonitors.drain(..) {
            let outpoint = channel_monitor.get_funding_txo();
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

        let mut attempts = 3;
        loop {
            match init::synchronize_listeners(
                bitcoind_client.as_ref(),
                network,
                &mut cache,
                chain_listeners.clone(),
            )
            .await
            {
                Ok(res) => break res,
                Err(e) => {
                    tracing::error!("Error synchronizing chain: {:?}", e);
                    attempts -= 1;
                    if attempts == 0 {
                        return Err(APIError::FailedBitcoindConnection(
                            e.into_inner().to_string(),
                        ));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    } else {
        polled_chain_tip
    };

    // Give ChannelMonitors to ChainMonitor
    for (_, (channel_monitor, _, _, _), _) in chain_listener_channel_monitors {
        let channel_id = channel_monitor.channel_id();
        assert_eq!(
            chain_monitor.load_existing_monitor(channel_id, channel_monitor),
            Ok(ChannelMonitorUpdateStatus::Completed)
        );
    }

    // Optional: Initialize the P2PGossipSync
    let gossip_sync = Arc::new(P2PGossipSync::new(
        Arc::clone(&network_graph),
        None,
        Arc::clone(&logger),
    ));

    // Initialize an OMDomainResolver as a service to other nodes.
    // As a service to other LDK users, using an `OMDomainResolver` allows others to resolve BIP
    // 353 Human Readable Names for others, providing them DNSSEC proofs over lightning onion
    // messages. Doing this only makes sense for an always-online public routing node, and doesn't
    // provide you any direct value, but it's nice to offer the service for others.
    let channel_manager: Arc<ChannelManager> = Arc::new(channel_manager);
    let resolver = "8.8.8.8:53".to_socket_addrs().unwrap().next().unwrap();
    let domain_resolver = Arc::new(OMDomainResolver::new(
        resolver,
        Some(Arc::clone(&channel_manager)),
    ));

    // Initialize the PeerManager
    let onion_messenger: Arc<OnionMessenger> = Arc::new(LdkOnionMessenger::new(
        Arc::clone(&keys_manager),
        Arc::clone(&keys_manager),
        Arc::clone(&logger),
        Arc::clone(&channel_manager),
        Arc::clone(&message_router),
        Arc::clone(&channel_manager),
        Arc::clone(&channel_manager),
        domain_resolver,
        IgnoringMessageHandler {},
    ));
    let mut ephemeral_bytes = [0; 32];
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    rand::thread_rng().fill_bytes(&mut ephemeral_bytes);

    let virtual_channel_access = Arc::new(VirtualChannelAccess::new(
        static_state,
        channel_manager.clone(),
    ));
    let async_order_handler = match static_state.lsp_base_url.as_ref() {
        Some(lsp_base_url) => Arc::new(AsyncOrderMessageHandler::new_with_lsp_client(
            virtual_channel_access,
            lsp_base_url.clone(),
            static_state.lsp_bearer_token.clone(),
            Handle::current(),
        )),
        None => Arc::new(AsyncOrderMessageHandler::new(virtual_channel_access)),
    };
    let async_payments_preimage_root = Arc::new(
        AsyncPaymentsPreimageRoot::build_from_mnemonic(
            &mnemonic,
            network,
            &channel_manager.get_our_node_id(),
        )
        .map_err(|err| APIError::Unexpected(err.message))?,
    );

    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: gossip_sync.clone(),
        onion_message_handler: onion_messenger.clone(),
        custom_message_handler: Arc::clone(&async_order_handler),
        send_only_message_handler: Arc::clone(&chain_monitor),
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
        TokioSpawner,
        Arc::clone(&gossip_sync),
        Arc::clone(&peer_manager),
    );
    gossip_sync.add_utxo_lookup(Some(Arc::new(utxo_lookup)));

    // ## Running LDK
    // Initialize networking

    let peer_manager_connection_handler = peer_manager.clone();
    let listening_port = ldk_peer_listening_port;
    let stop_processing = Arc::new(AtomicBool::new(false));
    let stop_listen = Arc::clone(&stop_processing);
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("[::]:{listening_port}"))
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
    let output_sweeper: Arc<OutputSweeper> = Arc::new(output_sweeper);
    let channel_manager_listener = channel_manager.clone();
    let chain_monitor_listener = chain_monitor.clone();
    let output_sweeper_listener = output_sweeper.clone();
    let bitcoind_block_source = bitcoind_client.clone();
    let stop_listen = Arc::clone(&stop_processing);
    tokio::spawn(async move {
        let chain_poller = poll::ChainPoller::new(bitcoind_block_source.as_ref(), network);
        let chain_listener = (
            chain_monitor_listener,
            &(channel_manager_listener, output_sweeper_listener),
        );
        let mut spv_client = SpvClient::new(chain_tip, chain_poller, &mut cache, &chain_listener);
        loop {
            if stop_listen.load(Ordering::Acquire) {
                return;
            }
            if let Err(e) = spv_client.poll_best_tip().await {
                tracing::error!("Error while polling best tip: {:?}", e);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Read payment info from KVStore
    let inbound_payments = Arc::new(Mutex::new({
        match kv_store.read("", "", INBOUND_PAYMENTS_KEY) {
            Ok(bytes) => InboundPaymentInfoStorage::read(&mut &bytes[..]).unwrap_or_else(|_| {
                InboundPaymentInfoStorage {
                    payments: new_hash_map(),
                }
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => InboundPaymentInfoStorage {
                payments: new_hash_map(),
            },
            Err(e) => panic!("Failed to read inbound payments from KVStore: {e}"),
        }
    }));
    let outbound_payments = Arc::new(Mutex::new({
        match kv_store.read("", "", OUTBOUND_PAYMENTS_KEY) {
            Ok(bytes) => OutboundPaymentInfoStorage::read(&mut &bytes[..]).unwrap_or_else(|_| {
                OutboundPaymentInfoStorage {
                    payments: new_hash_map(),
                }
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => OutboundPaymentInfoStorage {
                payments: new_hash_map(),
            },
            Err(e) => panic!("Failed to read outbound payments from KVStore: {e}"),
        }
    }));

    let bump_tx_event_handler = Arc::new(BumpTransactionEventHandler::new(
        Arc::clone(&broadcaster),
        Arc::new(Wallet::new(rgb_wallet_wrapper.clone(), Arc::clone(&logger))),
        Arc::clone(&keys_manager),
        Arc::clone(&logger),
    ));

    // Persist ChannelManager and NetworkGraph
    let persister = KVStoreSyncWrapper(Arc::clone(&kv_store));

    // Read swaps info from KVStore
    let maker_swaps = Arc::new(Mutex::new({
        match kv_store.read("", "", MAKER_SWAPS_KEY) {
            Ok(bytes) => SwapMap::read(&mut &bytes[..]).unwrap_or_else(|_| SwapMap {
                swaps: new_hash_map(),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => SwapMap {
                swaps: new_hash_map(),
            },
            Err(e) => panic!("Failed to read maker swaps from KVStore: {e}"),
        }
    }));
    let taker_swaps = Arc::new(Mutex::new({
        match kv_store.read("", "", TAKER_SWAPS_KEY) {
            Ok(bytes) => SwapMap::read(&mut &bytes[..]).unwrap_or_else(|_| SwapMap {
                swaps: new_hash_map(),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => SwapMap {
                swaps: new_hash_map(),
            },
            Err(e) => panic!("Failed to read taker swaps from KVStore: {e}"),
        }
    }));

    // Read channel IDs info from KVStore
    let channel_ids_map = Arc::new(Mutex::new({
        match kv_store.read("", "", CHANNEL_IDS_KEY) {
            Ok(bytes) => ChannelIdsMap::read(&mut &bytes[..]).unwrap_or_else(|_| ChannelIdsMap {
                channel_ids: new_hash_map(),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => ChannelIdsMap {
                channel_ids: new_hash_map(),
            },
            Err(e) => panic!("Failed to read channel IDs from KVStore: {e}"),
        }
    }));

    let virtual_channel_draft_store = Arc::new(Mutex::new({
        match kv_store.read("", "", VIRTUAL_CHANNEL_DRAFTS_KEY) {
            Ok(bytes) => VirtualChannelDraftStore::read(&mut &bytes[..]).unwrap_or_else(|_| {
                VirtualChannelDraftStore {
                    entries: new_hash_map(),
                }
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => VirtualChannelDraftStore {
                entries: new_hash_map(),
            },
            Err(e) => panic!("Failed to read virtual channel drafts from KVStore: {e}"),
        }
    }));

    let virtual_channel_session_store = Arc::new(Mutex::new({
        match kv_store.read("", "", VIRTUAL_CHANNEL_SESSIONS_KEY) {
            Ok(bytes) => VirtualChannelSessionStore::read(&mut &bytes[..]).unwrap_or_else(|_| {
                VirtualChannelSessionStore {
                    entries: new_hash_map(),
                }
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => VirtualChannelSessionStore {
                entries: new_hash_map(),
            },
            Err(e) => panic!("Failed to read virtual channel sessions from KVStore: {e}"),
        }
    }));

    {
        let sessions = virtual_channel_session_store.lock().unwrap();
        for channel_id in sessions.entries.keys() {
            let marker_key = format!("virtual_channel_{}", channel_id);
            if kv_store.read("", "", &marker_key).is_err() {
                kv_store
                    .write("", "", &marker_key, vec![])
                    .expect("able to recover virtual channel marker");
            }
        }
    }

    let unlocked_state = Arc::new(UnlockedAppState {
        channel_manager: Arc::clone(&channel_manager),
        inbound_payments,
        keys_manager,
        network_graph,
        chain_monitor: chain_monitor.clone(),
        onion_messenger: onion_messenger.clone(),
        outbound_payments,
        peer_manager: Arc::clone(&peer_manager),
        async_order_handler,
        async_payments_preimage_root,
        kv_store: Arc::clone(&kv_store),
        bump_tx_event_handler,
        rgb_wallet_wrapper,
        maker_swaps,
        taker_swaps,
        router: Arc::clone(&router),
        output_sweeper: Arc::clone(&output_sweeper),
        rgb_send_lock: Arc::new(Mutex::new(false)),
        channel_ids_map,
        proxy_endpoint: proxy_endpoint.to_string(),
        virtual_channel_draft_store,
        virtual_channel_session_store,
    });

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
    unlocked_state.fail_outbound_pending_payments(recent_payments_payment_ids);

    // Handle LDK Events
    let unlocked_state_copy = Arc::clone(&unlocked_state);
    let static_state_copy = Arc::clone(static_state);
    let event_handler = move |event: Event| {
        let unlocked_state_copy = Arc::clone(&unlocked_state_copy);
        let static_state_copy = Arc::clone(&static_state_copy);
        async move { handle_ldk_events(event, unlocked_state_copy, static_state_copy).await }
    };

    // Background Processing
    let (bp_exit, bp_exit_check) = tokio::sync::watch::channel(());
    let background_processor = tokio::spawn(process_events_async(
        persister,
        event_handler,
        chain_monitor.clone(),
        channel_manager.clone(),
        Some(onion_messenger),
        GossipSync::p2p(gossip_sync),
        peer_manager.clone(),
        NO_LIQUIDITY_MANAGER,
        Some(Arc::clone(&output_sweeper)),
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
        || {
            Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap(),
            )
        },
    ));

    // Regularly reconnect to channel peers.
    let connect_cm = Arc::clone(&channel_manager);
    let connect_pm = Arc::clone(&peer_manager);
    let connect_db = Arc::clone(&static_state.database);
    let stop_connect = Arc::clone(&stop_processing);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let db = RlnDatabase::new((*connect_db).clone());
            match db.read_channel_peer_data() {
                Ok(info) => {
                    for node_id in connect_cm
                        .list_channels()
                        .iter()
                        .map(|chan| chan.counterparty.node_id)
                        .filter(|id| connect_pm.peer_by_node_id(id).is_none())
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
                    "ERROR: errored reading channel peer info from database: {:?}",
                    e
                ),
            }
        }
    });

    // Regularly broadcast our node_announcement. This is only required (or possible) if we have
    // some public channels.
    let mut ldk_announced_listen_addr = Vec::new();
    for addr in unlock_request.announce_addresses {
        match SocketAddress::from_str(&addr) {
            Ok(sa) => {
                ldk_announced_listen_addr.push(sa);
            }
            Err(_) => {
                return Err(APIError::InvalidAnnounceAddresses(format!(
                    "failed to parse address '{addr}'"
                )))
            }
        }
    }
    let ldk_announced_node_name = match unlock_request.announce_alias {
        Some(s) => {
            if s.len() > 32 {
                return Err(APIError::InvalidAnnounceAlias(s!(
                    "cannot be longer than 32 bytes"
                )));
            }
            let mut bytes = [0; 32];
            bytes[..s.len()].copy_from_slice(s.as_bytes());
            bytes
        }
        None => [0; 32],
    };
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
            if chan_man
                .list_channels()
                .iter()
                .any(|chan| chan.is_announced)
            {
                peer_man.broadcast_node_announcement(
                    [0; 3],
                    ldk_announced_node_name,
                    ldk_announced_listen_addr.clone(),
                );
            }
        }
    });

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

impl AppState {
    fn stop_ldk(&self) -> Option<JoinHandle<Result<(), io::Error>>> {
        let mut ldk_background_services = self.get_ldk_background_services();

        if ldk_background_services.is_none() {
            // node is locked
            tracing::info!("LDK is not running");
            return None;
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
    }
}

pub(crate) async fn stop_ldk(app_state: Arc<AppState>) {
    tracing::info!("Stopping LDK");

    if let Some(join_handle) = app_state.stop_ldk() {
        join_handle.await.unwrap().unwrap();
    }

    // connect to the peer port so it can be released
    let peer_port = app_state.static_state.ldk_peer_listening_port;
    let sock_addr = SocketAddr::from(([127, 0, 0, 1], peer_port));
    let _ = check_port_is_available(peer_port);
    // check the peer port has been released
    let t_0 = OffsetDateTime::now_utc();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if TcpListener::bind(sock_addr).is_ok() {
            break;
        }
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 10.0 {
            panic!("LDK peer port not being released")
        }
    }

    tracing::info!("Stopped LDK");
}

pub(crate) fn clear_rgb_payment_pending(payment_hash: &PaymentHash, kv_store: &dyn KVStoreSync) {
    let payment_hash_str = hex_str(&payment_hash.0);
    let raw_pending_key = format!("{payment_hash_str}_pending");
    let pending_suffix = format!("{payment_hash_str}_pending");
    for namespace in [RGB_PAYMENT_INFO_INBOUND_NS, RGB_PAYMENT_INFO_OUTBOUND_NS] {
        let _ = kv_store.remove(RGB_PRIMARY_NS, namespace, &raw_pending_key, false);
        if let Ok(keys) = kv_store.list(RGB_PRIMARY_NS, namespace) {
            for key in keys {
                if key.ends_with(&pending_suffix) && key.len() > pending_suffix.len() {
                    let _ = kv_store.remove(RGB_PRIMARY_NS, namespace, &key, false);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv_store::SeaOrmKvStore;
    use lightning::rgb_utils::{RgbInfo, RGB_CHANNEL_INFO_NS};
    use rgb_lib::AssetSchema;
    use rln_migration::{Migrator, MigratorTrait};
    use sea_orm::{ConnectOptions, Database};
    use std::str::FromStr;

    fn test_contract_id() -> rgb_lib::ContractId {
        rgb_lib::ContractId::from_str("rgb:EIkAVQvq-WbAb5JG-CYxbUER-oqDNwne-ZNxBDID-p0cpf9U")
            .unwrap()
    }

    fn build_kv_store() -> Arc<dyn KVStoreSync + Send + Sync> {
        let db_path = std::env::temp_dir().join(format!("rln-ldk-unit-{}", uuid::Uuid::new_v4()));
        let connection_string = format!("sqlite:{}?mode=rwc", db_path.display());
        let db =
            crate::runtime::block_on(Database::connect(ConnectOptions::new(connection_string)))
                .expect("db connection");
        crate::runtime::block_on(Migrator::up(&db, None)).expect("run migrations");
        Arc::new(SeaOrmKvStore::from_connection(Arc::new(db)))
    }

    fn seed_channel_info(
        kv_store: &Arc<dyn KVStoreSync + Send + Sync>,
        channel_id: &str,
        local_rgb_amount: u64,
        remote_rgb_amount: u64,
    ) {
        let info = RgbInfo {
            contract_id: test_contract_id(),
            schema: AssetSchema::Nia,
            local_rgb_amount,
            remote_rgb_amount,
        };
        let data = bincode::serialize(&info).expect("serialize rgb info");
        kv_store
            .write(RGB_PRIMARY_NS, RGB_CHANNEL_INFO_NS, channel_id, data)
            .expect("write rgb channel info");
    }

    fn seed_pending_payment_key(
        kv_store: &Arc<dyn KVStoreSync + Send + Sync>,
        namespace: &str,
        channel_id: &str,
        payment_hash: &PaymentHash,
        swap_payment: bool,
        inbound: bool,
    ) -> String {
        let info = RgbPaymentInfo {
            contract_id: test_contract_id(),
            amount: 25,
            local_rgb_amount: 100,
            remote_rgb_amount: 0,
            swap_payment,
            inbound,
        };
        let key = format!("{}{}_pending", channel_id, hex_str(&payment_hash.0));
        let data = bincode::serialize(&info).expect("serialize rgb payment info");
        kv_store
            .write(RGB_PRIMARY_NS, namespace, &key, data)
            .expect("write rgb payment info");
        key
    }

    fn read_local_amount(kv_store: &Arc<dyn KVStoreSync + Send + Sync>, channel_id: &str) -> u64 {
        let data = kv_store
            .read(RGB_PRIMARY_NS, RGB_CHANNEL_INFO_NS, channel_id)
            .expect("read rgb channel info");
        let info: RgbInfo = bincode::deserialize(&data).expect("deserialize rgb info");
        info.local_rgb_amount
    }

    #[test]
    fn finalize_rgb_channel_payment_clears_pending_markers_after_apply() {
        let kv_store = build_kv_store();
        let channel_id = "a".repeat(64);
        let payment_hash = PaymentHash([0xAB; 32]);
        seed_channel_info(&kv_store, &channel_id, 0, 100);
        let key = seed_pending_payment_key(
            &kv_store,
            RGB_PAYMENT_INFO_INBOUND_NS,
            &channel_id,
            &payment_hash,
            false,
            true,
        );

        _finalize_rgb_channel_payment(&payment_hash, true, &kv_store).expect("scanner succeeds");

        assert!(matches!(
            kv_store.read(RGB_PRIMARY_NS, RGB_PAYMENT_INFO_INBOUND_NS, &key),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
        assert_eq!(read_local_amount(&kv_store, &channel_id), 25);
    }

    #[test]
    fn finalize_rgb_channel_payment_leaves_pending_markers_when_nothing_applies() {
        let kv_store = build_kv_store();
        let channel_id = "b".repeat(64);
        let payment_hash = PaymentHash([0xCD; 32]);
        seed_channel_info(&kv_store, &channel_id, 100, 0);
        let key = seed_pending_payment_key(
            &kv_store,
            RGB_PAYMENT_INFO_INBOUND_NS,
            &channel_id,
            &payment_hash,
            true,
            true,
        );

        _finalize_rgb_channel_payment(&payment_hash, false, &kv_store)
            .expect("scanner succeeds without applying");

        assert!(kv_store
            .read(RGB_PRIMARY_NS, RGB_PAYMENT_INFO_INBOUND_NS, &key)
            .is_ok());
        assert_eq!(read_local_amount(&kv_store, &channel_id), 100);
    }

    #[test]
    fn finalize_rgb_channel_payment_ignores_non_pending_keys() {
        let kv_store = build_kv_store();
        let channel_id = "c".repeat(64);
        let payment_hash = PaymentHash([0xEF; 32]);
        seed_channel_info(&kv_store, &channel_id, 100, 0);
        let final_key = format!("{}{}", channel_id, hex_str(&payment_hash.0));
        let info = RgbPaymentInfo {
            contract_id: test_contract_id(),
            amount: 25,
            local_rgb_amount: 100,
            remote_rgb_amount: 0,
            swap_payment: false,
            inbound: true,
        };
        kv_store
            .write(
                RGB_PRIMARY_NS,
                RGB_PAYMENT_INFO_INBOUND_NS,
                &final_key,
                bincode::serialize(&info).unwrap(),
            )
            .unwrap();

        _finalize_rgb_channel_payment(&payment_hash, true, &kv_store).expect("scanner succeeds");

        assert!(kv_store
            .read(RGB_PRIMARY_NS, RGB_PAYMENT_INFO_INBOUND_NS, &final_key)
            .is_ok());
        assert_eq!(read_local_amount(&kv_store, &channel_id), 100);
    }

    #[test]
    fn finalize_rgb_channel_payment_only_touches_matching_payment_hash() {
        let kv_store = build_kv_store();
        let channel_id = "d".repeat(64);
        let target_hash = PaymentHash([0x11; 32]);
        let other_hash = PaymentHash([0x22; 32]);
        seed_channel_info(&kv_store, &channel_id, 0, 100);
        let target_key = seed_pending_payment_key(
            &kv_store,
            RGB_PAYMENT_INFO_INBOUND_NS,
            &channel_id,
            &target_hash,
            false,
            true,
        );
        let other_key = seed_pending_payment_key(
            &kv_store,
            RGB_PAYMENT_INFO_INBOUND_NS,
            &channel_id,
            &other_hash,
            false,
            true,
        );

        _finalize_rgb_channel_payment(&target_hash, true, &kv_store).expect("scanner succeeds");

        assert!(matches!(
            kv_store.read(RGB_PRIMARY_NS, RGB_PAYMENT_INFO_INBOUND_NS, &target_key),
            Err(e) if e.kind() == io::ErrorKind::NotFound
        ));
        assert!(kv_store
            .read(RGB_PRIMARY_NS, RGB_PAYMENT_INFO_INBOUND_NS, &other_key)
            .is_ok());
    }

    #[test]
    fn finalize_rgb_channel_payment_propagates_non_not_found_errors() {
        let db_path = std::env::temp_dir().join(format!("rln-ldk-unit-{}", uuid::Uuid::new_v4()));
        let connection_string = format!("sqlite:{}?mode=rwc", db_path.display());
        let db =
            crate::runtime::block_on(Database::connect(ConnectOptions::new(connection_string)))
                .expect("db connection");
        let kv_store: Arc<dyn KVStoreSync + Send + Sync> =
            Arc::new(SeaOrmKvStore::from_connection(Arc::new(db)));

        let result = _finalize_rgb_channel_payment(&PaymentHash([0; 32]), true, &kv_store);
        match result {
            Err(e) => assert_ne!(
                e.kind(),
                io::ErrorKind::NotFound,
                "real DB errors must not be classified as NotFound"
            ),
            Ok(()) => panic!("expected error when kv_store table is missing"),
        }
    }
}

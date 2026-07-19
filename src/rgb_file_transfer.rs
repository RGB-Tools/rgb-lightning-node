//! Peer-to-peer transport of the RGB files exchanged during channel opening.
//!
//! Instead of uploading the channel-funding consignment (and the asset's media files) to an HTTP
//! proxy, the initiator sends them directly to the channel counterparty over the encrypted (BOLT 8)
//! Lightning p2p connection as custom messages. Two kinds of file travel over this transport:
//!
//! * the funding **consignment**, written to `consignment_{funding_txid}`;
//! * zero or more **media** files (content-addressed by their SHA-256 digest), written to the RGB
//!   wallet media directory so the acceptor can serve `/getassetmedia` for the newly learned asset.
//!
//! The acceptor learns which media files to expect from the validated contract itself (rgb-lib
//! returns their digests when accepting the consignment), so nothing the sender claims about the
//! media set is trusted.
//!
//! Because Lightning wire messages are capped at `LN_MAX_MSG_LEN` (65535 bytes), every file is split
//! into chunks and reassembled on the receiving side. Only channel counterparties may send us files
//! (see [`PeerChannelGate`]); a peer's in-flight chunks are capped, dropped when it disconnects, and
//! swept once a transfer stops making progress (see [`REASSEMBLY_TTL`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{DecodeError, Init, LightningError};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::rgb_utils::get_media_staging_dir;
use lightning::types::features::{InitFeatures, NodeFeatures};
use lightning::util::ser::{LengthLimitedRead, Readable, Writeable, Writer};

// Custom Lightning message type id used for RGB file-transfer chunks.
//
// Must be odd (so peers that don't understand it ignore it instead of disconnecting) and live in
// the custom message range (>= 32768) defined by BOLT 1.
pub(crate) const RGB_FILE_TRANSFER_TYPE: u16 = 33333;

// Version of the on-wire framing. Bumped only on a breaking layout change; the receiver rejects
// messages carrying an unknown version.
const WIRE_VERSION: u8 = 1;

// File-kind discriminators carried in each chunk.
const FILE_KIND_CONSIGNMENT: u8 = 0;
const FILE_KIND_MEDIA: u8 = 1;

// Maximum number of file payload bytes carried in a single chunk.
//
// Kept well below `LN_MAX_MSG_LEN` (65535) to leave room for the 2-byte message type and the chunk
// framing (version, kind, funding txid, file id, indices and length prefixes).
const CHUNK_SIZE: usize = 60_000;

// How long a transfer may make no progress before its buffered chunks are dropped.
//
// The sender queues a funding's files in one go, so a transfer that stalls mid-file has either been
// abandoned by a peer that never disconnected or is a peer holding memory on purpose. Generous
// enough not to interrupt a large consignment crawling over a slow link.
pub(crate) const REASSEMBLY_TTL: Duration = Duration::from_secs(600);

// How often stale transfers are swept. Only bounds how long dead chunks outlive [`REASSEMBLY_TTL`],
// so it can be coarse.
pub(crate) const REASSEMBLY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

// How long a fully-written consignment file lingers before the sweep reclaims it as belonging to a
// funding that never arrived. The clock starts when the file lands on disk (`written_at`), not when
// its download began. The download is bounded separately by [`REASSEMBLY_TTL`]. `funding_created`
// follows the last chunk within seconds, so this is generous slack, not a tight deadline.
const CONSIGNMENT_TTL: Duration = Duration::from_secs(600);

// Node-wide cap on the number of consignments we hold at once: one per pending channel we're
// receiving funding files for.
//
// This is the node-wide bound that matters: peer identities are free (LDK's
// `MAX_UNFUNDED_CHANNEL_PEERS` limit is bypassed under manual accept, which this node uses), so a
// per-peer bound gives no guarantee.  Capping the total means an attacker sending invalid
// consignments can make us hold at most `MAX_PENDING_CONSIGNMENTS * MAX_CONSIGNMENT_SIZE` of trash
// before we discard the rest. Well above the handful of channels a node opens concurrently. The
// operator overrides this default at startup with `--max-pending-consignments`.
pub(crate) const MAX_PENDING_CONSIGNMENTS: usize = 10;

// Cap on the size of a single funding consignment.
pub(crate) const MAX_CONSIGNMENT_SIZE: usize = 16 * 1024 * 1024;

// Default cap on the total media bytes staged for one channel, across any number of files.
//
// The acceptor cannot know which media a contract expects until it accepts the consignment at
// funding time, so until then it takes what it is given; media is content-addressed, so a peer can
// mint unlimited distinct files by varying the bytes. This bounds the aggregate per funding. The
// operator overrides it at startup with `--max-aggregated-media-size-per-channel-mb`.
pub(crate) const MAX_MEDIA_MB_PER_CHANNEL: u16 = 24;

#[cfg(test)]
const MAX_MEDIA_BYTES_PER_CHANNEL: usize = MAX_MEDIA_MB_PER_CHANNEL as usize * 1024 * 1024;

// Default cap on the number of media files staged for one channel, in flight plus already written.
//
// The byte budget bounds only the summed size. Without a count cap a peer could mint a huge number
// of tiny (even 1-byte) media files, each cheap in bytes but each costing a reassembly map entry in
// memory and an inode on disk, so the object count, not the byte total, becomes the exhaustion
// vector. A real asset has a handful of media files, so this sits far above any honest use. The
// operator overrides it at startup with `--max-media-files-per-channel`.
pub(crate) const MAX_MEDIA_FILES_PER_CHANNEL: usize = 42;

// How many chunks `len` bytes is split into, or `None` if the framing cannot number them.
//
// The chunk count and index are `u16`, so a file over `CHUNK_SIZE * u16::MAX` (~3.9GB) cannot be
// described. That is beyond any real consignment or media file, but a cast would wrap in silence
// rather than fail, so the count is derived through a checked conversion instead.
fn chunk_count(len: usize) -> Option<u16> {
    // callers reject empty files, so `len` is at least 1
    u16::try_from(len.div_ceil(CHUNK_SIZE)).ok()
}

// Whether `s` is the canonical hex form of a 32-byte hash.
//
// Both reach us as claims from the sender and go on to name files and directories, so anything but
// the canonical form is refused rather than sanitised. It also bounds what a peer can make us hold
// per in-flight file, since these strings end up in the reassembly key.
fn is_hash_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// A single chunk of an RGB file being transferred over the p2p link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RgbFileMessage {
    // Which kind of file this chunk belongs to.
    pub(crate) file_kind: u8,
    // The funding transaction id (canonical hex string) this transfer belongs to.
    pub(crate) funding_txid: String,
    // Per-file identifier. For media it is the claimed SHA-256 digest; empty for the consignment
    // (there is only one per funding txid).
    pub(crate) file_id: String,
    // Index of this chunk (0-based).
    pub(crate) chunk_index: u16,
    // Total number of chunks composing the file.
    pub(crate) total_chunks: u16,
    // The raw file bytes carried by this chunk.
    pub(crate) data: Vec<u8>,
}

impl Type for RgbFileMessage {
    fn type_id(&self) -> u16 {
        RGB_FILE_TRANSFER_TYPE
    }
}

impl Writeable for RgbFileMessage {
    fn write<W: Writer>(&self, w: &mut W) -> Result<(), bitcoin::io::Error> {
        WIRE_VERSION.write(w)?;
        self.file_kind.write(w)?;
        let txid_bytes = self.funding_txid.as_bytes();
        (txid_bytes.len() as u16).write(w)?;
        w.write_all(txid_bytes)?;
        let file_id_bytes = self.file_id.as_bytes();
        (file_id_bytes.len() as u16).write(w)?;
        w.write_all(file_id_bytes)?;
        self.chunk_index.write(w)?;
        self.total_chunks.write(w)?;
        (self.data.len() as u32).write(w)?;
        w.write_all(&self.data)?;
        Ok(())
    }
}

impl RgbFileMessage {
    fn read_from<R: LengthLimitedRead>(buffer: &mut R) -> Result<Self, DecodeError> {
        let version: u8 = Readable::read(buffer)?;
        if version != WIRE_VERSION {
            return Err(DecodeError::InvalidValue);
        }
        let file_kind: u8 = Readable::read(buffer)?;
        if !matches!(file_kind, FILE_KIND_CONSIGNMENT | FILE_KIND_MEDIA) {
            return Err(DecodeError::InvalidValue);
        }
        let txid_len: u16 = Readable::read(buffer)?;
        let mut txid_bytes = vec![0u8; txid_len as usize];
        buffer.read_exact(&mut txid_bytes)?;
        let funding_txid = String::from_utf8(txid_bytes).map_err(|_| DecodeError::InvalidValue)?;
        if !is_hash_hex(&funding_txid) {
            return Err(DecodeError::InvalidValue);
        }
        let file_id_len: u16 = Readable::read(buffer)?;
        let mut file_id_bytes = vec![0u8; file_id_len as usize];
        buffer.read_exact(&mut file_id_bytes)?;
        let file_id = String::from_utf8(file_id_bytes).map_err(|_| DecodeError::InvalidValue)?;
        let file_id_ok = match file_kind {
            FILE_KIND_CONSIGNMENT => file_id.is_empty(),
            FILE_KIND_MEDIA => is_hash_hex(&file_id),
            _ => false,
        };
        if !file_id_ok {
            return Err(DecodeError::InvalidValue);
        }
        let chunk_index: u16 = Readable::read(buffer)?;
        let total_chunks: u16 = Readable::read(buffer)?;
        let data_len: u32 = Readable::read(buffer)?;
        // the whole message is bounded by the transport to LN_MAX_MSG_LEN, so a larger length is
        // bogus; reject it instead of attempting a huge allocation
        if data_len as usize > u16::MAX as usize {
            return Err(DecodeError::InvalidValue);
        }
        let mut data = vec![0u8; data_len as usize];
        buffer.read_exact(&mut data)?;
        Ok(RgbFileMessage {
            file_kind,
            funding_txid,
            file_id,
            chunk_index,
            total_chunks,
            data,
        })
    }
}

// Reassembly key for a single in-flight file: sender + kind + funding txid + per-file id.
//
// Keeping the kind and file id in the key lets the different files of the same funding reassemble
// concurrently without colliding. Keying by sender too keeps peers from interfering with each
// other's transfers (only the channel counterparty legitimately sends chunks for a given funding
// txid) and lets us drop a peer's state when it disconnects.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ReassemblyKey {
    peer: PublicKey,
    file_kind: u8,
    funding_txid: String,
    file_id: String,
}

// What the transport needs to know about our channels to tell legitimate senders from abuse.
//
// Files are only ever legitimately sent by a channel counterparty, while funding a colored channel.
// Any peer that completes the BOLT 8 handshake reaches
// [`CustomMessageHandler::handle_custom_message`], with no channel and no other relationship with
// us, so without these checks anyone could make us buffer chunks and write files to disk.
//
// Kept as a trait so the transport depends on these two questions rather than on the whole channel
// manager, and so it can be unit tested.
pub(crate) trait PeerChannelGate: Send + Sync {
    // How many channels, including ones still being funded, we have with `peer`.
    fn channel_count_with(&self, peer: &PublicKey) -> usize;

    // Whether any of our channels is funded by `funding_txid`.
    fn has_channel_funded_by(&self, funding_txid: &str) -> bool;
}

// Identifies one funding's staged state.
//
// The funding txid is the sender's claim, not something we can check on arrival: we only learn the
// real one from `funding_created`, which by design arrives *after* the consignment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FundingStagingKey {
    peer: PublicKey,
    funding_txid: String,
}

// Per-funding bookkeeping: when the consignment landed and the media staged with it.
struct FundingStagingRecord {
    written_at: Instant,
    // Media bytes staged against this funding, bounding one channel's media aggregate.
    staged_media_bytes: usize,
    // Number of media files staged against this funding, bounding one channel's media file count.
    staged_media_count: usize,
}

// Reassembly state for a single in-flight file.
struct ReassemblyState {
    // The sender's claimed total number of chunks, which the receiver verifies.
    total_chunks: u16,
    // Received chunks, keyed by index. A map rather than a pre-sized `Vec` so it holds only the
    // chunks actually received, never the sender's claimed `total_chunks`: a peer can't force a
    // large allocation with a single chunk. Out-of-order arrival is fine and re-sends are refused.
    chunks: BTreeMap<u16, Vec<u8>>,
    // Bytes currently held in `chunks`, kept alongside it to bound memory without re-summing.
    buffered: usize,
    // When this transfer last accepted a chunk, so a stalled one can be swept.
    last_progress: Instant,
}

impl ReassemblyState {
    fn new(now: Instant) -> Self {
        ReassemblyState {
            total_chunks: 0,
            chunks: BTreeMap::new(),
            buffered: 0,
            last_progress: now,
        }
    }
}

// Handles sending and receiving RGB files over the Lightning p2p connection.
pub(crate) struct RgbFileTransferHandler {
    ldk_data_dir: PathBuf,
    // Node-wide cap on the number of pending consignments; set from `--max-pending-consignments` at
    // startup, defaulting to [`MAX_PENDING_CONSIGNMENTS`].
    max_pending_fundings: usize,
    // Cap on one channel's aggregate staged media, in bytes; set from
    // `--max-aggregated-media-size-per-channel-mb` at startup.
    max_media_bytes_per_channel: usize,
    // Cap on one channel's media file count, in flight plus staged; set from
    // `--max-media-files-per-channel` at startup, defaulting to [`MAX_MEDIA_FILES_PER_CHANNEL`].
    max_media_files_per_channel: usize,
    channel_gate: Arc<dyn PeerChannelGate>,
    reassembly: Mutex<HashMap<ReassemblyKey, ReassemblyState>>,
    // Per-funding staged state we have written and not yet reclaimed: one entry per funding,
    // tracking when its consignment landed, gating the media staged against that funding, and
    // driving cleanup once the funding settles or ages out.
    staged_fundings: Mutex<HashMap<FundingStagingKey, FundingStagingRecord>>,
    outbound: Mutex<Vec<(PublicKey, RgbFileMessage)>>,
    // Test-only override for a single consignment's size cap; production always uses
    // [`MAX_CONSIGNMENT_SIZE`]. Read through [`Self::max_consignment_size`], never directly.
    #[cfg(test)]
    max_consignment_size: usize,
    // Test-only override for the size every chunk but the last must carry; production always uses
    // [`CHUNK_SIZE`]. Read through [`Self::chunk_size`], never directly.
    #[cfg(test)]
    chunk_size: usize,
}

impl RgbFileTransferHandler {
    pub(crate) fn new(
        ldk_data_dir: PathBuf,
        channel_gate: Arc<dyn PeerChannelGate>,
        max_pending_fundings: usize,
        max_media_bytes_per_channel: usize,
        max_media_files_per_channel: usize,
    ) -> Self {
        RgbFileTransferHandler {
            ldk_data_dir,
            max_pending_fundings,
            max_media_bytes_per_channel,
            max_media_files_per_channel,
            channel_gate,
            reassembly: Mutex::new(HashMap::new()),
            staged_fundings: Mutex::new(HashMap::new()),
            outbound: Mutex::new(Vec::new()),
            #[cfg(test)]
            max_consignment_size: MAX_CONSIGNMENT_SIZE,
            #[cfg(test)]
            chunk_size: CHUNK_SIZE,
        }
    }

    // The size every chunk but the last must carry. Fixed at [`CHUNK_SIZE`] in production.
    #[cfg(not(test))]
    fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    #[cfg(test)]
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    // Cap on a single consignment's size. Fixed at [`MAX_CONSIGNMENT_SIZE`] in production.
    #[cfg(not(test))]
    fn max_consignment_size(&self) -> usize {
        MAX_CONSIGNMENT_SIZE
    }

    #[cfg(test)]
    fn max_consignment_size(&self) -> usize {
        self.max_consignment_size
    }

    #[cfg(test)]
    fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    #[cfg(test)]
    fn with_media_limit(mut self, limit: usize) -> Self {
        self.max_media_bytes_per_channel = limit;
        self
    }

    #[cfg(test)]
    fn with_media_files_limit(mut self, limit: usize) -> Self {
        self.max_media_files_per_channel = limit;
        self
    }

    #[cfg(test)]
    fn with_consignment_size_limit(mut self, limit: usize) -> Self {
        self.max_consignment_size = limit;
        self
    }

    #[cfg(test)]
    fn with_pending_consignments_limit(mut self, limit: usize) -> Self {
        self.max_pending_fundings = limit;
        self
    }

    // Split `bytes` into chunks and queue them for delivery to `peer`.
    //
    // Fails only if the file is too large for the framing to describe.
    fn queue_file(
        &self,
        peer: PublicKey,
        file_kind: u8,
        funding_txid: String,
        file_id: String,
        bytes: Vec<u8>,
    ) -> Result<(), ()> {
        // no real file is empty, and the receiver rejects empty chunks, so an empty file has
        // nothing to send; refuse it here rather than emit an undeliverable chunk
        if bytes.is_empty() {
            tracing::error!("Refusing to send an empty RGB file for funding txid {funding_txid}");
            return Err(());
        }
        let Some(total_chunks) = chunk_count(bytes.len()) else {
            tracing::error!(
                "Refusing to send a {} byte RGB file for funding txid {funding_txid}: more than the {} chunks the framing can number",
                bytes.len(),
                u16::MAX,
            );
            return Err(());
        };
        let chunks: Vec<&[u8]> = bytes.chunks(CHUNK_SIZE).collect();
        debug_assert_eq!(chunks.len(), total_chunks as usize);
        let mut outbound = self.outbound.lock().unwrap();
        for (idx, chunk) in chunks.into_iter().enumerate() {
            outbound.push((
                peer,
                RgbFileMessage {
                    file_kind,
                    funding_txid: funding_txid.clone(),
                    file_id: file_id.clone(),
                    // bounded by `total_chunks`, which `chunk_count` proved fits
                    chunk_index: idx as u16,
                    total_chunks,
                    data: chunk.to_vec(),
                },
            ));
        }
        Ok(())
    }

    // Split the funding consignment into chunks and queue them for delivery to `peer`.
    //
    // After calling this the caller must trigger `PeerManager::process_events` to flush the queued
    // messages onto the wire.
    pub(crate) fn queue_consignment(
        &self,
        peer: PublicKey,
        funding_txid: String,
        bytes: Vec<u8>,
    ) -> Result<(), ()> {
        self.queue_file(
            peer,
            FILE_KIND_CONSIGNMENT,
            funding_txid,
            String::new(),
            bytes,
        )
    }

    // Queue a single media file (identified by its SHA-256 `digest`) for delivery to `peer`.
    //
    // After calling this the caller must trigger `PeerManager::process_events` to flush the queued
    // messages onto the wire.
    pub(crate) fn queue_media(
        &self,
        peer: PublicKey,
        funding_txid: String,
        digest: String,
        bytes: Vec<u8>,
    ) -> Result<(), ()> {
        self.queue_file(peer, FILE_KIND_MEDIA, funding_txid, digest, bytes)
    }

    // On startup, delete the consignment and staged-media files of channels that never funded.
    //
    // A file is an orphan when no funded channel claims its funding txid: LDK drops unfunded
    // channels across a restart, so a channel that still hasn't funded by the time this runs is
    // gone for good and its leftover files can be removed.
    //
    // This can't be left to the periodic sweep. The sweep only reclaims files tracked in the
    // in-memory map, and a restart wipes that map, so these files would otherwise sit on disk for
    // good (and, the node-wide cap being in-memory too, wouldn't even count against it). This pass
    // rediscovers them by scanning the data dir directly.
    //
    // Recent files are kept even without a funded channel yet: the age check guards the crash
    // window where a channel funded but the manager's state hadn't been persisted. On restart its
    // replayed `ChannelPending` still needs the file, and removing it would make the acceptor read
    // that colored channel as vanilla and drop the asset.
    pub(crate) fn cleanup_orphans_from_previous_run(&self) {
        self.cleanup_orphans_at(SystemTime::now())
    }

    fn cleanup_orphans_at(&self, at: SystemTime) {
        let entries = fs::read_dir(&self.ldk_data_dir).expect("ldk_data_dir exists at startup");
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // `consignment_<txid>_<contract_id>`, the transient closing consignment, is not a
            // canonical txid once the prefix is stripped, so it is left alone here.
            let funding_txid = name
                .strip_prefix("consignment_")
                .or_else(|| name.strip_prefix("media_staging_"))
                .filter(|txid| is_hash_hex(txid));
            let Some(funding_txid) = funding_txid else {
                continue;
            };
            let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
                continue;
            };
            // a clock that moved backwards reads as "not old enough", which errs towards keeping
            let Ok(age) = at.duration_since(modified) else {
                continue;
            };
            if age < CONSIGNMENT_TTL || self.channel_gate.has_channel_funded_by(funding_txid) {
                continue;
            }
            let path = entry.path();
            let res = if path.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            match res {
                Ok(()) => {
                    tracing::info!("Removed orphaned RGB file {name} from a previous run")
                }
                Err(e) => tracing::warn!("Failed to remove orphaned RGB file {name}: {e}"),
            }
        }
    }

    // Forget the staged funding record, freeing the node-wide cap slot it held.
    //
    // A staged funding record only needs to count against the node-wide cap while its channel is
    // still being funded; once the funding happens (or the channel goes away) the slot should be
    // freed.  The periodic sweep does this eventually: it drops a record as soon as the funding is
    // observed, but two handlers call this to do it immediately instead of waiting up to a sweep
    // interval: the acceptor's `ChannelPending` path once the funding locks in, and `ChannelClosed`
    // (which also removes the staged funding files). The latter is essential rather than just
    // prompt: a channel that funds and closes within a single sweep interval is never seen as
    // funded by the sweep, so without this its record would linger for the whole `CONSIGNMENT_TTL`
    // and refuse the peer's next channel.
    pub(crate) fn forget_staged_funding(&self, funding_txid: &str) {
        self.staged_fundings
            .lock()
            .unwrap()
            .retain(|key, _| key.funding_txid != funding_txid);
    }

    // Delete what abandoned transfers left behind, in memory and on disk.
    pub(crate) fn sweep_stale_state(&self) {
        let now = Instant::now();
        self.sweep_stale_transfers_at(now);
        self.sweep_unfunded_stagings_at(now);
    }

    // Drop the state staged for a funding that never happened.
    //
    // A peer can open a channel, send files naming any funding txid it likes, and simply never fund
    // it, costing it nothing. Those files are deleted here.
    //
    // The age check is what keeps this safe. A consignment file's *absence* is how the acceptor
    // decides a channel is vanilla, so removing one that a funding still needs would silently drop
    // the asset. Only a funding whose transaction never arrived, long after it would have, is
    // touched.
    fn sweep_unfunded_stagings_at(&self, now: Instant) {
        let mut persisted = self.staged_fundings.lock().unwrap();
        persisted.retain(|key, record| {
            // the funding happened, so this file belongs to a real channel: leave it alone and stop
            // holding it against the node-wide cap. It is removed when that channel closes, and its
            // staged media was promoted into the wallet by `handle_funding`
            if self.channel_gate.has_channel_funded_by(&key.funding_txid) {
                return false;
            }
            if now.duration_since(record.written_at) < CONSIGNMENT_TTL {
                return true;
            }
            // media staged against a funding that never happened is unvouched-for bytes
            let _ =
                fs::remove_dir_all(get_media_staging_dir(&self.ldk_data_dir, &key.funding_txid));
            match fs::remove_file(self.consignment_path(&key.funding_txid)) {
                Ok(()) => tracing::debug!(
                    "Removed unfunded RGB consignment from peer {} for funding txid {}",
                    key.peer,
                    key.funding_txid
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(
                    "Failed to remove unfunded RGB consignment for funding txid {}: {e}",
                    key.funding_txid
                ),
            }
            false
        });
    }

    // Drop transfers that haven't accepted a chunk within [`REASSEMBLY_TTL`].
    //
    // [`CustomMessageHandler::peer_disconnected`] already deletes a peer's buffers when it goes
    // away; this covers the peer that stays connected but never finishes what it started.
    fn sweep_stale_transfers_at(&self, now: Instant) {
        self.reassembly.lock().unwrap().retain(|key, state| {
            // returns zero, not a panic, if `now` precedes the last progress: a backwards clock
            // reads as not-yet-stale, so the transfer is kept rather than dropped
            let stale = now.duration_since(state.last_progress) >= REASSEMBLY_TTL;
            if stale {
                tracing::debug!(
                    "Dropping stalled RGB file transfer from peer {}: {} bytes buffered for funding txid {}",
                    key.peer,
                    state.buffered,
                    key.funding_txid
                );
            }
            !stale
        });
    }

    fn consignment_path(&self, funding_txid: &str) -> PathBuf {
        self.ldk_data_dir
            .join(format!("consignment_{funding_txid}"))
    }

    // Persist a fully reassembled file to disk according to its kind.
    fn persist_file(&self, key: &ReassemblyKey, bytes: Vec<u8>, now: Instant) {
        match key.file_kind {
            FILE_KIND_CONSIGNMENT => {
                // peer identities are free, so the count of held consignments is bounded node-wide
                // rather than per peer: the funding txid is a string the sender could invent, so
                // any peer could otherwise write unlimited files without ever funding anything, and
                // more peers cost nothing. Beyond the cap, further consignments are simply
                // discarded
                let mut persisted = self.staged_fundings.lock().unwrap();
                let staging_key = FundingStagingKey {
                    peer: key.peer,
                    funding_txid: key.funding_txid.clone(),
                };
                // a funding's consignment is written once. A second one for a funding we already
                // hold is a re-send: ignore it. Overwriting would reset the record's
                // `staged_media_bytes` to 0 while its media stays on disk, letting the peer stage
                // another full budget's worth of files and, by repeating, fill the disk unbounded
                if persisted.contains_key(&staging_key) {
                    tracing::debug!(
                        "Ignoring resent RGB consignment from peer {} for funding txid {}",
                        key.peer,
                        key.funding_txid,
                    );
                    return;
                }
                let count = persisted.len();
                if count >= self.max_pending_fundings {
                    tracing::debug!(
                        "Refusing RGB consignment from peer {}: {count} consignments already held",
                        key.peer
                    );
                    return;
                }
                let path = self.consignment_path(&key.funding_txid);
                if let Err(e) = fs::write(&path, &bytes) {
                    tracing::error!(
                        "Failed to persist RGB consignment for funding txid {}: {e}",
                        key.funding_txid
                    );
                } else {
                    persisted.insert(
                        staging_key,
                        FundingStagingRecord {
                            written_at: now,
                            staged_media_bytes: 0,
                            staged_media_count: 0,
                        },
                    );
                    tracing::info!(
                        "Received RGB consignment ({} bytes) over p2p for funding txid {}",
                        bytes.len(),
                        key.funding_txid
                    );
                }
            }
            FILE_KIND_MEDIA => {
                // media files are content-addressed, so the digest is recomputed from the received
                // bytes (identical hashing to `post_asset_media`) rather than taking the sender's
                // `file_id` on trust. The two disagreeing means these are not the bytes we were
                // promised: the transport is authenticated, so it is a sender that lied or a file
                // that changed under it, never corruption in flight. Drop them instead of spending
                // disk and this funding's staging budget on bytes already known to be wrong
                let digest = sha256::Hash::hash(&bytes).to_string();
                if digest != key.file_id {
                    tracing::warn!(
                        "Refusing RGB media from peer {} for funding txid {}: claimed digest {}, content hashes to {digest}",
                        key.peer,
                        key.funding_txid,
                        key.file_id,
                    );
                    return;
                }

                // media belongs to a funding, and the sender queues its consignment first, so on an
                // ordered connection one is always outstanding by now. Requiring it ties media to a
                // real channel, instead of letting a peer stage media against funding txids it
                // invents
                let mut persisted = self.staged_fundings.lock().unwrap();
                let staging_key = FundingStagingKey {
                    peer: key.peer,
                    funding_txid: key.funding_txid.clone(),
                };
                let Some(record) = persisted.get_mut(&staging_key) else {
                    tracing::debug!(
                        "Refusing RGB media from peer {}: no consignment outstanding for funding txid {}",
                        key.peer,
                        key.funding_txid
                    );
                    return;
                };

                let staging_dir = get_media_staging_dir(&self.ldk_data_dir, &key.funding_txid);
                let path = staging_dir.join(&digest);
                if path.exists() {
                    // identical bytes already staged, nothing to do
                    return;
                }
                if record.staged_media_bytes + bytes.len() > self.max_media_bytes_per_channel {
                    tracing::debug!(
                        "Refusing RGB media file {digest} from peer {}: funding txid {} has staged {} bytes, over the {} byte per-channel limit",
                        key.peer,
                        key.funding_txid,
                        record.staged_media_bytes,
                        self.max_media_bytes_per_channel,
                    );
                    return;
                }
                if record.staged_media_count >= self.max_media_files_per_channel {
                    tracing::debug!(
                        "Refusing RGB media file {digest} from peer {}: funding txid {} already has {} staged media files, the per-channel cap",
                        key.peer,
                        key.funding_txid,
                        record.staged_media_count,
                    );
                    return;
                }
                if let Err(e) = fs::create_dir_all(&staging_dir) {
                    tracing::error!(
                        "Failed to create RGB media staging dir for funding txid {}: {e}",
                        key.funding_txid
                    );
                    return;
                }
                if let Err(e) = fs::write(&path, &bytes) {
                    tracing::error!("Failed to stage RGB media file {digest}: {e}");
                } else {
                    record.staged_media_bytes += bytes.len();
                    record.staged_media_count += 1;
                    tracing::info!(
                        "Received RGB media file {digest} ({} bytes) over p2p for funding txid {}",
                        bytes.len(),
                        key.funding_txid
                    );
                }
            }
            _ => unreachable!("unknown file kind is rejected while decoding"),
        }
    }
}

impl CustomMessageReader for RgbFileTransferHandler {
    type CustomMessage = RgbFileMessage;

    fn read<R: LengthLimitedRead>(
        &self,
        message_type: u16,
        buffer: &mut R,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        if message_type != RGB_FILE_TRANSFER_TYPE {
            return Ok(None);
        }
        Ok(Some(RgbFileMessage::read_from(buffer)?))
    }
}

impl RgbFileTransferHandler {
    // Processes one received chunk. The [`CustomMessageHandler::handle_custom_message`] trait
    // method is a thin wrapper that just calls this with the current time; `now` is a parameter,
    // rather than read from the clock here, so tests can drive the reassembly TTL and sweep
    // deadlines with a synthetic clock instead of wall-clock time.
    fn handle_chunk(
        &self,
        msg: RgbFileMessage,
        sender_node_id: PublicKey,
        now: Instant,
    ) -> Result<(), LightningError> {
        // refuse anyone who isn't a channel counterparty before buffering or persisting anything.
        // Logged at debug level because any peer on the internet can trigger this at will, so it
        // must not be able to flood the logs
        if self.channel_gate.channel_count_with(&sender_node_id) == 0 {
            tracing::debug!(
                "Ignoring RGB file chunk from peer {sender_node_id}: no channel with this node"
            );
            return Ok(());
        }

        // files are only ever sent while a channel is being funded, before `funding_created`, so a
        // chunk naming a funding we already have open is never legitimate: that transfer completed
        // when the channel funded. Reject it, or a peer that knows the (public) funding txid of a
        // live channel could overwrite its consignment, re-stage media against it, or burn a
        // pending slot, none of which the staged-state guards catch once the sweep drops the funded
        // record
        if self.channel_gate.has_channel_funded_by(&msg.funding_txid) {
            tracing::debug!(
                "Ignoring RGB file chunk from peer {sender_node_id}: channel with funding txid {} is already open",
                msg.funding_txid
            );
            return Ok(());
        }

        let key = ReassemblyKey {
            peer: sender_node_id,
            file_kind: msg.file_kind,
            funding_txid: msg.funding_txid,
            file_id: msg.file_id,
        };
        let mut reassembly = self.reassembly.lock().unwrap();

        // malformed-stream checks. A correct sender on this reliable, ordered transport emits each
        // chunk once, in range, at the fixed size, under one consistent total; anything else is a bad
        // or malicious sender. Drop the whole transfer rather than tolerate it.
        // Only a transfer's own counterparty can send chunks for its key, so a peer can only ever
        // abort its own transfer this way

        // an in-range index (and non-zero total). Completing on `chunks.len() == total_chunks` alone
        // would accept e.g. indices {0, 1, 5} for total 3 and assemble garbage
        if msg.total_chunks == 0 || msg.chunk_index >= msg.total_chunks {
            tracing::warn!(
                "Dropping RGB file transfer from peer {}: invalid indices (index {}, total {}) for funding txid {}",
                key.peer,
                msg.chunk_index,
                msg.total_chunks,
                key.funding_txid
            );
            reassembly.remove(&key);
            return Ok(());
        }

        // the sender splits a file into fixed-size chunks, so every chunk but the last carries
        // exactly `chunk_size` bytes and the last carries 1..=chunk_size, which also rejects empty
        // and undersized chunks
        let is_last_chunk = msg.chunk_index == msg.total_chunks - 1;
        let chunk_size = self.chunk_size();
        let valid_len = if is_last_chunk {
            (1..=chunk_size).contains(&msg.data.len())
        } else {
            msg.data.len() == chunk_size
        };
        if !valid_len {
            tracing::warn!(
                "Dropping RGB file transfer from peer {}: chunk {} of {} carries {} bytes for funding txid {}",
                key.peer,
                msg.chunk_index,
                msg.total_chunks,
                msg.data.len(),
                key.funding_txid
            );
            reassembly.remove(&key);
            return Ok(());
        }

        // against an existing in-flight entry: a resent index, or a total_chunks that disagrees with
        // the one this transfer locked in on its first chunk, are both malformed
        let (resent, inconsistent_total) = {
            let existing = reassembly.get(&key);
            (
                existing.is_some_and(|s| s.chunks.contains_key(&msg.chunk_index)),
                existing.is_some_and(|s| s.total_chunks != msg.total_chunks),
            )
        };
        if resent {
            tracing::warn!(
                "Dropping RGB file transfer from peer {}: chunk {} resent for funding txid {}",
                key.peer,
                msg.chunk_index,
                key.funding_txid,
            );
            reassembly.remove(&key);
            return Ok(());
        }
        if inconsistent_total {
            tracing::warn!(
                "Dropping RGB file transfer from peer {}: total_chunks {} disagrees with the transfer's for funding txid {}",
                key.peer,
                msg.total_chunks,
                key.funding_txid,
            );
            reassembly.remove(&key);
            return Ok(());
        }

        // bytes already buffered for this file, or 0 when this is its first chunk (no state yet)
        let entry_buffered = reassembly.get(&key).map_or(0, |state| state.buffered);
        // what this file would occupy after accepting the chunk. Every index is new (re-sends aborted
        // above), so the chunk only ever adds
        let file_prospective = entry_buffered + msg.data.len();

        {
            let persisted = self.staged_fundings.lock().unwrap();

            // count a funding as pending from its first chunk, in flight or persisted, so the cap
            // bounds memory, not just completed files on disk: a peer can otherwise open endless
            // never-completing transfers under invented funding txids, none of which ever get counted
            // because none ever complete
            let funding_known = reassembly
                .keys()
                .any(|k| k.funding_txid == key.funding_txid)
                || persisted.keys().any(|k| k.funding_txid == key.funding_txid);
            if !funding_known {
                let mut fundings: HashSet<&str> =
                    reassembly.keys().map(|k| k.funding_txid.as_str()).collect();
                fundings.extend(persisted.keys().map(|k| k.funding_txid.as_str()));
                if fundings.len() >= self.max_pending_fundings {
                    tracing::debug!(
                        "Ignoring RGB file chunk from peer {}: {} fundings already pending, new funding txid {} refused",
                        key.peer,
                        fundings.len(),
                        key.funding_txid,
                    );
                    return Ok(());
                }
            }

            // a consignment is one file, capped at its max size; media is any number of files, but
            // their total for one channel, in flight plus already staged, is capped, so memory
            // can't grow with the file count
            if key.file_kind == FILE_KIND_MEDIA {
                let staging_key = FundingStagingKey {
                    peer: key.peer,
                    funding_txid: key.funding_txid.clone(),
                };
                let record = persisted.get(&staging_key);
                let other_media: usize = reassembly
                    .iter()
                    .filter(|(k, _)| {
                        **k != key
                            && k.file_kind == FILE_KIND_MEDIA
                            && k.funding_txid == key.funding_txid
                    })
                    .map(|(_, s)| s.buffered)
                    .sum();
                let staged = record.map_or(0, |r| r.staged_media_bytes);
                if other_media + file_prospective + staged > self.max_media_bytes_per_channel {
                    tracing::warn!(
                        "Ignoring RGB media chunk from peer {}: funding txid {} would exceed its {} byte media budget",
                        key.peer,
                        key.funding_txid,
                        self.max_media_bytes_per_channel,
                    );
                    return Ok(());
                }
                // bytes alone don't bound the object count: 1-byte files are cheap in bytes but each
                // costs a map entry and an inode. A chunk starting a new file (none in flight for it
                // yet) must not push the funding's media file count, in flight plus staged, over the
                // cap. A chunk continuing a file already in flight is already counted, so it is let by
                if !reassembly.contains_key(&key) {
                    let in_flight_files = reassembly
                        .keys()
                        .filter(|k| {
                            k.file_kind == FILE_KIND_MEDIA && k.funding_txid == key.funding_txid
                        })
                        .count();
                    let staged_files = record.map_or(0, |r| r.staged_media_count);
                    if in_flight_files + staged_files >= self.max_media_files_per_channel {
                        tracing::warn!(
                            "Ignoring RGB media chunk from peer {}: funding txid {} already has {} media files, the per-channel cap",
                            key.peer,
                            key.funding_txid,
                            in_flight_files + staged_files,
                        );
                        return Ok(());
                    }
                }
            } else if file_prospective > self.max_consignment_size() {
                tracing::warn!(
                    "Ignoring RGB consignment chunk from peer {}: funding txid {} would exceed its {} byte cap",
                    key.peer,
                    key.funding_txid,
                    self.max_consignment_size(),
                );
                return Ok(());
            }
        }

        let state = reassembly
            .entry(key.clone())
            .or_insert_with(|| ReassemblyState::new(now));
        // first chunk locks in total_chunks; later chunks were checked to agree with it above
        if state.total_chunks == 0 {
            state.total_chunks = msg.total_chunks;
        }
        // only a chunk we actually accept counts as progress, so a peer can't keep a transfer alive
        // by dribbling out chunks we reject (malformed chunks abort the transfer above, so they can't
        // either)
        state.last_progress = now;
        state.buffered += msg.data.len();
        state.chunks.insert(msg.chunk_index, msg.data);

        let complete = (0..state.total_chunks).all(|i| state.chunks.contains_key(&i));
        if complete {
            // `buffered` is the exact summed length of every chunk, so this is the final file size
            let mut bytes = Vec::with_capacity(state.buffered);
            for i in 0..state.total_chunks {
                bytes.extend_from_slice(&state.chunks[&i]);
            }
            reassembly.remove(&key);
            drop(reassembly);
            // written synchronously so the files are in place before `funding_created` (which
            // arrives after the chunks on the same ordered connection) is processed
            self.persist_file(&key, bytes, now);
        }
        Ok(())
    }
}

impl CustomMessageHandler for RgbFileTransferHandler {
    fn handle_custom_message(
        &self,
        msg: Self::CustomMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        self.handle_chunk(msg, sender_node_id, Instant::now())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        std::mem::take(&mut *self.outbound.lock().unwrap())
    }

    fn peer_disconnected(&self, their_node_id: PublicKey) {
        // drop whatever the peer left half-transferred, so incomplete transfers don't accumulate
        self.reassembly
            .lock()
            .unwrap()
            .retain(|key, _| key.peer != their_node_id);
    }

    fn peer_connected(
        &self,
        _their_node_id: PublicKey,
        _msg: &Init,
        _inbound: bool,
    ) -> Result<(), ()> {
        Ok(())
    }

    fn provided_node_features(&self) -> NodeFeatures {
        NodeFeatures::empty()
    }

    fn provided_init_features(&self, _their_node_id: PublicKey) -> InitFeatures {
        InitFeatures::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn peer_id(byte: u8) -> PublicKey {
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &sk)
    }

    fn dummy_peer() -> PublicKey {
        peer_id(0x01)
    }

    // stands in for the channel manager
    #[derive(Default)]
    struct TestGate {
        // holds one entry per channel, so a peer appearing twice has two channels with us
        channels: Vec<PublicKey>,
        funded_txids: Vec<String>,
    }

    impl TestGate {
        fn with_channels(channels: Vec<PublicKey>) -> Self {
            TestGate {
                channels,
                ..Default::default()
            }
        }
    }

    impl PeerChannelGate for TestGate {
        fn channel_count_with(&self, peer: &PublicKey) -> usize {
            self.channels.iter().filter(|p| *p == peer).count()
        }

        fn has_channel_funded_by(&self, funding_txid: &str) -> bool {
            self.funded_txids.iter().any(|t| t == funding_txid)
        }
    }

    // handler that accepts files from the peers the tests use
    fn handler(dir: &tempfile::TempDir) -> RgbFileTransferHandler {
        handler_gated(
            dir,
            TestGate::with_channels(vec![peer_id(0x01), peer_id(0x02)]),
        )
    }

    fn handler_gated(dir: &tempfile::TempDir, gate: TestGate) -> RgbFileTransferHandler {
        RgbFileTransferHandler::new(
            dir.path().to_path_buf(),
            Arc::new(gate),
            MAX_PENDING_CONSIGNMENTS,
            MAX_MEDIA_BYTES_PER_CHANNEL,
            MAX_MEDIA_FILES_PER_CHANNEL,
        )
    }

    fn media_chunk(funding_txid: &str, data: Vec<u8>) -> RgbFileMessage {
        RgbFileMessage {
            file_kind: FILE_KIND_MEDIA,
            funding_txid: funding_txid.to_string(),
            file_id: sha256::Hash::hash(&data).to_string(),
            chunk_index: 0,
            total_chunks: 1,
            data,
        }
    }

    fn staged_path(handler: &RgbFileTransferHandler, funding_txid: &str, data: &[u8]) -> PathBuf {
        get_media_staging_dir(&handler.ldk_data_dir, funding_txid)
            .join(sha256::Hash::hash(data).to_string())
    }

    fn consignment_chunk(
        funding_txid: &str,
        chunk_index: u16,
        total_chunks: u16,
        data: Vec<u8>,
    ) -> RgbFileMessage {
        RgbFileMessage {
            file_kind: FILE_KIND_CONSIGNMENT,
            funding_txid: funding_txid.to_string(),
            file_id: String::new(),
            chunk_index,
            total_chunks,
            data,
        }
    }

    #[test]
    fn reassembly_completes_with_scrambled_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(3);
        let peer = dummy_peer();
        let txid = "aa".repeat(32);

        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 3, b"aaa".to_vec()), peer)
            .unwrap();
        handler
            .handle_custom_message(consignment_chunk(&txid, 2, 3, b"ccc".to_vec()), peer)
            .unwrap();
        assert!(!handler.consignment_path(&txid).exists());

        handler
            .handle_custom_message(consignment_chunk(&txid, 1, 3, b"bbb".to_vec()), peer)
            .unwrap();
        assert_eq!(
            fs::read(handler.consignment_path(&txid)).unwrap(),
            b"aaabbbccc"
        );
    }

    #[test]
    fn a_peer_without_a_channel_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let stranger = peer_id(0x03);
        let handler = handler_gated(&dir, TestGate::with_channels(vec![dummy_peer()]));
        let txid = "ac".repeat(32);

        // a complete, otherwise valid transfer from a peer we have no channel with
        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 1, b"aaa".to_vec()), stranger)
            .unwrap();

        // nothing buffered, nothing written to disk
        assert!(handler.reassembly.lock().unwrap().is_empty());
        assert!(!handler.consignment_path(&txid).exists());

        // while the counterparty we do have a channel with is served
        handler
            .handle_custom_message(
                consignment_chunk(&txid, 0, 1, b"aaa".to_vec()),
                dummy_peer(),
            )
            .unwrap();
        assert_eq!(fs::read(handler.consignment_path(&txid)).unwrap(), b"aaa");
    }

    #[test]
    fn a_chunk_for_an_already_funded_channel_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let txid = "0a".repeat(32);
        // the peer has a channel with us, and its funding is already open
        let handler = handler_gated(
            &dir,
            TestGate {
                channels: vec![peer],
                funded_txids: vec![txid.clone()],
            },
        );
        let t0 = Instant::now();

        // a consignment naming that live channel's funding is rejected before it can overwrite the
        // consignment file the funded channel still relies on
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"evil".to_vec()), peer, t0)
            .unwrap();
        assert!(handler.reassembly.lock().unwrap().is_empty());
        assert!(!handler.consignment_path(&txid).exists());
    }

    #[test]
    fn a_stalled_transfer_is_swept_once_it_stops_making_progress() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(2);
        let peer = dummy_peer();
        let txid = "ad".repeat(32);
        let t0 = Instant::now();

        // a transfer left half-finished by a peer that stays connected
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 2, b"aa".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(handler.reassembly.lock().unwrap().len(), 1);

        // still within the TTL: kept, since a slow transfer is not a dead one
        handler.sweep_stale_transfers_at(t0 + REASSEMBLY_TTL / 2);
        assert_eq!(handler.reassembly.lock().unwrap().len(), 1);

        // past the TTL with no progress: the buffer is reclaimed
        handler.sweep_stale_transfers_at(t0 + REASSEMBLY_TTL);
        assert!(handler.reassembly.lock().unwrap().is_empty());
    }

    #[test]
    fn a_chunk_refreshes_the_deadline_of_a_slow_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(2);
        let peer = dummy_peer();
        let txid = "ae".repeat(32);
        let t0 = Instant::now();
        let second_chunk = t0 + REASSEMBLY_TTL / 2;

        handler
            .handle_chunk(consignment_chunk(&txid, 0, 3, b"aa".to_vec()), peer, t0)
            .unwrap();
        // a chunk arriving halfway through the TTL restarts the clock
        handler
            .handle_chunk(
                consignment_chunk(&txid, 1, 3, b"bb".to_vec()),
                peer,
                second_chunk,
            )
            .unwrap();

        // so a sweep past the first chunk's deadline leaves the transfer alone
        handler.sweep_stale_transfers_at(t0 + REASSEMBLY_TTL);
        assert_eq!(handler.reassembly.lock().unwrap().len(), 1);

        // and it is only dropped once the refreshed deadline passes too
        handler.sweep_stale_transfers_at(second_chunk + REASSEMBLY_TTL);
        assert!(handler.reassembly.lock().unwrap().is_empty());
    }

    #[test]
    fn consignments_are_capped_node_wide() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let other = peer_id(0x02);
        // node-wide limit for one consignment
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer, other]))
            .with_pending_consignments_limit(1);
        let t0 = Instant::now();
        let txid1 = "01".repeat(32);
        let txid2 = "02".repeat(32);
        let txid3 = "03".repeat(32);

        handler
            .handle_chunk(consignment_chunk(&txid1, 0, 1, b"aaa".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(fs::read(handler.consignment_path(&txid1)).unwrap(), b"aaa");

        // funding txids can be invented by a sender, so without the cap a peer could fill the disk
        // with invalid consignments it never funds
        handler
            .handle_chunk(consignment_chunk(&txid2, 0, 1, b"bbb".to_vec()), peer, t0)
            .unwrap();
        assert!(!handler.consignment_path(&txid2).exists());

        // the cap is node-wide, so a second node (a Sybil) gets no fresh allowance
        handler
            .handle_chunk(consignment_chunk(&txid3, 0, 1, b"ccc".to_vec()), other, t0)
            .unwrap();
        assert!(!handler.consignment_path(&txid3).exists());

        // resending a consignment we already hold is ignored, not overwritten: the first content
        // stands and the funding is not counted twice
        handler
            .handle_chunk(consignment_chunk(&txid1, 0, 1, b"ddd".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(fs::read(handler.consignment_path(&txid1)).unwrap(), b"aaa");
    }

    #[test]
    fn a_resent_consignment_does_not_reset_the_media_budget() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        const LIMIT: usize = 6;
        let handler =
            handler_gated(&dir, TestGate::with_channels(vec![peer])).with_media_limit(LIMIT);
        let t0 = Instant::now();
        let txid = "07".repeat(32);

        // a consignment, then media that fills the per-channel budget
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"con".to_vec()), peer, t0)
            .unwrap();
        let max_size_media = vec![0u8; LIMIT];
        handler
            .handle_chunk(media_chunk(&txid, max_size_media.clone()), peer, t0)
            .unwrap();
        assert!(staged_path(&handler, &txid, &max_size_media).exists());

        // resend the consignment with distinct bytes: it is ignored, not re-persisted, so the file
        // keeps its original content rather than being overwritten
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"resent".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(fs::read(handler.consignment_path(&txid)).unwrap(), b"con");

        // and because it was ignored the staged-media accounting stands, so more media, which would
        // fit only if the budget had been reset, is still refused
        let more_media = vec![1u8];
        handler
            .handle_chunk(media_chunk(&txid, more_media.clone()), peer, t0)
            .unwrap();
        assert!(!staged_path(&handler, &txid, &more_media).exists());
    }

    #[test]
    fn in_flight_media_files_are_capped_per_funding() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        const MAX_FILES: usize = 3;
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer]))
            .with_media_files_limit(MAX_FILES);
        let t0 = Instant::now();
        let txid = "08".repeat(32);

        // each message is the short last chunk of a distinct two-chunk media file, so it stays in
        // flight holding a single byte: the object-count amplification the byte budget can't stop
        let incomplete = |seed: u8| RgbFileMessage {
            file_kind: FILE_KIND_MEDIA,
            funding_txid: txid.clone(),
            file_id: sha256::Hash::hash(&[seed; 8]).to_string(),
            chunk_index: 1,
            total_chunks: 2,
            data: vec![seed],
        };

        for seed in 0..MAX_FILES as u8 {
            handler.handle_chunk(incomplete(seed), peer, t0).unwrap();
        }
        assert_eq!(handler.reassembly.lock().unwrap().len(), MAX_FILES);

        // one more distinct media file is refused once the funding is at its file cap, even though
        // its single byte is nowhere near the byte budget
        handler.handle_chunk(incomplete(0xff), peer, t0).unwrap();
        assert_eq!(handler.reassembly.lock().unwrap().len(), MAX_FILES);
    }

    #[test]
    fn a_consignment_larger_than_the_cap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        // a small per-consignment size cap, so the test needn't build 16 MB
        let handler =
            handler_gated(&dir, TestGate::with_channels(vec![peer])).with_consignment_size_limit(4);
        let t0 = Instant::now();
        let txid = "0f".repeat(32);

        // a chunk that would push the file past its size cap is refused before it is buffered, so
        // the oversized file never lands in memory or on disk
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"aaaaa".to_vec()), peer, t0)
            .unwrap();
        assert!(!handler.consignment_path(&txid).exists());
        assert!(handler.reassembly.lock().unwrap().is_empty());
    }

    #[test]
    fn an_empty_chunk_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir);
        let peer = dummy_peer();
        let txid = "0e".repeat(32);

        // an empty chunk carries no data and would let an incomplete transfer sit in memory,
        // costing nothing against any byte budget
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 2, vec![]), peer, Instant::now())
            .unwrap();
        assert!(handler.reassembly.lock().unwrap().is_empty());
    }

    #[test]
    fn only_the_last_chunk_may_be_short() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(4);
        let peer = dummy_peer();
        let txid1 = "0f".repeat(32);
        let t0 = Instant::now();

        // a non-final chunk shorter than chunk_size is refused
        handler
            .handle_chunk(consignment_chunk(&txid1, 0, 2, b"ab".to_vec()), peer, t0)
            .unwrap();
        assert!(handler.reassembly.lock().unwrap().is_empty());

        // a full non-final chunk is accepted, and a shorter last chunk completes the file
        handler
            .handle_chunk(consignment_chunk(&txid1, 0, 2, b"abcd".to_vec()), peer, t0)
            .unwrap();
        handler
            .handle_chunk(consignment_chunk(&txid1, 1, 2, b"ef".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(
            fs::read(handler.consignment_path(&txid1)).unwrap(),
            b"abcdef"
        );

        // same with chunk order inverted
        let txid2 = "0f".repeat(32);
        handler
            .handle_chunk(consignment_chunk(&txid2, 1, 2, b"ef".to_vec()), peer, t0)
            .unwrap();
        handler
            .handle_chunk(consignment_chunk(&txid2, 0, 2, b"abcd".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(
            fs::read(handler.consignment_path(&txid2)).unwrap(),
            b"abcdef"
        );
    }

    #[test]
    fn incomplete_transfers_count_against_the_pending_cap() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        // room for one pending funding
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer]))
            .with_pending_consignments_limit(1)
            .with_chunk_size(2);
        let t0 = Instant::now();
        let stuck_txid = "01".repeat(32);
        let fresh_txid = "02".repeat(32);

        // a transfer that arrives but never completes still occupies one pending slot
        handler
            .handle_chunk(
                consignment_chunk(&stuck_txid, 0, 2, b"aa".to_vec()),
                peer,
                t0,
            )
            .unwrap();
        assert_eq!(handler.reassembly.lock().unwrap().len(), 1);

        // so a new funding is refused at its first chunk, not only once something completes
        handler
            .handle_chunk(
                consignment_chunk(&fresh_txid, 0, 2, b"bb".to_vec()),
                peer,
                t0,
            )
            .unwrap();
        let reassembly = handler.reassembly.lock().unwrap();
        assert_eq!(reassembly.len(), 1);
        assert!(reassembly.keys().all(|k| k.funding_txid == stuck_txid));
    }

    #[test]
    fn media_aggregate_counts_bytes_still_in_flight() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        // budget with room for one full chunk but not two
        const CHUNK: usize = 50;
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer]))
            .with_media_limit(CHUNK + CHUNK / 2)
            .with_chunk_size(CHUNK);
        let t0 = Instant::now();
        let txid = "03".repeat(32);

        // a consignment, so media is accepted for this funding
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"aaa".to_vec()), peer, t0)
            .unwrap();

        // one media file holding a full chunk in flight (2 chunks, only the first sent)
        let media = |file_id: &str| RgbFileMessage {
            file_kind: FILE_KIND_MEDIA,
            funding_txid: txid.clone(),
            file_id: file_id.to_string(),
            chunk_index: 0,
            total_chunks: 2,
            data: vec![0u8; CHUNK],
        };
        handler
            .handle_chunk(media(&"aa".repeat(32)), peer, t0)
            .unwrap();

        // a second media file whose first chunk, added to the first's in-flight bytes, would exceed
        // the channel's media budget is refused, even though neither file alone exceeds it, and
        // nothing has been staged yet
        handler
            .handle_chunk(media(&"bb".repeat(32)), peer, t0)
            .unwrap();
        let media_entries = handler
            .reassembly
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.file_kind == FILE_KIND_MEDIA)
            .count();
        assert_eq!(media_entries, 1);
    }

    #[test]
    fn an_unfunded_consignment_is_reclaimed_and_a_funded_one_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let funded_txid = "03".repeat(32);
        let never_funded_txid = "04".repeat(32);
        let handler = handler_gated(
            &dir,
            TestGate {
                channels: vec![peer, peer],
                funded_txids: vec![funded_txid.clone()],
            },
        );
        let t0 = Instant::now();

        // the never-funded consignment arrives normally over p2p
        handler
            .handle_chunk(
                consignment_chunk(&never_funded_txid, 0, 1, b"aaa".to_vec()),
                peer,
                t0,
            )
            .unwrap();
        // the funded one was written before its channel funded, so put that pre-funding state in
        // place directly
        fs::write(handler.consignment_path(&funded_txid), b"aaa").unwrap();
        handler.staged_fundings.lock().unwrap().insert(
            FundingStagingKey {
                peer,
                funding_txid: funded_txid.clone(),
            },
            FundingStagingRecord {
                written_at: t0,
                staged_media_bytes: 0,
                staged_media_count: 0,
            },
        );

        // before the TTL nothing is touched, however the funding turned out
        handler.sweep_unfunded_stagings_at(t0);
        assert!(handler.consignment_path(&never_funded_txid).exists());

        handler.sweep_unfunded_stagings_at(t0 + CONSIGNMENT_TTL);
        // the channel that opened keeps its consignment: deleting it would make the acceptor read
        // the colored channel as vanilla. It is removed when that channel closes.
        assert!(handler.consignment_path(&funded_txid).exists());
        // the one that never funded is deleted
        assert!(!handler.consignment_path(&never_funded_txid).exists());
    }

    #[test]
    fn a_funded_consignment_stops_counting_against_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let funded_txid = "05".repeat(32);
        // node-wide room for one consignment
        let handler = handler_gated(
            &dir,
            TestGate {
                channels: vec![peer],
                funded_txids: vec![funded_txid.clone()],
            },
        )
        .with_pending_consignments_limit(1);
        let t0 = Instant::now();

        handler
            .handle_chunk(
                consignment_chunk(&funded_txid, 0, 1, b"aaa".to_vec()),
                peer,
                t0,
            )
            .unwrap();
        // once the funding happens the file belongs to a real channel, so it must stop occupying a
        // slot, otherwise the next channel's consignment would be refused
        handler.sweep_unfunded_stagings_at(t0);
        assert!(handler.staged_fundings.lock().unwrap().is_empty());

        let next_txid = "06".repeat(32);
        handler
            .handle_chunk(
                consignment_chunk(&next_txid, 0, 1, b"bbb".to_vec()),
                peer,
                t0,
            )
            .unwrap();
        assert_eq!(
            fs::read(handler.consignment_path(&next_txid)).unwrap(),
            b"bbb"
        );
    }

    #[test]
    fn forgetting_a_closed_channels_consignment_frees_a_slot() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        // node-wide room for one consignment
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer]))
            .with_pending_consignments_limit(1);
        let t0 = Instant::now();
        let txid1 = "07".repeat(32);
        let txid2 = "08".repeat(32);

        handler
            .handle_chunk(consignment_chunk(&txid1, 0, 1, b"aaa".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(fs::read(handler.consignment_path(&txid1)).unwrap(), b"aaa");

        // simulate a channel that funds and closes within a sweep interval, so the sweep never saw
        // it as funded and its record would otherwise linger; the ChannelClosed handler forgets it
        // instead
        handler.forget_staged_funding(&txid1);
        assert!(handler.staged_fundings.lock().unwrap().is_empty());

        // with the slot freed, the next channel's consignment is accepted rather than refused
        handler
            .handle_chunk(consignment_chunk(&txid2, 0, 1, b"bbb".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(fs::read(handler.consignment_path(&txid2)).unwrap(), b"bbb");
    }

    #[test]
    fn media_is_staged_and_needs_an_outstanding_consignment() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer]));
        let t0 = Instant::now();
        let txid = "07".repeat(32);

        // media for a funding we hold no consignment for is refused: otherwise a peer could stage
        // media against any funding txid it cared to invent
        handler
            .handle_chunk(media_chunk(&txid, b"picture".to_vec()), peer, t0)
            .unwrap();
        assert!(!staged_path(&handler, &txid, b"picture").exists());

        // with a consignment outstanding it is staged, not placed among the wallet's real media:
        // nothing has vouched for these bytes until the consignment is accepted at funding
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"aaa".to_vec()), peer, t0)
            .unwrap();
        handler
            .handle_chunk(media_chunk(&txid, b"picture".to_vec()), peer, t0)
            .unwrap();
        assert_eq!(
            fs::read(staged_path(&handler, &txid, b"picture")).unwrap(),
            b"picture"
        );
    }

    #[test]
    fn media_that_does_not_match_its_claimed_digest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer]));
        let t0 = Instant::now();
        let txid = "0e".repeat(32);
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"aaa".to_vec()), peer, t0)
            .unwrap();

        // the sender says one thing and sends another: known-bad bytes, so nothing is written and
        // the funding's staging budget is not spent on them
        let mut msg = media_chunk(&txid, b"picture".to_vec());
        msg.file_id = "cd".repeat(32);
        handler.handle_chunk(msg, peer, t0).unwrap();

        assert!(!get_media_staging_dir(&handler.ldk_data_dir, &txid).exists());
        let persisted = handler.staged_fundings.lock().unwrap();
        assert_eq!(persisted.values().next().unwrap().staged_media_bytes, 0);
    }

    #[test]
    fn staged_media_is_capped_per_funding() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        const LIMIT: usize = 400;
        let handler =
            handler_gated(&dir, TestGate::with_channels(vec![peer])).with_media_limit(LIMIT);
        let t0 = Instant::now();
        let txid = "08".repeat(32);
        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"aaa".to_vec()), peer, t0)
            .unwrap();

        // media is content-addressed, so distinct bytes mean distinct files: without a cap one
        // funding would let a peer write as many as it likes. Four files fill the byte budget, so the
        // fifth is the one that must be refused
        let mut accepted = 0;
        for i in 0..5u8 {
            let data = vec![i; LIMIT / 4];
            handler
                .handle_chunk(media_chunk(&txid, data.clone()), peer, t0)
                .unwrap();
            if staged_path(&handler, &txid, &data).exists() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 4);

        let staged = handler.staged_fundings.lock().unwrap();
        let record = staged.values().next().unwrap();
        assert!(record.staged_media_bytes <= LIMIT);
    }

    #[test]
    fn staged_media_is_discarded_when_the_funding_never_happens() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let handler = handler_gated(&dir, TestGate::with_channels(vec![peer]));
        let t0 = Instant::now();
        let txid = "09".repeat(32);

        handler
            .handle_chunk(consignment_chunk(&txid, 0, 1, b"aaa".to_vec()), peer, t0)
            .unwrap();
        handler
            .handle_chunk(media_chunk(&txid, b"picture".to_vec()), peer, t0)
            .unwrap();
        assert!(staged_path(&handler, &txid, b"picture").exists());

        handler.sweep_unfunded_stagings_at(t0 + CONSIGNMENT_TTL);
        assert!(!get_media_staging_dir(&handler.ldk_data_dir, &txid).exists());
    }

    #[test]
    fn orphans_from_a_previous_run_are_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let peer = dummy_peer();
        let funded_txid = "0a".repeat(32);
        let never_funded_txid = "0b".repeat(32);
        let t0 = Instant::now();

        // before the restart both files were written while their channels were still being funded,
        // so nothing was funded yet
        {
            let handler = handler_gated(
                &dir,
                TestGate {
                    channels: vec![peer, peer],
                    funded_txids: vec![],
                },
            );
            for txid in [&funded_txid, &never_funded_txid] {
                handler
                    .handle_chunk(consignment_chunk(txid, 0, 1, b"aaa".to_vec()), peer, t0)
                    .unwrap();
                handler
                    .handle_chunk(media_chunk(txid, b"picture".to_vec()), peer, t0)
                    .unwrap();
            }
        }

        // restart: `funded` has since funded, `never_funded` never did. The record of what was
        // written is gone, so only the directory is left to go on
        let handler = handler_gated(
            &dir,
            TestGate {
                channels: vec![peer, peer],
                funded_txids: vec![funded_txid.clone()],
            },
        );
        assert!(handler.staged_fundings.lock().unwrap().is_empty());

        // nothing old enough yet
        handler.cleanup_orphans_at(SystemTime::now());
        assert!(handler.consignment_path(&never_funded_txid).exists());

        handler.cleanup_orphans_at(SystemTime::now() + CONSIGNMENT_TTL);
        // the funding that never happened takes its media with it
        assert!(!handler.consignment_path(&never_funded_txid).exists());
        assert!(!get_media_staging_dir(&handler.ldk_data_dir, &never_funded_txid).exists());
        // the channel that opened keeps its consignment, whatever run wrote it
        assert!(handler.consignment_path(&funded_txid).exists());
    }

    #[test]
    fn reclaiming_orphans_leaves_the_closing_consignment_alone() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler_gated(&dir, TestGate::default());

        // the transient closing consignment shares the prefix but is owned elsewhere, as
        // denoted by its suffix
        let closing = dir
            .path()
            .join(format!("consignment_{}_rgb:contract-id", "0c".repeat(32)));
        fs::write(&closing, b"x").unwrap();

        handler.cleanup_orphans_at(SystemTime::now() + CONSIGNMENT_TTL);
        assert!(closing.exists());
    }

    #[test]
    fn a_funding_txid_that_is_not_a_txid_is_rejected() {
        // the funding txid names a file and a staging directory, so a peer must not be able to
        // steer those paths
        let encode = |msg: &RgbFileMessage| {
            let mut encoded = Vec::new();
            msg.write(&mut encoded).unwrap();
            encoded
        };

        for txid in [
            "../../etc/passwd",
            "",
            &"ab".repeat(64),
            "zz".repeat(32).as_str(),
        ] {
            let encoded = encode(&consignment_chunk(txid, 0, 1, b"aaa".to_vec()));
            assert!(
                RgbFileMessage::read_from(&mut &encoded[..]).is_err(),
                "accepted bogus funding txid {txid:?}"
            );
        }

        // a canonical one still round-trips
        let msg = consignment_chunk(&"ab".repeat(32), 0, 1, b"aaa".to_vec());
        let encoded = encode(&msg);
        assert_eq!(RgbFileMessage::read_from(&mut &encoded[..]).unwrap(), msg);
    }

    #[test]
    fn an_out_of_range_index_aborts_the_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(1);
        let peer = dummy_peer();
        let txid = "bb".repeat(32);

        // two valid chunks buffer, leaving the transfer in flight
        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 3, b"a".to_vec()), peer)
            .unwrap();
        handler
            .handle_custom_message(consignment_chunk(&txid, 1, 3, b"b".to_vec()), peer)
            .unwrap();
        assert_eq!(handler.reassembly.lock().unwrap().len(), 1);

        // a chunk whose index is out of range (5 of 3) is malformed: the whole transfer is dropped,
        // so it can never assemble garbage from a set like {0, 1, 5}
        handler
            .handle_custom_message(consignment_chunk(&txid, 5, 3, b"c".to_vec()), peer)
            .unwrap();
        assert!(handler.reassembly.lock().unwrap().is_empty());
        assert!(!handler.consignment_path(&txid).exists());
    }

    #[test]
    fn an_inconsistent_total_chunks_aborts_the_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(1);
        let peer = dummy_peer();
        let txid = "bd".repeat(32);

        // a chunk locks the transfer in at total_chunks = 3
        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 3, b"a".to_vec()), peer)
            .unwrap();
        assert_eq!(handler.reassembly.lock().unwrap().len(), 1);

        // a later chunk claiming a different total is malformed: the whole transfer is dropped
        handler
            .handle_custom_message(consignment_chunk(&txid, 1, 5, b"b".to_vec()), peer)
            .unwrap();
        assert!(handler.reassembly.lock().unwrap().is_empty());
    }

    #[test]
    fn reassembly_state_is_dropped_when_the_peer_disconnects() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(1);
        let peer = dummy_peer();
        let other = peer_id(0x02);
        let txid = "cc".repeat(32);

        // both peers leave a transfer half-finished
        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 2, b"a".to_vec()), peer)
            .unwrap();
        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 2, b"a".to_vec()), other)
            .unwrap();
        assert_eq!(handler.reassembly.lock().unwrap().len(), 2);

        // only the disconnecting peer's state goes away
        handler.peer_disconnected(peer);
        let reassembly = handler.reassembly.lock().unwrap();
        assert_eq!(reassembly.len(), 1);
        assert!(reassembly.keys().all(|k| k.peer == other));
    }

    #[test]
    fn peers_cannot_interfere_with_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(2);
        let txid = "dd".repeat(32);

        // two peers each send one half of the same funding txid: keyed by sender, neither completes,
        // rather than assembling one file out of two peers' chunks
        handler
            .handle_custom_message(
                consignment_chunk(&txid, 0, 2, b"aa".to_vec()),
                peer_id(0x01),
            )
            .unwrap();
        handler
            .handle_custom_message(
                consignment_chunk(&txid, 1, 2, b"bb".to_vec()),
                peer_id(0x02),
            )
            .unwrap();

        assert!(!handler.consignment_path(&txid).exists());
        assert_eq!(handler.reassembly.lock().unwrap().len(), 2);
    }

    #[test]
    fn chunk_count_refuses_what_the_framing_cannot_number() {
        // callers reject empty files, so the smallest input is one byte: a single chunk
        assert_eq!(chunk_count(1), Some(1));
        assert_eq!(chunk_count(CHUNK_SIZE), Some(1));
        assert_eq!(chunk_count(CHUNK_SIZE + 1), Some(2));

        // the largest file the u16 chunk count can describe, and the first one it cannot: a cast
        // would wrap these to 0 and 1 respectively, and the receiver would either drop every chunk
        // or complete on the first one and write a truncated file
        let max = CHUNK_SIZE * u16::MAX as usize;
        assert_eq!(chunk_count(max), Some(u16::MAX));
        assert_eq!(chunk_count(max + 1), None);
        assert_eq!(chunk_count(usize::MAX), None);
    }

    #[test]
    fn a_file_id_that_is_not_a_digest_is_rejected() {
        let encode = |msg: &RgbFileMessage| {
            let mut encoded = Vec::new();
            msg.write(&mut encoded).unwrap();
            encoded
        };
        let txid = "ab".repeat(32);
        let media = |file_id: &str| RgbFileMessage {
            file_kind: FILE_KIND_MEDIA,
            funding_txid: txid.clone(),
            file_id: file_id.to_string(),
            chunk_index: 0,
            total_chunks: 1,
            data: b"x".to_vec(),
        };

        // the file id keys the reassembly map, so an arbitrary-length string is refused
        for file_id in ["", &"z".repeat(65_000), "not-a-digest"] {
            let encoded = encode(&media(file_id));
            assert!(
                RgbFileMessage::read_from(&mut &encoded[..]).is_err(),
                "accepted bogus media file id {file_id:?}"
            );
        }
        let good = media(&"cd".repeat(32));
        let encoded = encode(&good);
        assert_eq!(RgbFileMessage::read_from(&mut &encoded[..]).unwrap(), good);

        // a consignment carries no file id, there being one per funding
        let mut consignment = consignment_chunk(&txid, 0, 1, b"x".to_vec());
        let encoded = encode(&consignment);
        assert_eq!(
            RgbFileMessage::read_from(&mut &encoded[..]).unwrap(),
            consignment
        );
        assert_eq!(consignment.file_id, "");
        consignment.file_id = "cd".repeat(32);
        let encoded = encode(&consignment);
        assert!(RgbFileMessage::read_from(&mut &encoded[..]).is_err());
    }

    #[test]
    fn resent_chunk_aborts_the_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let handler = handler(&dir).with_chunk_size(3);
        let peer = dummy_peer();
        let txid = "ba".repeat(32);

        // a non-final chunk of a two-chunk file leaves the transfer in flight
        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 2, b"aaa".to_vec()), peer)
            .unwrap();
        assert_eq!(handler.reassembly.lock().unwrap().len(), 1);

        // re-sending an index we already hold is a malformed stream: the whole transfer is dropped
        handler
            .handle_custom_message(consignment_chunk(&txid, 0, 2, b"aaa".to_vec()), peer)
            .unwrap();
        assert!(handler.reassembly.lock().unwrap().is_empty());
        assert!(!handler.consignment_path(&txid).exists());
    }
}

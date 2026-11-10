//! Evidence-collection helpers shared by the reproduction tests.
//!
//! Nodes run in-process, so the strongest evidence channel is a node's own data directory: this
//! module snapshots it, diffs two snapshots and pretty-prints the result, so a test can show
//! exactly which files a scenario created, removed or rewrote — and, via the same snapshots on a
//! clean run, which of those also happen on the happy path.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use lightning::ln::types::ChannelId;
use lightning::util::ser::Writeable;

use crate::disk::{read_channel_ids_info, CHANNEL_IDS_FNAME};

use super::*;

/// Files whose contents change on every run regardless of the scenario. Their size still shows up
/// in a snapshot, but [`SnapshotDiff::excluding_volatile`] drops them so a diff stays readable.
fn is_volatile(rel_path: &str) -> bool {
    let file_name = file_name_of(rel_path);
    rel_path.starts_with(".ldk/logs/") || file_name == LDK_LOGS_FILE || rel_path.ends_with("/log")
}

/// Whether a path inside a node directory holds RGB state. These are the files a repro test cares
/// about, so they are the ones a snapshot hashes; everything else is recorded by size only.
///
/// Two groups: the rgb-lib wallet (`<fingerprint>/rgb/`, `rgb_lib_db`, `transfers/`, `assets/`,
/// `media_files/`, `wallet_manifest.json`) and the RGB records LDK keeps beside its own state in
/// `.ldk/` (consignments, funding PSBTs, per-transfer info, the RGB channel-info files named after
/// a channel ID, and the former-temporary -> final channel ID map).
fn is_rgb_related(rel_path: &str) -> bool {
    let file_name = file_name_of(rel_path);

    if rel_path.contains("/rgb/")
        || rel_path.contains("/transfers/")
        || rel_path.contains("/assets/")
        || rel_path.contains("/media_files/")
        || file_name == "rgb_lib_db"
        || file_name == "wallet_manifest.json"
    {
        return true;
    }

    file_name == CHANNEL_IDS_FNAME
        || file_name.starts_with("consignment_")
        || file_name.starts_with("psbt_")
        || file_name.ends_with("_transfer_info")
        || is_channel_info_name(file_name)
}

/// RGB channel info is written to `.ldk/<channel_id>` (final) and `.ldk/<channel_id>.pending`.
fn is_channel_info_name(file_name: &str) -> bool {
    let stem = file_name.strip_suffix(".pending").unwrap_or(file_name);
    stem.len() == 64 && stem.chars().all(|c| c.is_ascii_hexdigit())
}

fn file_name_of(rel_path: &str) -> &str {
    rel_path.rsplit('/').next().unwrap_or(rel_path)
}

fn short_hash(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

/// One file as recorded by a [`DirSnapshot`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileEntry {
    pub size: u64,
    /// sha256 of the contents, computed only for RGB-related files (see [`is_rgb_related`]).
    pub sha256: Option<String>,
}

impl FileEntry {
    fn describe(&self) -> String {
        match &self.sha256 {
            Some(hash) => format!("{} bytes, sha256 {}", self.size, short_hash(hash)),
            None => format!("{} bytes", self.size),
        }
    }
}

/// The state of a node data directory at one point in time: relative path -> entry, sorted.
#[derive(Clone, Debug)]
pub(crate) struct DirSnapshot {
    /// what this snapshot is of, e.g. "node1 before the second open"
    pub label: String,
    pub root: PathBuf,
    pub entries: BTreeMap<String, FileEntry>,
}

/// Snapshot a node's data directory (`tmp/<test>/node<N>`), recording every file's path relative
/// to that directory and its size, plus the sha256 of RGB-related files.
///
/// A missing directory yields an empty snapshot rather than an error, so a test can snapshot
/// before the node has been started.
pub(crate) fn snapshot_node_dir(label: &str, node_test_dir: &str) -> DirSnapshot {
    let root = PathBuf::from(node_test_dir);
    let mut entries = BTreeMap::new();

    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(rel) = entry.path().strip_prefix(&root) else {
            continue;
        };
        let rel_path = rel.to_string_lossy().replace('\\', "/");
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let sha256 = if is_rgb_related(&rel_path) {
            std::fs::read(entry.path())
                .ok()
                .map(|bytes| Sha256::hash(&bytes).to_string())
        } else {
            None
        };
        entries.insert(
            rel_path,
            FileEntry {
                size: metadata.len(),
                sha256,
            },
        );
    }

    DirSnapshot {
        label: label.to_string(),
        root,
        entries,
    }
}

impl DirSnapshot {
    pub(crate) fn get(&self, rel_path: &str) -> Option<&FileEntry> {
        self.entries.get(rel_path)
    }

    pub(crate) fn contains(&self, rel_path: &str) -> bool {
        self.entries.contains_key(rel_path)
    }

    /// Paths satisfying `pred`, in sorted order — e.g. every consignment the node holds.
    pub(crate) fn paths_matching<F: Fn(&str) -> bool>(&self, pred: F) -> Vec<String> {
        self.entries.keys().filter(|p| pred(p)).cloned().collect()
    }

    /// Diff this snapshot (the "before") against a later one.
    pub(crate) fn diff(&self, after: &DirSnapshot) -> SnapshotDiff {
        assert_eq!(
            self.root, after.root,
            "refusing to diff snapshots of different node directories"
        );

        let mut diff = SnapshotDiff {
            before_label: self.label.clone(),
            after_label: after.label.clone(),
            root: self.root.clone(),
            ..Default::default()
        };

        for (path, before) in &self.entries {
            match after.entries.get(path) {
                None => diff.removed.push(EntryDiff {
                    path: path.clone(),
                    before: Some(before.clone()),
                    after: None,
                }),
                Some(after_entry) if after_entry != before => diff.changed.push(EntryDiff {
                    path: path.clone(),
                    before: Some(before.clone()),
                    after: Some(after_entry.clone()),
                }),
                Some(_) => {}
            }
        }

        for (path, after_entry) in &after.entries {
            if !self.entries.contains_key(path) {
                diff.added.push(EntryDiff {
                    path: path.clone(),
                    before: None,
                    after: Some(after_entry.clone()),
                });
            }
        }

        diff
    }
}

/// One path that differs between two snapshots. `before` is `None` for an added file, `after` is
/// `None` for a removed one.
#[derive(Clone, Debug)]
pub(crate) struct EntryDiff {
    pub path: String,
    pub before: Option<FileEntry>,
    pub after: Option<FileEntry>,
}

/// The difference between two [`DirSnapshot`]s of the same node directory.
#[derive(Clone, Debug, Default)]
pub(crate) struct SnapshotDiff {
    pub before_label: String,
    pub after_label: String,
    pub root: PathBuf,
    pub added: Vec<EntryDiff>,
    pub removed: Vec<EntryDiff>,
    pub changed: Vec<EntryDiff>,
}

impl SnapshotDiff {
    pub(crate) fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Every path that was added, removed or rewritten, sorted and deduplicated.
    pub(crate) fn paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .added
            .iter()
            .chain(&self.removed)
            .chain(&self.changed)
            .map(|e| e.path.clone())
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    pub(crate) fn added_paths(&self) -> Vec<String> {
        self.added.iter().map(|e| e.path.clone()).collect()
    }

    pub(crate) fn removed_paths(&self) -> Vec<String> {
        self.removed.iter().map(|e| e.path.clone()).collect()
    }

    pub(crate) fn changed_paths(&self) -> Vec<String> {
        self.changed.iter().map(|e| e.path.clone()).collect()
    }

    pub(crate) fn filter<F: Fn(&str) -> bool>(&self, pred: F) -> SnapshotDiff {
        let keep = |entries: &[EntryDiff]| -> Vec<EntryDiff> {
            entries.iter().filter(|e| pred(&e.path)).cloned().collect()
        };
        SnapshotDiff {
            before_label: self.before_label.clone(),
            after_label: self.after_label.clone(),
            root: self.root.clone(),
            added: keep(&self.added),
            removed: keep(&self.removed),
            changed: keep(&self.changed),
        }
    }

    /// Only the RGB state — the usual starting point when looking for residue.
    pub(crate) fn rgb_only(&self) -> SnapshotDiff {
        self.filter(is_rgb_related)
    }

    /// Drop the log files, which churn on every run and would otherwise swamp the output.
    pub(crate) fn excluding_volatile(&self) -> SnapshotDiff {
        self.filter(|path| !is_volatile(path))
    }

    pub(crate) fn pretty(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "--- data dir diff [{}]: {} -> {}",
            self.root.display(),
            self.before_label,
            self.after_label
        );
        if self.is_empty() {
            let _ = writeln!(out, "  (no changes)");
            return out;
        }
        for entry in &self.added {
            let after = entry
                .after
                .as_ref()
                .expect("added entry has an after state");
            let _ = writeln!(out, "  + {} ({})", entry.path, after.describe());
        }
        for entry in &self.removed {
            let before = entry
                .before
                .as_ref()
                .expect("removed entry has a before state");
            let _ = writeln!(out, "  - {} (was {})", entry.path, before.describe());
        }
        for entry in &self.changed {
            let before = entry
                .before
                .as_ref()
                .expect("changed entry has a before state");
            let after = entry
                .after
                .as_ref()
                .expect("changed entry has an after state");
            let _ = writeln!(
                out,
                "  ~ {} ({} -> {})",
                entry.path,
                before.describe(),
                after.describe()
            );
        }
        out
    }

    /// Print the diff to the test's stdout (visible with `-- --nocapture`).
    pub(crate) fn print(&self) {
        print!("{}", self.pretty());
    }
}

/// Path of the former-temporary -> final channel ID map inside a node's data directory.
pub(crate) fn channel_ids_path(node_test_dir: &str) -> PathBuf {
    PathBuf::from(node_test_dir)
        .join(LDK_DIR)
        .join(CHANNEL_IDS_FNAME)
}

/// The former-temporary -> final channel ID map as the node persisted it, as sorted
/// `(temporary, final)` hex pairs. An absent or unreadable file reads as an empty map, exactly as
/// the node itself reads it on startup (`disk::read_channel_ids_info`).
pub(crate) fn channel_ids_on_disk(node_test_dir: &str) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> =
        read_channel_ids_info(&channel_ids_path(node_test_dir))
            .channel_ids
            .iter()
            .map(|(tmp, final_id)| (hex_str(&tmp.0), hex_str(&final_id.0)))
            .collect();
    entries.sort();
    entries
}

/// Add a `temporary -> final` entry to a **stopped** node's persisted channel ID map. The node
/// only reads the map from disk at startup, so this is the only way to hand it a map it would not
/// have built itself.
pub(crate) fn inject_channel_id_entry(node_test_dir: &str, temporary: &str, final_id: &str) {
    let path = channel_ids_path(node_test_dir);
    let mut map = read_channel_ids_info(&path);
    map.channel_ids.insert(
        channel_id_from_hex(temporary),
        channel_id_from_hex(final_id),
    );
    std::fs::write(&path, map.encode()).unwrap();
}

fn channel_id_from_hex(hex: &str) -> ChannelId {
    let bytes = hex_str_to_vec(hex).unwrap_or_else(|| panic!("{hex} is not valid hex"));
    ChannelId(bytes.try_into().expect("a channel ID is 32 bytes"))
}

/// One output of a transaction, as bitcoind reports it.
#[derive(Clone, Debug)]
pub(crate) struct TxOutput {
    pub index: u32,
    pub sats: u64,
    pub script_pubkey: String,
    pub script_type: String,
}

impl TxOutput {
    pub(crate) fn is_op_return(&self) -> bool {
        self.script_type == "nulldata"
    }
}

/// Every output of `txid`, in transaction order. The harness already has `tx_output_sats`, but a
/// claim about *which* output holds something needs the scripts as well as the values.
pub(crate) fn tx_outputs(txid: &str) -> Vec<TxOutput> {
    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(bitcoin_cli())
        .arg("getrawtransaction")
        .arg(txid)
        .arg("true")
        .output()
        .expect("able to call getrawtransaction");
    assert!(output.status.success(), "no such transaction: {txid}");
    let tx: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid tx JSON");
    tx["vout"]
        .as_array()
        .expect("vout array")
        .iter()
        .map(|v| TxOutput {
            index: v["n"].as_u64().expect("output index") as u32,
            sats: Amount::from_btc(v["value"].as_f64().expect("output value"))
                .expect("valid amount")
                .to_sat(),
            script_pubkey: v["scriptPubKey"]["hex"]
                .as_str()
                .expect("output script")
                .to_string(),
            script_type: v["scriptPubKey"]["type"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        })
        .collect()
}

/// Pretty-print a transaction's outputs, marking the funding one.
pub(crate) fn print_tx_outputs(label: &str, txid: &str, funding_index: Option<u16>) {
    println!("{label} {txid}");
    for out in tx_outputs(txid) {
        let marker = if Some(out.index as u16) == funding_index {
            " <- channel funding output"
        } else {
            ""
        };
        println!(
            "  vout {}: {:>10} sat  {:<12} {}{marker}",
            out.index, out.sats, out.script_type, out.script_pubkey
        );
    }
}

/// The funding output index LDK settled on, recovered from the channel ID rather than from a guess
/// about the transaction layout: a v1 channel ID is the funding txid with its last two bytes xored
/// with the output index (`ChannelId::v1_from_funding_txid`), so exactly one index of the funding
/// transaction reproduces the channel's ID.
pub(crate) fn funding_output_index_of(
    channel_id: &str,
    funding_txid: &str,
    num_outputs: usize,
) -> u16 {
    let txid = bitcoin::Txid::from_str(funding_txid).expect("valid funding txid");
    let txid_bytes = Hash::as_byte_array(&txid);
    (0..num_outputs as u16)
        .find(|index| hex_str(&ChannelId::v1_from_funding_txid(txid_bytes, *index).0) == channel_id)
        .unwrap_or_else(|| panic!("no output of {funding_txid} derives channel ID {channel_id}"))
}

/// The funding transaction a node built, read from the PSBT it persisted in `.ldk/psbt_<txid>`.
/// Unlike [`tx_outputs`] this works for a funding that was never broadcast, which is the case
/// whenever the open fails after the transaction was built. Returns `(txid, outputs)`.
pub(crate) fn funding_psbt_outputs(node_test_dir: &str) -> (String, Vec<TxOutput>) {
    let ldk_dir = PathBuf::from(node_test_dir).join(LDK_DIR);
    let mut psbts: Vec<PathBuf> = std::fs::read_dir(&ldk_dir)
        .expect("the node has an .ldk directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| file_name_of(&p.to_string_lossy()).starts_with("psbt_"))
        .collect();
    psbts.sort();
    assert_eq!(
        psbts.len(),
        1,
        "expected exactly one persisted funding PSBT, got {psbts:?}"
    );
    let txid = file_name_of(&psbts[0].to_string_lossy())
        .trim_start_matches("psbt_")
        .to_string();
    let psbt = bitcoin::psbt::Psbt::from_str(&std::fs::read_to_string(&psbts[0]).unwrap())
        .expect("a valid funding PSBT");
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .map(|(index, out)| TxOutput {
            index: index as u32,
            sats: out.value.to_sat(),
            script_pubkey: out.script_pubkey.to_hex_string(),
            script_type: script_type_of(&out.script_pubkey),
        })
        .collect();
    (txid, outputs)
}

/// The `scriptPubKey.type` string bitcoind would report for a script, so that outputs read from a
/// PSBT and outputs read from bitcoind describe themselves the same way.
fn script_type_of(script: &bitcoin::ScriptBuf) -> String {
    if script.is_op_return() {
        s!("nulldata")
    } else if script.is_p2wsh() {
        s!("witness_v0_scripthash")
    } else if script.is_p2wpkh() {
        s!("witness_v0_keyhash")
    } else if script.is_p2tr() {
        s!("witness_v1_taproot")
    } else {
        s!("other")
    }
}

/// Print outputs that were read from a PSBT rather than from bitcoind.
pub(crate) fn print_outputs(
    label: &str,
    txid: &str,
    outputs: &[TxOutput],
    funding_index: Option<u16>,
) {
    println!("{label} {txid}");
    for out in outputs {
        let marker = if Some(out.index as u16) == funding_index {
            " <- channel funding output"
        } else {
            ""
        };
        println!(
            "  vout {}: {:>10} sat  {:<22} {}{marker}",
            out.index, out.sats, out.script_type, out.script_pubkey
        );
    }
}

/// Exercises the snapshot/diff/print helpers on a throwaway directory laid out like a real node
/// dir. Pure filesystem work: no regtest services, no node.
#[serial_test::serial]
#[test]
fn repro_util_snapshot_diff() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap().to_string();
    let ldk = tmp.path().join(LDK_DIR);
    let wallet = tmp.path().join("0a58336b");
    std::fs::create_dir_all(ldk.join("logs")).unwrap();
    std::fs::create_dir_all(wallet.join("rgb")).unwrap();

    let chan_a = "a".repeat(64);
    std::fs::write(ldk.join(&chan_a), "{\"local\":100}").unwrap();
    std::fs::write(ldk.join(format!("{chan_a}.pending")), "{\"local\":100}").unwrap();
    std::fs::write(ldk.join(CHANNEL_IDS_FNAME), "one entry").unwrap();
    std::fs::write(ldk.join("manager"), "ldk state").unwrap();
    std::fs::write(ldk.join("logs").join(LDK_LOGS_FILE), "line one\n").unwrap();
    std::fs::write(wallet.join("rgb").join("stash.dat"), "stash").unwrap();

    let before = snapshot_node_dir("before", &root);
    assert_eq!(before.entries.len(), 6);

    // RGB-related files are hashed, everything else is recorded by size only
    assert!(before
        .get(&format!(".ldk/{chan_a}"))
        .unwrap()
        .sha256
        .is_some());
    assert!(before.get(".ldk/channel_ids").unwrap().sha256.is_some());
    assert!(before
        .get("0a58336b/rgb/stash.dat")
        .unwrap()
        .sha256
        .is_some());
    assert!(before.get(".ldk/manager").unwrap().sha256.is_none());
    assert!(before.get(".ldk/logs/logs.txt").unwrap().sha256.is_none());

    // a missing directory is an empty snapshot, not an error
    assert!(
        snapshot_node_dir("absent", &format!("{root}/does_not_exist"))
            .entries
            .is_empty()
    );

    // a scenario runs: one file appears, one is rewritten in place at the same size, one is
    // removed, and the log churns
    let chan_b = "b".repeat(64);
    std::fs::write(ldk.join(&chan_b), "{\"local\":200}").unwrap();
    std::fs::write(ldk.join(CHANNEL_IDS_FNAME), "two entries").unwrap();
    std::fs::write(ldk.join(&chan_a), "{\"local\":999}").unwrap();
    std::fs::remove_file(ldk.join(format!("{chan_a}.pending"))).unwrap();
    std::fs::write(ldk.join("logs").join(LDK_LOGS_FILE), "line one\nline two\n").unwrap();

    let after = snapshot_node_dir("after", &root);
    let diff = before.diff(&after);
    diff.print();

    assert_eq!(diff.added_paths(), vec![format!(".ldk/{chan_b}")]);
    assert_eq!(diff.removed_paths(), vec![format!(".ldk/{chan_a}.pending")]);
    assert_eq!(
        diff.changed_paths(),
        vec![
            format!(".ldk/{chan_a}"),
            s!(".ldk/channel_ids"),
            s!(".ldk/logs/logs.txt")
        ]
    );

    // a same-size rewrite is still a change, because RGB-related files are compared by hash
    let chan_a_diff = diff
        .changed
        .iter()
        .find(|e| e.path == format!(".ldk/{chan_a}"))
        .unwrap();
    assert_eq!(
        chan_a_diff.before.as_ref().unwrap().size,
        chan_a_diff.after.as_ref().unwrap().size
    );
    assert_ne!(
        chan_a_diff.before.as_ref().unwrap().sha256,
        chan_a_diff.after.as_ref().unwrap().sha256
    );

    // filters
    assert!(!diff
        .excluding_volatile()
        .changed_paths()
        .contains(&s!(".ldk/logs/logs.txt")));
    // the four RGB paths above; the log churn is not RGB state
    assert_eq!(diff.rgb_only().paths().len(), 4);
    assert_eq!(
        after.paths_matching(|p| p.ends_with(".pending")),
        Vec::<String>::new()
    );

    // pretty-printing marks each kind of change
    let pretty = diff.pretty();
    assert!(pretty.contains(&format!("+ .ldk/{chan_b}")));
    assert!(pretty.contains(&format!("- .ldk/{chan_a}.pending")));
    assert!(pretty.contains("~ .ldk/channel_ids"));

    // and an unchanged directory diffs to nothing
    let unchanged = snapshot_node_dir("unchanged", &root);
    let empty = after.diff(&unchanged);
    assert!(empty.is_empty(), "{}", empty.pretty());
    assert!(empty.pretty().contains("(no changes)"));
}

/// The channel ID map helpers round-trip through the node's own encoding: what
/// [`inject_channel_id_entry`] writes is what [`channel_ids_on_disk`] — and the node's
/// `disk::read_channel_ids_info` — reads back.
#[serial_test::serial]
#[test]
fn repro_util_channel_ids_map() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap().to_string();
    std::fs::create_dir_all(tmp.path().join(LDK_DIR)).unwrap();

    let temp_a = "a".repeat(64);
    let temp_b = "b".repeat(64);
    let final_a = "c".repeat(64);

    // an absent file reads as an empty map, not an error
    assert!(channel_ids_on_disk(&root).is_empty());

    inject_channel_id_entry(&root, &temp_a, &final_a);
    assert_eq!(
        channel_ids_on_disk(&root),
        vec![(temp_a.clone(), final_a.clone())]
    );

    // two temporary keys can map to one final ID
    inject_channel_id_entry(&root, &temp_b, &final_a);
    assert_eq!(
        channel_ids_on_disk(&root),
        vec![(temp_a, final_a.clone()), (temp_b, final_a)]
    );
}

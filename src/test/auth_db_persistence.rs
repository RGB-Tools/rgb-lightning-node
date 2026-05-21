use biscuit_auth::{macros::biscuit, KeyPair};
use chrono::Utc;
use rln_migration::{Migrator, MigratorTrait};
use sea_orm::{ActiveValue, ConnectOptions, Database, DatabaseConnection, EntityTrait};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::sync::CancellationToken;

use crate::database::entities::{
    ChannelPeerActMod, ChannelPeerEntity, RevokedTokenActMod, RevokedTokenEntity,
};
use crate::database::RlnDatabase;
use crate::disk::FilesystemLogger;
use crate::utils::{AppState, StaticState};

fn build_state(storage_dir_path: PathBuf, database: DatabaseConnection) -> AppState {
    AppState {
        static_state: Arc::new(StaticState {
            ldk_peer_listening_port: 9735,
            network: rgb_lib::BitcoinNetwork::Regtest,
            storage_dir_path: storage_dir_path.clone(),
            ldk_data_dir: storage_dir_path.join(".ldk"),
            logger: Arc::new(FilesystemLogger::new(storage_dir_path)),
            max_media_upload_size_mb: 1,
            enable_virtual_channels_v0: false,
            virtual_peer_pubkeys: vec![],
            database: RwLock::new(Arc::new(database)),
            lsp_base_url: None,
            lsp_bearer_token: None,
            vss_url: None,
            vss_allow_empty_restore: false,
        }),
        cancel_token: CancellationToken::new(),
        unlocked_app_state: Arc::new(TokioMutex::new(None)),
        ldk_background_services: Arc::new(Mutex::new(None)),
        changing_state: Mutex::new(false),
        root_public_key: None,
        revoked_tokens: Arc::new(Mutex::new(HashSet::new())),
    }
}

fn setup_test_db() -> DatabaseConnection {
    let db_path = std::env::temp_dir().join(format!("rln-db-test-{}", uuid::Uuid::new_v4()));
    let connection_string = format!("sqlite:{}?mode=rwc", db_path.display());
    let db = crate::runtime::block_on(Database::connect(ConnectOptions::new(connection_string)))
        .expect("db connection");
    crate::runtime::block_on(Migrator::up(&db, None)).expect("run migrations");
    db
}

#[test]
fn revoke_token_does_not_update_in_memory_when_db_persist_fails() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = tmp_dir.path().join("rln_db");
    let connection_string = format!("sqlite:{}?mode=rwc", db_path.display());
    let database =
        crate::runtime::block_on(Database::connect(ConnectOptions::new(connection_string)))
            .expect("db connection");

    // Intentionally do not run migrations to force DB persist failure.
    let state = build_state(tmp_dir.path().to_path_buf(), database);
    let keypair = KeyPair::new();
    let token = biscuit!("role(\"custom\");")
        .build(&keypair)
        .expect("valid biscuit");

    let res = state.revoke_token(&token);
    assert!(res.is_err(), "revoke_token should fail without DB schema");

    // In-memory set must remain unchanged if DB write fails.
    let revoked = state.revoked_tokens.lock().unwrap();
    assert!(
        revoked.is_empty(),
        "in-memory set must not be updated when DB write fails"
    );
}

#[test]
fn load_revoked_tokens_silently_ignores_malformed_hex_rows() {
    let db = setup_test_db();

    crate::runtime::block_on(
        RevokedTokenEntity::insert(RevokedTokenActMod {
            token_id: ActiveValue::Set("zzzzzz-not-hex".to_string()),
            revoked_at: ActiveValue::Set(Utc::now()),
        })
        .exec(&db),
    )
    .expect("insert malformed token");

    let rln_db = RlnDatabase::new(db);
    let revoked = rln_db
        .load_revoked_tokens()
        .expect("load_revoked_tokens should not error");
    assert!(
        revoked.is_empty(),
        "malformed token rows are silently skipped"
    );
}

#[test]
fn read_channel_peer_data_silently_ignores_malformed_rows() {
    let db = setup_test_db();

    crate::runtime::block_on(
        ChannelPeerEntity::insert(ChannelPeerActMod {
            pubkey: ActiveValue::Set("not-a-pubkey".to_string()),
            address: ActiveValue::Set("not-an-address".to_string()),
            created_at: ActiveValue::Set(Utc::now()),
        })
        .exec(&db),
    )
    .expect("insert malformed channel peer");

    let rln_db = RlnDatabase::new(db);
    let peers = rln_db
        .read_channel_peer_data()
        .expect("read_channel_peer_data should not error");
    assert!(peers.is_empty(), "malformed peer rows are silently skipped");
}

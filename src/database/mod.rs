pub(crate) mod entities;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use futures::executor::block_on;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter};

use crate::database::entities::{
    ChannelPeerActMod, ChannelPeerColumn, ChannelPeerEntity, ConfigActMod, ConfigColumn,
    ConfigEntity, DbMnemonic, DbMnemonicActMod, MnemonicColumn, MnemonicEntity, RevokedTokenActMod,
    RevokedTokenColumn, RevokedTokenEntity,
};
use crate::error::APIError;

pub struct RlnDatabase {
    connection: DatabaseConnection,
}

impl RlnDatabase {
    pub fn new(connection: DatabaseConnection) -> Self {
        Self { connection }
    }

    pub fn get_connection(&self) -> &DatabaseConnection {
        &self.connection
    }

    pub fn add_revoked_token(&self, token_id_hex: &str) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;

        let token = RevokedTokenActMod {
            token_id: ActiveValue::Set(token_id_hex.to_string()),
            revoked_at: ActiveValue::Set(now),
        };

        // Use on_conflict to ignore duplicates
        block_on(
            RevokedTokenEntity::insert(token)
                .on_conflict(
                    OnConflict::column(RevokedTokenColumn::TokenId)
                        .do_nothing()
                        .to_owned(),
                )
                .exec(self.get_connection()),
        )
        .map_err(|e| std::io::Error::other(format!("Database write failed: {e}")))?;

        Ok(())
    }

    pub fn delete_channel_peer(&self, pubkey: &str) -> Result<(), APIError> {
        let result = block_on(
            ChannelPeerEntity::find()
                .filter(ChannelPeerColumn::Pubkey.eq(pubkey))
                .one(self.get_connection()),
        )
        .map_err(|e| std::io::Error::other(format!("Database query failed: {e}")))?;

        if let Some(peer) = result {
            block_on(peer.delete(self.get_connection()))
                .map_err(|e| std::io::Error::other(format!("Database delete failed: {e}")))?;
        }

        Ok(())
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>, APIError> {
        let result = block_on(
            ConfigEntity::find()
                .filter(ConfigColumn::Key.eq(key))
                .one(self.get_connection()),
        )
        .map_err(|e| std::io::Error::other(format!("Database query failed: {e}")))?;

        Ok(result.map(|r| r.value))
    }

    pub fn get_mnemonic(&self) -> Result<Option<DbMnemonic>, APIError> {
        block_on(MnemonicEntity::find_by_id(1).one(self.get_connection()))
            .map_err(|e| std::io::Error::other(format!("Database query failed: {e}")))
            .map_err(APIError::IO)
    }

    pub fn load_revoked_tokens(&self) -> Result<HashSet<Vec<u8>>, APIError> {
        let results = block_on(RevokedTokenEntity::find().all(self.get_connection()))
            .map_err(|e| std::io::Error::other(format!("Database query failed: {e}")))?;

        let mut revoked = HashSet::new();
        for record in results {
            if let Some(token_bytes) = crate::utils::hex_str_to_vec(&record.token_id) {
                revoked.insert(token_bytes);
            }
        }

        Ok(revoked)
    }

    pub fn mnemonic_exists(&self) -> Result<bool, APIError> {
        let result = block_on(MnemonicEntity::find_by_id(1).one(self.get_connection()))
            .map_err(|e| std::io::Error::other(format!("Database query failed: {e}")))?;
        Ok(result.is_some())
    }

    pub fn persist_channel_peer(
        &self,
        pubkey: &PublicKey,
        address: &SocketAddr,
    ) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;

        let peer = ChannelPeerActMod {
            pubkey: ActiveValue::Set(pubkey.to_string()),
            address: ActiveValue::Set(address.to_string()),
            created_at: ActiveValue::Set(now),
        };

        block_on(
            ChannelPeerEntity::insert(peer)
                .on_conflict(
                    OnConflict::column(ChannelPeerColumn::Pubkey)
                        .update_column(ChannelPeerColumn::Address)
                        .to_owned(),
                )
                .exec(self.get_connection()),
        )
        .map_err(|e| std::io::Error::other(format!("Database write failed: {e}")))?;

        tracing::info!("persisted peer (pubkey: {pubkey}, addr: {address})");
        Ok(())
    }

    pub fn read_channel_peer_data(&self) -> Result<HashMap<PublicKey, SocketAddr>, APIError> {
        let results = block_on(ChannelPeerEntity::find().all(self.get_connection()))
            .map_err(|e| std::io::Error::other(format!("Database query failed: {e}")))?;

        let mut peer_data = HashMap::new();
        for record in results {
            if let (Ok(pubkey), Ok(address)) = (
                PublicKey::from_str(&record.pubkey),
                SocketAddr::from_str(&record.address),
            ) {
                peer_data.insert(pubkey, address);
            }
        }

        Ok(peer_data)
    }

    pub fn save_mnemonic(&self, encrypted_mnemonic: String) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;

        let mnemonic = DbMnemonicActMod {
            id: ActiveValue::Set(1),
            encrypted_mnemonic: ActiveValue::Set(encrypted_mnemonic),
            created_at: ActiveValue::Set(now),
            updated_at: ActiveValue::Set(now),
        };

        block_on(
            MnemonicEntity::insert(mnemonic)
                .on_conflict(
                    OnConflict::column(MnemonicColumn::Id)
                        .update_columns([
                            MnemonicColumn::EncryptedMnemonic,
                            MnemonicColumn::UpdatedAt,
                        ])
                        .to_owned(),
                )
                .exec(self.get_connection()),
        )
        .map_err(|e| std::io::Error::other(format!("Database write failed: {e}")))?;

        Ok(())
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<(), APIError> {
        let now = crate::utils::get_current_timestamp() as i64;

        let config = ConfigActMod {
            key: ActiveValue::Set(key.to_string()),
            value: ActiveValue::Set(value.to_string()),
            created_at: ActiveValue::Set(now),
            updated_at: ActiveValue::Set(now),
        };

        block_on(
            ConfigEntity::insert(config)
                .on_conflict(
                    OnConflict::column(ConfigColumn::Key)
                        .update_columns([ConfigColumn::Value, ConfigColumn::UpdatedAt])
                        .to_owned(),
                )
                .exec(self.get_connection()),
        )
        .map_err(|e| std::io::Error::other(format!("Database write failed: {e}")))?;

        Ok(())
    }
}

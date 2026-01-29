use std::sync::Arc;

use bitcoin::io;
use futures::executor::block_on;
use lightning::util::persist::KVStoreSync;
use sea_orm::sea_query::OnConflict;

use crate::database::entities::{KvStoreActMod, KvStoreColumn, KvStoreEntity};
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

/// Sea-ORM based KVStore implementation for LDK persistence.
/// Uses block_on for sync context.
pub struct SeaOrmKvStore {
    connection: Arc<DatabaseConnection>,
}

impl SeaOrmKvStore {
    /// Create a SeaOrmKvStore from an existing shared connection.
    /// Does NOT run migrations (assumes they were already run).
    pub fn from_connection(connection: Arc<DatabaseConnection>) -> Self {
        tracing::info!("SeaOrmKvStore initialized from shared connection");
        Self { connection }
    }

    fn get_connection(&self) -> &DatabaseConnection {
        &self.connection
    }
}

impl KVStoreSync for SeaOrmKvStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, io::Error> {
        tracing::trace!(primary_namespace, secondary_namespace, key, "KVStore read");

        let result = block_on(
            KvStoreEntity::find()
                .filter(KvStoreColumn::PrimaryNamespace.eq(primary_namespace))
                .filter(KvStoreColumn::SecondaryNamespace.eq(secondary_namespace))
                .filter(KvStoreColumn::Key.eq(key))
                .one(self.get_connection()),
        )
        .map_err(|e| {
            tracing::error!(
                primary_namespace,
                secondary_namespace,
                key,
                error = %e,
                "KVStore read failed"
            );
            io::Error::new(io::ErrorKind::Other, format!("Database read failed: {e}"))
        })?;

        match result {
            Some(record) => {
                tracing::trace!(
                    primary_namespace,
                    secondary_namespace,
                    key,
                    value_len = record.value.len(),
                    "KVStore read success"
                );
                Ok(record.value)
            }
            None => {
                tracing::trace!(
                    primary_namespace,
                    secondary_namespace,
                    key,
                    "KVStore key not found"
                );
                Err(io::Error::new(io::ErrorKind::NotFound, "Key not found"))
            }
        }
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Result<(), io::Error> {
        tracing::trace!(
            primary_namespace,
            secondary_namespace,
            key,
            value_len = buf.len(),
            "KVStore write"
        );

        let model = KvStoreActMod {
            primary_namespace: ActiveValue::Set(primary_namespace.to_string()),
            secondary_namespace: ActiveValue::Set(secondary_namespace.to_string()),
            key: ActiveValue::Set(key.to_string()),
            value: ActiveValue::Set(buf),
        };

        // Use UPSERT (INSERT ... ON CONFLICT DO UPDATE) for atomic write
        // This handles both insert and update in a single statement
        block_on(
            KvStoreEntity::insert(model)
                .on_conflict(
                    OnConflict::columns([
                        KvStoreColumn::PrimaryNamespace,
                        KvStoreColumn::SecondaryNamespace,
                        KvStoreColumn::Key,
                    ])
                    .update_column(KvStoreColumn::Value)
                    .to_owned(),
                )
                .exec(self.get_connection()),
        )
        .map_err(|e| {
            tracing::error!(
                primary_namespace,
                secondary_namespace,
                key,
                error = %e,
                "KVStore write failed"
            );
            io::Error::new(io::ErrorKind::Other, format!("Database write failed: {e}"))
        })?;

        Ok(())
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        lazy: bool,
    ) -> Result<(), io::Error> {
        tracing::trace!(
            primary_namespace,
            secondary_namespace,
            key,
            lazy,
            "KVStore remove"
        );

        let result = block_on(
            KvStoreEntity::delete_many()
                .filter(KvStoreColumn::PrimaryNamespace.eq(primary_namespace))
                .filter(KvStoreColumn::SecondaryNamespace.eq(secondary_namespace))
                .filter(KvStoreColumn::Key.eq(key))
                .exec(self.get_connection()),
        )
        .map_err(|e| {
            tracing::error!(
                primary_namespace,
                secondary_namespace,
                key,
                error = %e,
                "KVStore remove failed"
            );
            io::Error::new(io::ErrorKind::Other, format!("Database delete failed: {e}"))
        })?;

        tracing::trace!(
            primary_namespace,
            secondary_namespace,
            key,
            rows_affected = result.rows_affected,
            "KVStore remove complete"
        );

        Ok(())
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, io::Error> {
        tracing::trace!(primary_namespace, secondary_namespace, "KVStore list");

        let results = block_on(
            KvStoreEntity::find()
                .filter(KvStoreColumn::PrimaryNamespace.eq(primary_namespace))
                .filter(KvStoreColumn::SecondaryNamespace.eq(secondary_namespace))
                .all(self.get_connection()),
        )
        .map_err(|e| {
            tracing::error!(
                primary_namespace,
                secondary_namespace,
                error = %e,
                "KVStore list failed"
            );
            io::Error::new(io::ErrorKind::Other, format!("Database list failed: {e}"))
        })?;

        let keys: Vec<String> = results.into_iter().map(|r| r.key).collect();
        tracing::trace!(
            primary_namespace,
            secondary_namespace,
            count = keys.len(),
            "KVStore list complete"
        );

        Ok(keys)
    }
}

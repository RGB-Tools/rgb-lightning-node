use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Mnemonic::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Mnemonic::Id)
                            .integer()
                            .not_null()
                            .primary_key()
                            .default(1),
                    )
                    .col(string(Mnemonic::EncryptedMnemonic))
                    .col(big_unsigned(Mnemonic::CreatedAt))
                    .col(big_unsigned(Mnemonic::UpdatedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(KvStore::Table)
                    .if_not_exists()
                    .col(string(KvStore::PrimaryNamespace))
                    .col(string(KvStore::SecondaryNamespace))
                    .col(string(KvStore::Key))
                    .col(blob(KvStore::Value))
                    .primary_key(
                        Index::create()
                            .col(KvStore::PrimaryNamespace)
                            .col(KvStore::SecondaryNamespace)
                            .col(KvStore::Key),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Config::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Config::Key)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Config::Value).string().not_null())
                    .col(ColumnDef::new(Config::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Config::UpdatedAt).big_integer().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(RevokedToken::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RevokedToken::TokenId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RevokedToken::RevokedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ChannelPeer::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ChannelPeer::Pubkey)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ChannelPeer::Address).string().not_null())
                    .col(
                        ColumnDef::new(ChannelPeer::CreatedAt)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ChannelPeer::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RevokedToken::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Config::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(KvStore::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Mnemonic::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Mnemonic {
    Table,
    Id,
    EncryptedMnemonic,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum KvStore {
    Table,
    PrimaryNamespace,
    SecondaryNamespace,
    Key,
    Value,
}

#[derive(DeriveIden)]
enum Config {
    Table,
    Key,
    Value,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum RevokedToken {
    Table,
    TokenId,
    RevokedAt,
}

#[derive(DeriveIden)]
enum ChannelPeer {
    Table,
    Pubkey,
    Address,
    CreatedAt,
}

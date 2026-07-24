use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                        ColumnDef::new(Config::Idx)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(string(Config::EncryptedMnemonic))
                    .col(string_null(Config::IndexerUrl))
                    .col(string_null(Config::BitcoinNetwork))
                    .col(string_null(Config::WalletFingerprint))
                    .col(string_null(Config::WalletAccountXpubVanilla))
                    .col(string_null(Config::WalletAccountXpubColored))
                    .col(string_null(Config::WalletMasterFingerprint))
                    .col(big_unsigned(Config::CreatedAt))
                    .col(big_unsigned(Config::UpdatedAt))
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
            .await
    }
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
    Idx,
    EncryptedMnemonic,
    IndexerUrl,
    BitcoinNetwork,
    WalletFingerprint,
    WalletAccountXpubVanilla,
    WalletAccountXpubColored,
    WalletMasterFingerprint,
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

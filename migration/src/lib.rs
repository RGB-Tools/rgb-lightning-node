pub use sea_orm_migration::prelude::*;

mod m20250127_000001_init_db;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20250127_000001_init_db::Migration)]
    }
}

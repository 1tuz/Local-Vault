use super::model::SecretMetadata;
use crate::services::crypto::EncryptedValue;
use sqlx::SqlitePool;
#[derive(sqlx::FromRow)]
pub struct SecretRow {
  pub key: String,
  pub version: i64,
  pub ciphertext: Vec<u8>,
  pub value_nonce: Vec<u8>,
  pub wrapped_key: Vec<u8>,
  pub key_nonce: Vec<u8>,
  pub created_at: String,
  pub updated_at: String,
}
impl SecretRow {
  pub fn encrypted(&self) -> EncryptedValue {
    EncryptedValue {
      ciphertext: self.ciphertext.clone(),
      value_nonce: self.value_nonce.clone(),
      wrapped_key: self.wrapped_key.clone(),
      key_nonce: self.key_nonce.clone(),
    }
  }
  pub fn metadata(&self) -> SecretMetadata {
    SecretMetadata {
      key: self.key.clone(),
      version: self.version,
      created_at: self.created_at.clone(),
      updated_at: self.updated_at.clone(),
    }
  }
}
pub async fn list(
  pool: &SqlitePool,
  environment_id: &str,
) -> Result<Vec<SecretMetadata>, sqlx::Error> {
  sqlx::query_as(
    "SELECT key,version,created_at,updated_at FROM secrets WHERE environment_id=? ORDER BY key",
  )
  .bind(environment_id)
  .fetch_all(pool)
  .await
}
pub async fn rows(
  pool: &SqlitePool,
  environment_id: &str,
) -> Result<Vec<SecretRow>, sqlx::Error> {
  sqlx::query_as("SELECT key,version,ciphertext,value_nonce,wrapped_key,key_nonce,created_at,updated_at FROM secrets WHERE environment_id=? ORDER BY key").bind(environment_id).fetch_all(pool).await
}
pub async fn find(
  pool: &SqlitePool,
  environment_id: &str,
  key: &str,
) -> Result<Option<SecretRow>, sqlx::Error> {
  sqlx::query_as("SELECT key,version,ciphertext,value_nonce,wrapped_key,key_nonce,created_at,updated_at FROM secrets WHERE environment_id=? AND key=?").bind(environment_id).bind(key).fetch_optional(pool).await
}

pub async fn archive_version(
  tx: &mut sqlx::SqliteConnection,
  environment_id: &str,
  row: &SecretRow,
  archived_at: &str,
) -> Result<(), sqlx::Error> {
  sqlx::query("INSERT OR IGNORE INTO secret_versions(environment_id,key,version,ciphertext,value_nonce,wrapped_key,key_nonce,created_at,updated_at,archived_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
    .bind(environment_id)
    .bind(&row.key)
    .bind(row.version)
    .bind(&row.ciphertext)
    .bind(&row.value_nonce)
    .bind(&row.wrapped_key)
    .bind(&row.key_nonce)
    .bind(&row.created_at)
    .bind(&row.updated_at)
    .bind(archived_at)
    .execute(tx)
    .await?;
  Ok(())
}

pub async fn versions(
  pool: &SqlitePool,
  environment_id: &str,
  key: &str,
) -> Result<Vec<super::model::SecretVersionMetadata>, sqlx::Error> {
  sqlx::query_as("SELECT version,created_at,updated_at,archived_at FROM secret_versions WHERE environment_id=? AND key=? ORDER BY version DESC")
    .bind(environment_id)
    .bind(key)
    .fetch_all(pool)
    .await
}

pub async fn version(
  pool: &SqlitePool,
  environment_id: &str,
  key: &str,
  version: i64,
) -> Result<Option<SecretRow>, sqlx::Error> {
  sqlx::query_as("SELECT key,version,ciphertext,value_nonce,wrapped_key,key_nonce,created_at,updated_at FROM secret_versions WHERE environment_id=? AND key=? AND version=?")
    .bind(environment_id)
    .bind(key)
    .bind(version)
    .fetch_optional(pool)
    .await
}

pub async fn delete_version(
  tx: &mut sqlx::SqliteConnection,
  environment_id: &str,
  key: &str,
  version: i64,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("DELETE FROM secret_versions WHERE environment_id=? AND key=? AND version=?")
      .bind(environment_id)
      .bind(key)
      .bind(version)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}

pub async fn layout(
  pool: &SqlitePool,
  environment_id: &str,
) -> Result<Option<String>, sqlx::Error> {
  let row: Option<(String,)> =
    sqlx::query_as("SELECT layout FROM environment_env_layout WHERE environment_id=?")
      .bind(environment_id)
      .fetch_optional(pool)
      .await?;
  Ok(row.map(|(layout,)| layout))
}
pub async fn upsert_layout(
  tx: &mut sqlx::SqliteConnection,
  environment_id: &str,
  layout: &str,
  now: &str,
) -> Result<(), sqlx::Error> {
  sqlx::query("INSERT INTO environment_env_layout(environment_id,layout,updated_at)VALUES(?,?,?) ON CONFLICT(environment_id) DO UPDATE SET layout=excluded.layout,updated_at=excluded.updated_at")
        .bind(environment_id)
        .bind(layout)
        .bind(now)
        .execute(tx)
        .await?;
  Ok(())
}

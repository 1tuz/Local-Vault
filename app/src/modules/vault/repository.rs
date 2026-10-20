use super::model::{VaultFileMetadata, VaultFileVersion, VaultFolder};
use crate::services::crypto::EncryptedValue;
use sqlx::{SqliteConnection, SqlitePool};

#[derive(sqlx::FromRow)]
pub struct VaultFileRow {
  pub id: String,
  pub folder_id: String,
  pub environment_id: Option<String>,
  pub name: String,
  pub kind: String,
  pub encoding: String,
  pub version: i64,
  pub ciphertext: Vec<u8>,
  pub value_nonce: Vec<u8>,
  pub wrapped_key: Vec<u8>,
  pub key_nonce: Vec<u8>,
  pub created_at: String,
  pub updated_at: String,
}

impl VaultFileRow {
  pub fn encrypted(&self) -> EncryptedValue {
    EncryptedValue {
      ciphertext: self.ciphertext.clone(),
      value_nonce: self.value_nonce.clone(),
      wrapped_key: self.wrapped_key.clone(),
      key_nonce: self.key_nonce.clone(),
    }
  }
  pub fn metadata(&self) -> VaultFileMetadata {
    VaultFileMetadata {
      id: self.id.clone(),
      folder_id: self.folder_id.clone(),
      environment_id: self.environment_id.clone(),
      name: self.name.clone(),
      kind: self.kind.clone(),
      encoding: self.encoding.clone(),
      version: self.version,
      created_at: self.created_at.clone(),
      updated_at: self.updated_at.clone(),
    }
  }
}

const FILE_COLUMNS: &str = "id,folder_id,environment_id,name,kind,version,ciphertext,value_nonce,wrapped_key,key_nonce,created_at,updated_at,encoding";

pub async fn project_id(
  pool: &SqlitePool,
  project_ref: &str,
) -> Result<Option<String>, sqlx::Error> {
  sqlx::query_scalar("SELECT id FROM projects WHERE id=? OR name=?")
    .bind(project_ref)
    .bind(project_ref)
    .fetch_optional(pool)
    .await
}

pub async fn folders(
  pool: &SqlitePool,
  project_id: &str,
) -> Result<Vec<VaultFolder>, sqlx::Error> {
  sqlx::query_as("SELECT id,project_id,parent_id,environment_id,is_root,name,created_at,updated_at FROM vault_folders WHERE project_id=? ORDER BY is_root DESC,COALESCE(parent_id,''),name COLLATE NOCASE")
    .bind(project_id)
    .fetch_all(pool).await
}
pub async fn folder(
  pool: &SqlitePool,
  project_id: &str,
  id: &str,
) -> Result<Option<VaultFolder>, sqlx::Error> {
  sqlx::query_as("SELECT id,project_id,parent_id,environment_id,is_root,name,created_at,updated_at FROM vault_folders WHERE id=? AND project_id=?")
    .bind(id).bind(project_id)
    .fetch_optional(pool)
    .await
}
pub async fn folder_tx(
  tx: &mut SqliteConnection,
  project_id: &str,
  id: &str,
) -> Result<Option<VaultFolder>, sqlx::Error> {
  sqlx::query_as("SELECT id,project_id,parent_id,environment_id,is_root,name,created_at,updated_at FROM vault_folders WHERE id=? AND project_id=?")
    .bind(id).bind(project_id)
    .fetch_optional(tx)
    .await
}
pub async fn insert_folder(
  tx: &mut SqliteConnection,
  id: &str,
  project_id: &str,
  parent_id: Option<&str>,
  environment_id: Option<&str>,
  name: &str,
  now: &str,
) -> Result<(), sqlx::Error> {
  sqlx::query(
    "INSERT INTO vault_folders(id,project_id,parent_id,environment_id,name,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
  )
  .bind(id)
  .bind(project_id)
  .bind(parent_id)
  .bind(environment_id)
  .bind(name)
  .bind(now)
  .bind(now)
  .execute(tx)
  .await?;
  Ok(())
}
pub async fn move_folder(
  tx: &mut SqliteConnection,
  id: &str,
  parent_id: Option<&str>,
  name: &str,
  now: &str,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("UPDATE vault_folders SET parent_id=?,name=?,updated_at=? WHERE id=?")
      .bind(parent_id)
      .bind(name)
      .bind(now)
      .bind(id)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}
pub async fn set_folder_environment(
  tx: &mut SqliteConnection,
  id: &str,
  environment_id: Option<&str>,
  now: &str,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("UPDATE vault_folders SET environment_id=?,updated_at=? WHERE id=? AND is_root=0")
      .bind(environment_id)
      .bind(now)
      .bind(id)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}
pub async fn ensure_project_root(
  tx: &mut SqliteConnection,
  project_id: &str,
  root_id: &str,
  now: &str,
) -> Result<String, sqlx::Error> {
  sqlx::query("INSERT OR IGNORE INTO vault_folders(id,project_id,parent_id,environment_id,is_root,name,created_at,updated_at) VALUES(?,?,NULL,NULL,1,'',?,?)")
    .bind(root_id).bind(project_id).bind(now).bind(now).execute(&mut *tx).await?;
  let id: String =
    sqlx::query_scalar("SELECT id FROM vault_folders WHERE project_id=? AND is_root=1")
      .bind(project_id)
      .fetch_one(&mut *tx)
      .await?;
  sqlx::query("UPDATE vault_folders SET parent_id=?,updated_at=? WHERE project_id=? AND parent_id IS NULL AND is_root=0")
    .bind(&id).bind(now).bind(project_id).execute(&mut *tx).await?;
  Ok(id)
}
pub async fn delete_folder(
  tx: &mut SqliteConnection,
  id: &str,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("DELETE FROM vault_folders WHERE id=?")
      .bind(id)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}
pub async fn has_folder_children(
  tx: &mut SqliteConnection,
  id: &str,
) -> Result<bool, sqlx::Error> {
  let count: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM vault_folders WHERE parent_id=?) + (SELECT COUNT(*) FROM vault_files WHERE folder_id=?)")
    .bind(id).bind(id).fetch_one(tx).await?;
  Ok(count > 0)
}
pub async fn files(
  pool: &SqlitePool,
  project_id: &str,
  folder_id: &str,
) -> Result<Vec<VaultFileMetadata>, sqlx::Error> {
  sqlx::query_as("SELECT f.id,f.folder_id,f.environment_id,f.name,f.kind,f.version,f.created_at,f.updated_at,f.encoding FROM vault_files f JOIN vault_folders d ON d.id=f.folder_id WHERE d.project_id=? AND f.folder_id=? ORDER BY f.name COLLATE NOCASE")
    .bind(project_id).bind(folder_id).fetch_all(pool).await
}

pub async fn all_file_metadata(
  pool: &SqlitePool,
  project_id: &str,
) -> Result<Vec<VaultFileMetadata>, sqlx::Error> {
  sqlx::query_as("SELECT f.id,f.folder_id,f.environment_id,f.name,f.kind,f.version,f.created_at,f.updated_at,f.encoding FROM vault_files f JOIN vault_folders d ON d.id=f.folder_id WHERE d.project_id=? ORDER BY f.folder_id,f.name COLLATE NOCASE")
    .bind(project_id).fetch_all(pool).await
}
pub async fn file(
  pool: &SqlitePool,
  project_id: &str,
  id: &str,
) -> Result<Option<VaultFileRow>, sqlx::Error> {
  sqlx::query_as(&format!(
    "SELECT {FILE_COLUMNS} FROM vault_files WHERE id=? AND folder_id IN (SELECT id FROM vault_folders WHERE project_id=?)"
  ))
  .bind(id).bind(project_id)
  .fetch_optional(pool)
  .await
}
pub async fn file_tx(
  tx: &mut SqliteConnection,
  project_id: &str,
  id: &str,
) -> Result<Option<VaultFileRow>, sqlx::Error> {
  sqlx::query_as(&format!(
    "SELECT {FILE_COLUMNS} FROM vault_files WHERE id=? AND folder_id IN (SELECT id FROM vault_folders WHERE project_id=?)"
  ))
  .bind(id).bind(project_id)
  .fetch_optional(tx)
  .await
}
pub async fn insert_file(
  tx: &mut SqliteConnection,
  row: &VaultFileRow,
) -> Result<(), sqlx::Error> {
  sqlx::query("INSERT INTO vault_files(id,folder_id,environment_id,name,kind,version,ciphertext,value_nonce,wrapped_key,key_nonce,created_at,updated_at,encoding) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(&row.id).bind(&row.folder_id).bind(&row.environment_id).bind(&row.name).bind(&row.kind).bind(row.version)
    .bind(&row.ciphertext).bind(&row.value_nonce).bind(&row.wrapped_key).bind(&row.key_nonce)
    .bind(&row.created_at).bind(&row.updated_at).bind(&row.encoding).execute(tx).await?;
  Ok(())
}
pub async fn update_file(
  tx: &mut SqliteConnection,
  id: &str,
  version: i64,
  encrypted: &EncryptedValue,
  encoding: &str,
  now: &str,
) -> Result<u64, sqlx::Error> {
  Ok(sqlx::query("UPDATE vault_files SET version=?,ciphertext=?,value_nonce=?,wrapped_key=?,key_nonce=?,updated_at=?,encoding=? WHERE id=?")
    .bind(version).bind(&encrypted.ciphertext).bind(&encrypted.value_nonce).bind(&encrypted.wrapped_key).bind(&encrypted.key_nonce).bind(now).bind(encoding).bind(id)
    .execute(tx).await?.rows_affected())
}
pub async fn rename_file(
  tx: &mut SqliteConnection,
  id: &str,
  name: &str,
  now: &str,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("UPDATE vault_files SET name=?,updated_at=? WHERE id=?")
      .bind(name)
      .bind(now)
      .bind(id)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}
pub async fn move_file(
  tx: &mut SqliteConnection,
  id: &str,
  folder_id: &str,
  now: &str,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("UPDATE vault_files SET folder_id=?,updated_at=? WHERE id=?")
      .bind(folder_id)
      .bind(now)
      .bind(id)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}
pub async fn set_file_environment(
  tx: &mut SqliteConnection,
  id: &str,
  environment_id: Option<&str>,
  now: &str,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("UPDATE vault_files SET environment_id=?,updated_at=? WHERE id=?")
      .bind(environment_id)
      .bind(now)
      .bind(id)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}
pub async fn archive_file(
  tx: &mut SqliteConnection,
  row: &VaultFileRow,
  now: &str,
) -> Result<(), sqlx::Error> {
  sqlx::query("INSERT OR IGNORE INTO vault_file_versions(file_id,version,ciphertext,value_nonce,wrapped_key,key_nonce,created_at,updated_at,archived_at,encoding) VALUES(?,?,?,?,?,?,?,?,?,?)")
    .bind(&row.id).bind(row.version).bind(&row.ciphertext).bind(&row.value_nonce).bind(&row.wrapped_key).bind(&row.key_nonce).bind(&row.created_at).bind(&row.updated_at).bind(now).bind(&row.encoding)
    .execute(tx).await?;
  Ok(())
}
pub async fn versions(
  pool: &SqlitePool,
  id: &str,
) -> Result<Vec<VaultFileVersion>, sqlx::Error> {
  sqlx::query_as("SELECT version,encoding,created_at,updated_at,archived_at FROM vault_file_versions WHERE file_id=? ORDER BY version DESC")
    .bind(id).fetch_all(pool).await
}
pub async fn version(
  pool: &SqlitePool,
  project_id: &str,
  id: &str,
  version: i64,
) -> Result<Option<VaultFileRow>, sqlx::Error> {
  sqlx::query_as("SELECT f.id,f.folder_id,f.environment_id,f.name,f.kind,v.version,v.ciphertext,v.value_nonce,v.wrapped_key,v.key_nonce,v.created_at,v.updated_at,v.encoding FROM vault_file_versions v JOIN vault_files f ON f.id=v.file_id JOIN vault_folders d ON d.id=f.folder_id WHERE d.project_id=? AND v.file_id=? AND v.version=?")
    .bind(project_id).bind(id).bind(version).fetch_optional(pool).await
}

pub async fn delete_version(
  tx: &mut SqliteConnection,
  id: &str,
  version: i64,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("DELETE FROM vault_file_versions WHERE file_id=? AND version=?")
      .bind(id)
      .bind(version)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}

pub async fn delete_file(
  tx: &mut SqliteConnection,
  id: &str,
) -> Result<u64, sqlx::Error> {
  Ok(
    sqlx::query("DELETE FROM vault_files WHERE id=?")
      .bind(id)
      .execute(tx)
      .await?
      .rows_affected(),
  )
}

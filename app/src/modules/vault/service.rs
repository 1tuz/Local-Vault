use super::{
  model::*,
  repository::{self, VaultFileRow},
  validation,
};
use crate::{
  extractors::{
    require_project_access, require_project_manager, require_project_write,
    require_project_write_mutation,
  },
  http::HttpError,
  models::AuthIdentity,
  modules::common,
  state::AppState,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use std::collections::HashMap;
use ulid::Ulid;

const MAX_FILE_BYTES: usize = 1024 * 1024;

fn audit_actor(identity: &AuthIdentity) -> (&'static str, &str, Option<&str>) {
  match identity {
    AuthIdentity::Admin {
      admin_id, email, ..
    } => ("admin", admin_id, Some(email)),
    AuthIdentity::ServiceAccount {
      service_account_id,
      name,
      ..
    } => ("ai_agent", service_account_id, Some(name)),
    _ => unreachable!("project file writes require an admin or project token"),
  }
}

async fn resolve_project(
  state: &AppState,
  reference: &str,
) -> Result<String, HttpError> {
  repository::project_id(state.db.pool(), reference)
    .await?
    .ok_or_else(|| {
      HttpError::not_found("PROJECT_NOT_FOUND", "The requested project was not found.")
    })
}

pub async fn authorize_project_write(
  state: &AppState,
  identity: &AuthIdentity,
  headers: &axum::http::HeaderMap,
  project_ref: &str,
) -> Result<(), HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write_mutation(identity, headers, &project_id)
}

fn valid_name(name: &str) -> Result<String, HttpError> {
  validation::valid_name(name).map_err(|reason| {
    HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_NAME_INVALID".into(),
      reason.into(),
    )]))
  })
}

fn valid_content(content: &str) -> Result<(), HttpError> {
  if content.len() > MAX_FILE_BYTES || content.contains('\0') {
    return Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_CONTENT_INVALID".into(),
      "File content must be text, at most 1 MiB, and cannot contain NUL bytes.".into(),
    )])));
  }
  Ok(())
}

fn valid_encoding(
  encoding: &str,
  content: &str,
) -> Result<String, HttpError> {
  match encoding {
    "utf-8" => Ok(encoding.into()),
    "base64" if STANDARD.decode(content).is_ok() => Ok(encoding.into()),
    "base64" => Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_ENCODING_INVALID".into(),
      "Base64 encoded content must contain valid Base64 text.".into(),
    )]))),
    _ => Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_ENCODING_INVALID".into(),
      "File encoding must be utf-8 or base64.".into(),
    )]))),
  }
}

fn db_error(error: sqlx::Error) -> HttpError {
  if matches!(&error, sqlx::Error::Database(_)) {
    HttpError::conflict(
      "VAULT_NAME_CONFLICT",
      "A folder or file with this name already exists here.",
    )
  } else {
    HttpError::from(error)
  }
}

pub async fn list_folders(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
) -> Result<Vec<VaultFolder>, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_access(identity, &project_id)?;
  let folders = repository::folders(state.db.pool(), &project_id)
    .await
    .map_err(HttpError::from)?;
  Ok(
    folders
      .into_iter()
      .filter(|folder| !folder.is_root)
      .collect(),
  )
}

pub async fn tree(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
) -> Result<Vec<VaultFolderContents>, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_access(identity, &project_id)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  repository::ensure_project_root(
    &mut tx,
    &project_id,
    &Ulid::new().to_string(),
    &Utc::now().to_rfc3339(),
  )
  .await?;
  tx.commit().await?;
  let mut folders = repository::folders(state.db.pool(), &project_id).await?;
  for folder in &mut folders {
    if folder.is_root {
      folder.name = "Project root".into();
    }
  }
  let files = repository::all_file_metadata(state.db.pool(), &project_id).await?;
  let mut by_folder = HashMap::<String, Vec<VaultFileMetadata>>::new();
  for file in files {
    by_folder
      .entry(file.folder_id.clone())
      .or_default()
      .push(file);
  }
  Ok(
    folders
      .into_iter()
      .map(|folder| VaultFolderContents {
        files: by_folder.remove(&folder.id).unwrap_or_default(),
        folder,
      })
      .collect(),
  )
}

pub async fn create_folder(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  request: CreateFolderRequest,
) -> Result<VaultFolder, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  let name = valid_name(&request.name)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let root_id = repository::ensure_project_root(
    &mut tx,
    &project_id,
    &Ulid::new().to_string(),
    &Utc::now().to_rfc3339(),
  )
  .await?;
  let parent_id = request.parent_id.as_deref().unwrap_or(&root_id);
  if let Some(parent) = Some(parent_id) {
    repository::folder_tx(&mut tx, &project_id, parent)
      .await?
      .ok_or_else(|| {
        HttpError::not_found("VAULT_FOLDER_NOT_FOUND", "The parent folder was not found.")
      })?;
  }
  if let Some(environment_id) = request.environment_id.as_deref() {
    validate_project_environment(&mut tx, &project_id, environment_id).await?;
  }
  let id = Ulid::new().to_string();
  let now = Utc::now().to_rfc3339();
  repository::insert_folder(
    &mut tx,
    &id,
    &project_id,
    Some(parent_id),
    request.environment_id.as_deref(),
    &name,
    &now,
  )
  .await
  .map_err(db_error)?;
  let (actor_type, actor_id, actor_label) = audit_actor(identity);
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    "vault.folder.created",
    Some(&project_id),
    None,
    Some("vault_folder"),
    Some(&id),
    serde_json::json!({"name":name,"parentId":request.parent_id}),
  )
  .await?;
  tx.commit().await?;
  Ok(VaultFolder {
    id,
    project_id,
    parent_id: Some(parent_id.to_owned()),
    environment_id: request.environment_id,
    is_root: false,
    name,
    created_at: now.clone(),
    updated_at: now,
  })
}

pub async fn move_folder(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  request: MoveFolderRequest,
) -> Result<VaultFolder, HttpError> {
  let (admin_id, email) = require_project_manager(identity)?;
  let project_id = resolve_project(state, project_ref).await?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let mut folder = repository::folder_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FOLDER_NOT_FOUND", "The folder was not found."))?;
  if folder.is_root {
    return Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_ROOT_IMMUTABLE".into(),
      "The project root cannot be moved or renamed.".into(),
    )])));
  }
  let root_id = repository::ensure_project_root(
    &mut tx,
    &project_id,
    &Ulid::new().to_string(),
    &Utc::now().to_rfc3339(),
  )
  .await?;
  let parent_id = request.parent_id.as_deref().unwrap_or(&root_id);
  let name = valid_name(&request.name)?;
  if parent_id == id {
    return Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_FOLDER_CYCLE".into(),
      "A folder cannot contain itself.".into(),
    )])));
  }
  if let Some(parent) = Some(parent_id) {
    repository::folder_tx(&mut tx, &project_id, parent)
      .await?
      .ok_or_else(|| {
        HttpError::not_found(
          "VAULT_FOLDER_NOT_FOUND",
          "The destination folder was not found.",
        )
      })?;
    let descendants: Vec<(String,)> = sqlx::query_as("WITH RECURSIVE descendants(id) AS (SELECT id FROM vault_folders WHERE parent_id=? UNION ALL SELECT f.id FROM vault_folders f JOIN descendants d ON f.parent_id=d.id) SELECT id FROM descendants")
      .bind(id).fetch_all(&mut *tx).await?;
    if descendants.iter().any(|(descendant,)| descendant == parent) {
      return Err(HttpError::validation(std::collections::BTreeMap::from([(
        "VAULT_FOLDER_CYCLE".into(),
        "A folder cannot be moved inside its own descendant.".into(),
      )])));
    }
  }
  let now = Utc::now().to_rfc3339();
  repository::move_folder(&mut tx, id, Some(parent_id), &name, &now)
    .await
    .map_err(db_error)?;
  common::audit(
    &mut *tx,
    "admin",
    Some(admin_id),
    Some(email),
    "vault.folder.moved",
    Some(&project_id),
    None,
    Some("vault_folder"),
    Some(id),
    serde_json::json!({"name":name,"parentId":parent_id}),
  )
  .await?;
  tx.commit().await?;
  folder.name = name;
  folder.parent_id = Some(parent_id.to_owned());
  folder.updated_at = now;
  Ok(folder)
}

pub async fn move_file(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  destination_folder_id: &str,
) -> Result<VaultFileMetadata, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let mut file = repository::file_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  repository::folder_tx(&mut tx, &project_id, destination_folder_id)
    .await?
    .ok_or_else(|| {
      HttpError::not_found(
        "VAULT_FOLDER_NOT_FOUND",
        "The destination folder was not found.",
      )
    })?;
  let now = Utc::now().to_rfc3339();
  repository::move_file(&mut tx, id, destination_folder_id, &now)
    .await
    .map_err(db_error)?;
  let (actor_type, actor_id, actor_label) = audit_actor(identity);
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    "vault.file.moved",
    Some(&project_id),
    None,
    Some("vault_file"),
    Some(id),
    serde_json::json!({"fromFolderId":file.folder_id,"toFolderId":destination_folder_id}),
  )
  .await?;
  tx.commit().await?;
  file.folder_id = destination_folder_id.to_string();
  file.updated_at = now;
  Ok(file.metadata())
}

async fn validate_project_environment(
  tx: &mut sqlx::SqliteConnection,
  project_id: &str,
  environment_id: &str,
) -> Result<(), HttpError> {
  let belongs_to_project: bool =
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM environments WHERE id=? AND project_id=?)")
      .bind(environment_id)
      .bind(project_id)
      .fetch_one(&mut *tx)
      .await?;
  if !belongs_to_project {
    return Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_ENVIRONMENT_INVALID".into(),
      "The selected environment must belong to the same project.".into(),
    )])));
  }
  Ok(())
}

pub async fn set_folder_environment(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  environment_id: Option<&str>,
) -> Result<VaultFolder, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let mut folder = repository::folder_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FOLDER_NOT_FOUND", "The folder was not found."))?;
  if folder.is_root {
    return Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_ROOT_IMMUTABLE".into(),
      "The project root cannot be assigned an environment.".into(),
    )])));
  }
  if let Some(environment_id) = environment_id {
    validate_project_environment(&mut tx, &project_id, environment_id).await?;
  }
  let now = Utc::now().to_rfc3339();
  repository::set_folder_environment(&mut tx, id, environment_id, &now).await?;
  let (actor_type, actor_id, actor_label) = audit_actor(identity);
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    "vault.folder.environment_updated",
    Some(&project_id),
    None,
    Some("vault_folder"),
    Some(id),
    serde_json::json!({"environmentId":environment_id}),
  )
  .await?;
  tx.commit().await?;
  folder.environment_id = environment_id.map(str::to_owned);
  folder.updated_at = now;
  Ok(folder)
}

pub async fn set_file_environment(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  environment_id: Option<&str>,
) -> Result<VaultFileMetadata, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let mut file = repository::file_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  if let Some(environment_id) = environment_id {
    validate_project_environment(&mut tx, &project_id, environment_id).await?;
  }
  let now = Utc::now().to_rfc3339();
  repository::set_file_environment(&mut tx, id, environment_id, &now).await?;
  let (actor_type, actor_id, actor_label) = audit_actor(identity);
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    "vault.file.environment_updated",
    Some(&project_id),
    None,
    Some("vault_file"),
    Some(id),
    serde_json::json!({"environmentId":environment_id}),
  )
  .await?;
  tx.commit().await?;
  file.environment_id = environment_id.map(str::to_owned);
  file.updated_at = now;
  Ok(file.metadata())
}

pub async fn delete_folder(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
) -> Result<(), HttpError> {
  let (admin_id, email) = require_project_manager(identity)?;
  let project_id = resolve_project(state, project_ref).await?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let folder = repository::folder_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FOLDER_NOT_FOUND", "The folder was not found."))?;
  if folder.is_root {
    return Err(HttpError::validation(std::collections::BTreeMap::from([(
      "VAULT_ROOT_IMMUTABLE".into(),
      "The project root cannot be deleted.".into(),
    )])));
  }
  if repository::has_folder_children(&mut tx, id).await? {
    return Err(HttpError::conflict(
      "VAULT_FOLDER_NOT_EMPTY",
      "Move or delete the folder contents before deleting this folder.",
    ));
  }
  repository::delete_folder(&mut tx, id).await?;
  common::audit(
    &mut *tx,
    "admin",
    Some(admin_id),
    Some(email),
    "vault.folder.deleted",
    Some(&project_id),
    None,
    Some("vault_folder"),
    Some(id),
    serde_json::json!({}),
  )
  .await?;
  tx.commit().await?;
  Ok(())
}

pub async fn list_files(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  folder_id: &str,
) -> Result<Vec<VaultFileMetadata>, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_access(identity, &project_id)?;
  repository::folder(state.db.pool(), &project_id, folder_id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FOLDER_NOT_FOUND", "The folder was not found."))?;
  Ok(repository::files(state.db.pool(), &project_id, folder_id).await?)
}

pub async fn create_file(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  folder_id: &str,
  request: CreateVaultFileRequest,
) -> Result<VaultFileMetadata, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  let name = valid_name(&request.name)?;
  valid_content(&request.content)?;
  let encoding = valid_encoding(&request.encoding, &request.content)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  repository::folder_tx(&mut tx, &project_id, folder_id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FOLDER_NOT_FOUND", "The folder was not found."))?;
  if let Some(environment_id) = request.environment_id.as_deref() {
    let belongs_to_project: bool =
      sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM environments WHERE id=? AND project_id=?)")
        .bind(environment_id)
        .bind(&project_id)
        .fetch_one(&mut *tx)
        .await?;
    if !belongs_to_project {
      return Err(HttpError::validation(std::collections::BTreeMap::from([(
        "VAULT_ENVIRONMENT_INVALID".into(),
        "The selected environment must belong to the same project.".into(),
      )])));
    }
  }
  let id = Ulid::new().to_string();
  let now = Utc::now().to_rfc3339();
  let encrypted = state
    .crypto
    .encrypt(request.content.as_bytes(), &id, "vault-file", 1)
    .map_err(|_| HttpError::internal())?;
  let row = VaultFileRow {
    id,
    folder_id: folder_id.to_string(),
    environment_id: request.environment_id,
    name,
    kind: request.kind.as_db().into(),
    encoding,
    version: 1,
    ciphertext: encrypted.ciphertext,
    value_nonce: encrypted.value_nonce,
    wrapped_key: encrypted.wrapped_key,
    key_nonce: encrypted.key_nonce,
    created_at: now.clone(),
    updated_at: now.clone(),
  };
  repository::insert_file(&mut tx, &row)
    .await
    .map_err(db_error)?;
  let (actor_type, actor_id, actor_label) = audit_actor(identity);
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    "vault.file.created",
    Some(&project_id),
    None,
    Some("vault_file"),
    Some(&row.id),
    serde_json::json!({"name":row.name,"kind":row.kind,"version":1}),
  )
  .await?;
  tx.commit().await?;
  Ok(row.metadata())
}

pub async fn file_metadata(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
) -> Result<VaultFileMetadata, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_access(identity, &project_id)?;
  repository::file(state.db.pool(), &project_id, id)
    .await?
    .map(|row| row.metadata())
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))
}

pub async fn rename_file(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  requested_name: &str,
) -> Result<VaultFileMetadata, HttpError> {
  let (admin_id, email) = require_project_manager(identity)?;
  let project_id = resolve_project(state, project_ref).await?;
  let name = valid_name(requested_name)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let mut file = repository::file_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  let now = Utc::now().to_rfc3339();
  repository::rename_file(&mut tx, id, &name, &now)
    .await
    .map_err(db_error)?;
  common::audit(
    &mut *tx,
    "admin",
    Some(admin_id),
    Some(email),
    "vault.file.renamed",
    Some(&project_id),
    None,
    Some("vault_file"),
    Some(id),
    serde_json::json!({"oldName":&file.name,"name":name}),
  )
  .await?;
  tx.commit().await?;
  file.name = name;
  file.updated_at = now;
  Ok(file.metadata())
}

pub async fn update_file(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  request: UpdateVaultFileRequest,
) -> Result<VaultFileMetadata, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  valid_content(&request.content)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let previous = repository::file_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  let encoding = valid_encoding(
    request.encoding.as_deref().unwrap_or(&previous.encoding),
    &request.content,
  )?;
  let now = Utc::now().to_rfc3339();
  repository::archive_file(&mut tx, &previous, &now).await?;
  let version = previous.version + 1;
  let encrypted = state
    .crypto
    .encrypt(request.content.as_bytes(), id, "vault-file", version)
    .map_err(|_| HttpError::internal())?;
  repository::update_file(&mut tx, id, version, &encrypted, &encoding, &now).await?;
  let (actor_type, actor_id, actor_label) = audit_actor(identity);
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    "vault.file.updated",
    Some(&project_id),
    None,
    Some("vault_file"),
    Some(id),
    serde_json::json!({"version":version}),
  )
  .await?;
  tx.commit().await?;
  let mut row = previous;
  row.version = version;
  row.encoding = encoding;
  row.updated_at = now;
  Ok(row.metadata())
}

fn decrypt(
  state: &AppState,
  row: &VaultFileRow,
) -> Result<String, HttpError> {
  let bytes = state
    .crypto
    .decrypt(&row.encrypted(), &row.id, "vault-file", row.version)
    .map_err(|error| {
      tracing::error!(%error, "vault file decryption failed");
      HttpError::internal()
    })?;
  String::from_utf8(bytes.to_vec()).map_err(|_| HttpError::internal())
}

pub async fn reveal_file(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
) -> Result<RevealedVaultFile, HttpError> {
  let (admin_id, email) = require_project_manager(identity)?;
  let project_id = resolve_project(state, project_ref).await?;
  let row = repository::file(state.db.pool(), &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  let content = decrypt(state, &row)?;
  common::audit(
    state.db.pool(),
    "admin",
    Some(admin_id),
    Some(email),
    "vault.file.revealed",
    Some(&project_id),
    None,
    Some("vault_file"),
    Some(id),
    serde_json::json!({"kind":row.kind,"version":row.version}),
  )
  .await?;
  Ok(RevealedVaultFile {
    id: row.id,
    name: row.name,
    kind: row.kind,
    encoding: row.encoding,
    content,
    version: row.version,
  })
}

pub async fn file_versions(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
) -> Result<Vec<VaultFileVersion>, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_access(identity, &project_id)?;
  repository::file(state.db.pool(), &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  Ok(repository::versions(state.db.pool(), id).await?)
}

pub async fn rollback_file(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  version: i64,
) -> Result<VaultFileMetadata, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  let row = repository::version(state.db.pool(), &project_id, id, version)
    .await?
    .ok_or_else(|| {
      HttpError::not_found("VAULT_VERSION_NOT_FOUND", "The file version was not found.")
    })?;
  let content = decrypt(state, &row)?;
  update_file(
    state,
    identity,
    project_ref,
    id,
    UpdateVaultFileRequest {
      content,
      encoding: Some(row.encoding),
    },
  )
  .await
}

pub async fn delete_file_version(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
  version: i64,
) -> Result<(), HttpError> {
  let (admin_id, email) = require_project_manager(identity)?;
  let project_id = resolve_project(state, project_ref).await?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let current = repository::file_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  if current.version == version {
    return Err(HttpError::conflict(
      "VAULT_CURRENT_VERSION",
      "The current version cannot be deleted. Delete the file from the Admin UI instead.",
    ));
  }
  if repository::delete_version(&mut tx, id, version).await? == 0 {
    return Err(HttpError::not_found(
      "VAULT_VERSION_NOT_FOUND",
      "The file version was not found.",
    ));
  }
  common::audit(
    &mut *tx,
    "admin",
    Some(admin_id),
    Some(email),
    "vault.file_version.deleted",
    Some(&project_id),
    None,
    Some("vault_file_version"),
    Some(id),
    serde_json::json!({"version":version}),
  )
  .await?;
  tx.commit().await?;
  Ok(())
}

pub async fn delete_file(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  id: &str,
) -> Result<(), HttpError> {
  let (admin_id, email) = require_project_manager(identity)?;
  let project_id = resolve_project(state, project_ref).await?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let row = repository::file_tx(&mut tx, &project_id, id)
    .await?
    .ok_or_else(|| HttpError::not_found("VAULT_FILE_NOT_FOUND", "The file was not found."))?;
  repository::delete_file(&mut tx, id).await?;
  common::audit(
    &mut *tx,
    "admin",
    Some(admin_id),
    Some(email),
    "vault.file.deleted",
    Some(&project_id),
    None,
    Some("vault_file"),
    Some(id),
    serde_json::json!({"name":row.name,"kind":row.kind,"version":row.version}),
  )
  .await?;
  tx.commit().await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::valid_name;
  use crate::modules::vault::validation::NAME_INVALID_MESSAGE;
  use axum::http::StatusCode;

  #[test]
  fn name_rule_is_the_shared_vault_validation() {
    for name in [".", "..", "Ops/Prod", "Ops\\Prod", "nul\0name", "", "  "] {
      let error = valid_name(name).expect_err("name must be rejected");
      assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
      assert_eq!(
        error.errors.get("VAULT_NAME_INVALID").map(String::as_str),
        Some(NAME_INVALID_MESSAGE),
        "name {name:?} must keep the documented code and message"
      );
    }
    assert_eq!(valid_name("  deploy.sh  ").unwrap(), "deploy.sh");
  }
}

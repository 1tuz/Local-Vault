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
const MAX_IMPORT_ENTRIES: usize = 1000;
const MAX_IMPORT_VERSIONS: usize = 1000;
/// Total revisions across every entry. Empty revisions cost no bytes, so the
/// content budget alone cannot bound the rows written by one import.
const MAX_IMPORT_TOTAL_VERSIONS: usize = 5000;
const MAX_IMPORT_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_IMPORT_FOLDER_PATH_CHARS: usize = 160;
const MAX_IMPORT_FOLDER_DEPTH: usize = 32;

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
    _ => {
      tracing::warn!("project file write reached an unexpected identity");
      ("unknown", "", None)
    }
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
  if let sqlx::Error::Database(database) = &error {
    // SQLite reports a sibling-name conflict either as
    // "UNIQUE constraint failed: vault_files.folder_id, vault_files.name" or,
    // for the expression index on folders, as
    // "UNIQUE constraint failed: index 'vault_folders_sibling_name_idx'".
    // Every other constraint (primary key, foreign key, CHECK, BUSY, ...) is
    // a real server error and must not be reported as a name conflict.
    let message = database.message();
    if database.is_unique_violation()
      && (message.contains(".name") || message.contains("vault_folders_sibling_name_idx"))
    {
      return name_conflict();
    }
  }
  HttpError::from(error)
}

fn name_conflict() -> HttpError {
  HttpError::conflict(
    "VAULT_NAME_CONFLICT",
    "A folder or file with this name already exists here.",
  )
}

fn import_invalid(message: impl Into<String>) -> HttpError {
  HttpError::new(
    axum::http::StatusCode::BAD_REQUEST,
    "VAULT_IMPORT_INVALID",
    message,
  )
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
  // Reads never provision the project root: `create_folder`, `move_folder`
  // and `import` do that inside their write transactions. A project that has
  // no root yet simply has an empty tree.
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
  apply_file_update(state, identity, &project_id, id, request, None).await
}

/// Store a new current version of a file.
///
/// `rollback_from` is the archived version whose content is being restored.
/// It only selects the audit event, so a rollback stays distinguishable from
/// an ordinary edit.
async fn apply_file_update(
  state: &AppState,
  identity: &AuthIdentity,
  project_id: &str,
  id: &str,
  request: UpdateVaultFileRequest,
  rollback_from: Option<i64>,
) -> Result<VaultFileMetadata, HttpError> {
  valid_content(&request.content)?;
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let previous = repository::file_tx(&mut tx, project_id, id)
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
  let (action, metadata) = match rollback_from {
    Some(from_version) => (
      "vault.file.rolled_back",
      serde_json::json!({"fromVersion":from_version,"toVersion":version}),
    ),
    None => ("vault.file.updated", serde_json::json!({"version":version})),
  };
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    action,
    Some(project_id),
    None,
    Some("vault_file"),
    Some(id),
    metadata,
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
  apply_file_update(
    state,
    identity,
    &project_id,
    id,
    UpdateVaultFileRequest {
      content,
      encoding: Some(row.encoding),
    },
    Some(version),
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

/// Everything an import needs, validated before the transaction opens.
struct ImportPlan {
  root_name: String,
  folders: Vec<PlannedFolder>,
  files: Vec<PlannedFile>,
  versions: usize,
}

struct PlannedFolder {
  /// Case-insensitive canonical path, used to parent nested folders.
  key: String,
  parent_key: Option<String>,
  name: String,
}

struct PlannedFile {
  name: String,
  /// `None` places the file directly in the imported root folder.
  folder_key: Option<String>,
  kind: VaultFileKind,
  versions: Vec<(String, String)>,
}

fn plan_import(request: ImportVaultRequest) -> Result<ImportPlan, HttpError> {
  let root_name = validation::valid_name(&request.folder)
    .map_err(|reason| import_invalid(format!("Import folder name is invalid: {reason}")))?;
  if request.entries.is_empty() {
    return Err(import_invalid("An import must contain at least one entry."));
  }
  if request.entries.len() > MAX_IMPORT_ENTRIES {
    return Err(import_invalid(format!(
      "An import can contain at most {MAX_IMPORT_ENTRIES} entries."
    )));
  }
  let mut folders = Vec::<PlannedFolder>::new();
  let mut folder_keys = HashMap::<String, ()>::new();
  let mut identities = HashMap::<String, ()>::new();
  let mut files = Vec::<PlannedFile>::new();
  let mut total_bytes = 0_usize;
  let mut total_versions = 0_usize;
  for entry in request.entries {
    let name = validation::valid_name(&entry.name).map_err(|reason| {
      import_invalid(format!("File name {:?} is invalid: {reason}", entry.name))
    })?;
    let segments = import_folder_segments(&entry.folder)?;
    let folder_key = (!segments.is_empty()).then(|| segments.join("/").to_lowercase());
    for depth in 1..=segments.len() {
      let key = segments[..depth].join("/").to_lowercase();
      if folder_keys.insert(key.clone(), ()).is_none() {
        folders.push(PlannedFolder {
          parent_key: (depth > 1).then(|| segments[..depth - 1].join("/").to_lowercase()),
          name: segments[depth - 1].clone(),
          key,
        });
      }
    }
    let identity = format!(
      "{}/{}",
      folder_key.clone().unwrap_or_default(),
      name.to_lowercase()
    );
    if identities.insert(identity, ()).is_some() {
      return Err(import_invalid(format!(
        "Duplicate file name {name:?} in folder {:?}.",
        segments.join("/")
      )));
    }
    if entry.versions.is_empty() {
      return Err(import_invalid(format!(
        "File {name:?} has no revisions to import."
      )));
    }
    if entry.versions.len() > MAX_IMPORT_VERSIONS {
      return Err(import_invalid(format!(
        "File {name:?} has more than {MAX_IMPORT_VERSIONS} revisions."
      )));
    }
    total_versions += entry.versions.len();
    if total_versions > MAX_IMPORT_TOTAL_VERSIONS {
      return Err(import_invalid(format!(
        "An import can contain at most {MAX_IMPORT_TOTAL_VERSIONS} revisions across all files."
      )));
    }
    let mut versions = Vec::with_capacity(entry.versions.len());
    for version in entry.versions {
      if version.content.len() > MAX_FILE_BYTES || version.content.contains('\0') {
        return Err(import_invalid(format!(
          "File {name:?} contains content that must be text of at most 1 MiB without NUL bytes."
        )));
      }
      total_bytes += version.content.len();
      if total_bytes > MAX_IMPORT_TOTAL_BYTES {
        return Err(import_invalid(format!(
          "An import can contain at most {} MiB of content.",
          MAX_IMPORT_TOTAL_BYTES / (1024 * 1024)
        )));
      }
      let encoding = valid_encoding(&version.encoding, &version.content)?;
      versions.push((encoding, version.content));
    }
    files.push(PlannedFile {
      name,
      folder_key,
      kind: entry.kind,
      versions,
    });
  }
  let versions = total_versions;
  Ok(ImportPlan {
    root_name,
    folders,
    files,
    versions,
  })
}

fn import_folder_segments(path: &str) -> Result<Vec<String>, HttpError> {
  if path.chars().count() > MAX_IMPORT_FOLDER_PATH_CHARS {
    return Err(import_invalid(format!(
      "A folder path must be at most {MAX_IMPORT_FOLDER_PATH_CHARS} characters."
    )));
  }
  let mut segments = Vec::new();
  for segment in path
    .split(['/', '\\'])
    .map(str::trim)
    .filter(|part| !part.is_empty())
  {
    let segment = validation::valid_name(segment)
      .map_err(|reason| import_invalid(format!("Folder path {path:?} is invalid: {reason}")))?;
    segments.push(segment);
    if segments.len() > MAX_IMPORT_FOLDER_DEPTH {
      return Err(import_invalid(format!(
        "A folder path can have at most {MAX_IMPORT_FOLDER_DEPTH} levels."
      )));
    }
  }
  Ok(segments)
}

async fn insert_imported_file(
  state: &AppState,
  tx: &mut sqlx::SqliteConnection,
  folder_id: &str,
  file: &PlannedFile,
  now: &str,
) -> Result<(), HttpError> {
  let Some((encoding, content)) = file.versions.first() else {
    return Err(HttpError::internal());
  };
  let id = Ulid::new().to_string();
  let encrypted = state
    .crypto
    .encrypt(content.as_bytes(), &id, "vault-file", 1)
    .map_err(|_| HttpError::internal())?;
  let mut row = VaultFileRow {
    id: id.clone(),
    folder_id: folder_id.to_string(),
    environment_id: None,
    name: file.name.clone(),
    kind: file.kind.as_db().into(),
    encoding: encoding.clone(),
    version: 1,
    ciphertext: encrypted.ciphertext,
    value_nonce: encrypted.value_nonce,
    wrapped_key: encrypted.wrapped_key,
    key_nonce: encrypted.key_nonce,
    created_at: now.to_string(),
    updated_at: now.to_string(),
  };
  repository::insert_file(tx, &row).await.map_err(db_error)?;
  for (index, (encoding, content)) in file.versions.iter().enumerate().skip(1) {
    let version = i64::try_from(index + 1).map_err(|_| HttpError::internal())?;
    repository::archive_file(tx, &row, now).await?;
    let encrypted = state
      .crypto
      .encrypt(content.as_bytes(), &id, "vault-file", version)
      .map_err(|_| HttpError::internal())?;
    repository::update_file(tx, &id, version, &encrypted, encoding, now)
      .await
      .map_err(db_error)?;
    row.version = version;
    row.encoding = encoding.clone();
    row.ciphertext = encrypted.ciphertext;
    row.value_nonce = encrypted.value_nonce;
    row.wrapped_key = encrypted.wrapped_key;
    row.key_nonce = encrypted.key_nonce;
  }
  Ok(())
}

/// Import a whole folder tree in one transaction.
///
/// The payload is validated completely before the transaction opens, so a
/// rejected import never touches the database.
pub async fn import(
  state: &AppState,
  identity: &AuthIdentity,
  project_ref: &str,
  request: ImportVaultRequest,
) -> Result<VaultImportSummary, HttpError> {
  let project_id = resolve_project(state, project_ref).await?;
  require_project_write(identity, &project_id)?;
  let plan = plan_import(request)?;
  let now = Utc::now().to_rfc3339();
  let mut tx = state.db.pool().begin_with("BEGIN IMMEDIATE").await?;
  let project_root_id =
    repository::ensure_project_root(&mut tx, &project_id, &Ulid::new().to_string(), &now).await?;
  let existing: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM vault_folders WHERE project_id=? AND parent_id=? AND name=? COLLATE NOCASE",
  )
  .bind(&project_id)
  .bind(&project_root_id)
  .bind(&plan.root_name)
  .fetch_one(&mut *tx)
  .await?;
  if existing > 0 {
    return Err(name_conflict());
  }
  let root_folder_id = Ulid::new().to_string();
  repository::insert_folder(
    &mut tx,
    &root_folder_id,
    &project_id,
    Some(&project_root_id),
    None,
    &plan.root_name,
    &now,
  )
  .await
  .map_err(db_error)?;
  let mut folder_ids = HashMap::<String, String>::new();
  for folder in &plan.folders {
    let id = Ulid::new().to_string();
    let parent_id = folder
      .parent_key
      .as_ref()
      .and_then(|key| folder_ids.get(key))
      .map_or(root_folder_id.as_str(), String::as_str);
    repository::insert_folder(
      &mut tx,
      &id,
      &project_id,
      Some(parent_id),
      None,
      &folder.name,
      &now,
    )
    .await
    .map_err(db_error)?;
    folder_ids.insert(folder.key.clone(), id);
  }
  for file in &plan.files {
    let folder_id = file
      .folder_key
      .as_ref()
      .and_then(|key| folder_ids.get(key))
      .map_or(root_folder_id.as_str(), String::as_str);
    insert_imported_file(state, &mut tx, folder_id, file, &now).await?;
  }
  let folders = plan.folders.len() + 1;
  let files = plan.files.len();
  let versions = plan.versions;
  let (actor_type, actor_id, actor_label) = audit_actor(identity);
  common::audit(
    &mut *tx,
    actor_type,
    Some(actor_id),
    actor_label,
    "vault.import.completed",
    Some(&project_id),
    None,
    Some("vault_folder"),
    Some(&root_folder_id),
    serde_json::json!({
      "folders": folders,
      "files": files,
      "versions": versions,
      "destination": &plan.root_name,
    }),
  )
  .await?;
  tx.commit().await?;
  Ok(VaultImportSummary {
    folder_id: root_folder_id,
    folders,
    files,
    versions,
  })
}

#[cfg(test)]
mod tests {
  use super::{MAX_IMPORT_TOTAL_VERSIONS, db_error, plan_import, valid_name};
  use crate::modules::vault::{
    model::{ImportEntry, ImportVaultRequest, ImportVersion, VaultFileKind},
    validation::NAME_INVALID_MESSAGE,
  };
  use axum::http::StatusCode;
  use sqlx::Connection as _;
  use std::time::Duration;

  #[test]
  fn name_rule_is_the_shared_vault_validation() {
    for name in [
      ".",
      "..",
      "Ops/Prod",
      "Ops\\Prod",
      "nul\0name",
      "",
      "  ",
      "ansi\u{1b}[31mred",
      "tab\tname",
      "line\nbreak",
      "osc\u{1b}]0;title\u{7}name",
    ] {
      let error = valid_name(name).expect_err("name must be rejected");
      assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
      assert_eq!(
        error.errors.get("VAULT_NAME_INVALID").map(String::as_str),
        Some(NAME_INVALID_MESSAGE),
        "name {name:?} must keep the documented code and message"
      );
    }
    assert_eq!(valid_name("  deploy.sh  ").unwrap(), "deploy.sh");
    assert_eq!(valid_name("release notes.md").unwrap(), "release notes.md");
  }

  fn import_request(
    entries: usize,
    versions: usize,
  ) -> ImportVaultRequest {
    ImportVaultRequest {
      folder: "Import".into(),
      entries: (0..entries)
        .map(|index| ImportEntry {
          name: format!("file-{index}.txt"),
          folder: String::new(),
          kind: VaultFileKind::Text,
          versions: (0..versions)
            .map(|_| ImportVersion {
              encoding: "utf-8".into(),
              content: String::new(),
            })
            .collect(),
        })
        .collect(),
    }
  }

  #[test]
  fn import_revision_cap_is_enforced_before_any_work() {
    let per_file = MAX_IMPORT_TOTAL_VERSIONS / 5;
    let Ok(plan) = plan_import(import_request(5, per_file)) else {
      panic!("an import at exactly the revision cap must be accepted");
    };
    assert_eq!(plan.versions, MAX_IMPORT_TOTAL_VERSIONS);

    let Err(error) = plan_import(import_request(6, per_file)) else {
      panic!("an import above the revision cap must be rejected");
    };
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    let message = &error.errors["VAULT_IMPORT_INVALID"];
    assert!(
      message.contains(&MAX_IMPORT_TOTAL_VERSIONS.to_string()),
      "the rejection must name the limit: {message}"
    );
    assert!(message.contains("revisions"), "{message}");
  }

  #[tokio::test]
  async fn only_name_conflicts_map_to_a_conflict_response() {
    let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
      .await
      .unwrap();
    sqlx::query(
      "CREATE TABLE vault_folders(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, parent_id TEXT, name TEXT NOT NULL)",
    )
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::query(
      "CREATE UNIQUE INDEX vault_folders_sibling_name_idx ON vault_folders(project_id, COALESCE(parent_id,''), name COLLATE NOCASE)",
    )
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::query(
      "CREATE TABLE vault_files(id TEXT PRIMARY KEY, folder_id TEXT NOT NULL, name TEXT NOT NULL, UNIQUE(folder_id, name COLLATE NOCASE))",
    )
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::query("INSERT INTO vault_folders VALUES('f1','p',NULL,'Ops')")
      .execute(&mut connection)
      .await
      .unwrap();
    sqlx::query("INSERT INTO vault_files VALUES('a','f1','deploy.sh')")
      .execute(&mut connection)
      .await
      .unwrap();

    let folder_conflict = db_error(
      sqlx::query("INSERT INTO vault_folders VALUES('f2','p',NULL,'ops')")
        .execute(&mut connection)
        .await
        .unwrap_err(),
    );
    assert_eq!(folder_conflict.status, StatusCode::CONFLICT);
    assert!(folder_conflict.errors.contains_key("VAULT_NAME_CONFLICT"));

    let file_conflict = db_error(
      sqlx::query("INSERT INTO vault_files VALUES('b','f1','DEPLOY.SH')")
        .execute(&mut connection)
        .await
        .unwrap_err(),
    );
    assert_eq!(file_conflict.status, StatusCode::CONFLICT);
    assert!(file_conflict.errors.contains_key("VAULT_NAME_CONFLICT"));

    let primary_key = db_error(
      sqlx::query("INSERT INTO vault_files VALUES('a','f1','another.txt')")
        .execute(&mut connection)
        .await
        .unwrap_err(),
    );
    assert_eq!(
      primary_key.status,
      StatusCode::INTERNAL_SERVER_ERROR,
      "an id collision is not a name conflict"
    );
  }

  #[tokio::test]
  async fn foreign_key_and_check_violations_are_server_errors() {
    let mut connection = sqlx::SqliteConnection::connect("sqlite::memory:")
      .await
      .unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
      .execute(&mut connection)
      .await
      .unwrap();
    sqlx::query("CREATE TABLE parent(id TEXT PRIMARY KEY)")
      .execute(&mut connection)
      .await
      .unwrap();
    sqlx::query(
      "CREATE TABLE child(id TEXT PRIMARY KEY, parent_id TEXT NOT NULL REFERENCES parent(id))",
    )
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::query("CREATE TABLE checked(value INTEGER CHECK(value > 0))")
      .execute(&mut connection)
      .await
      .unwrap();

    let foreign_key = db_error(
      sqlx::query("INSERT INTO child VALUES('c','missing')")
        .execute(&mut connection)
        .await
        .unwrap_err(),
    );
    assert_eq!(foreign_key.status, StatusCode::INTERNAL_SERVER_ERROR);

    let check = db_error(
      sqlx::query("INSERT INTO checked VALUES(0)")
        .execute(&mut connection)
        .await
        .unwrap_err(),
    );
    assert_eq!(check.status, StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[tokio::test]
  async fn busy_violations_are_server_errors() {
    let directory = tempfile::TempDir::new().unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::new()
      .filename(directory.path().join("busy.db"))
      .create_if_missing(true)
      .busy_timeout(Duration::ZERO);
    let mut first = sqlx::SqliteConnection::connect_with(&options)
      .await
      .unwrap();
    let mut second = sqlx::SqliteConnection::connect_with(&options)
      .await
      .unwrap();
    sqlx::query("CREATE TABLE t(value INTEGER)")
      .execute(&mut first)
      .await
      .unwrap();
    sqlx::query("BEGIN IMMEDIATE")
      .execute(&mut first)
      .await
      .unwrap();
    let busy = sqlx::query("INSERT INTO t VALUES(1)")
      .execute(&mut second)
      .await
      .unwrap_err();
    assert!(
      busy
        .as_database_error()
        .is_some_and(|error| error.code().as_deref() == Some("5")),
      "expected SQLITE_BUSY, got {busy:?}"
    );
    assert_eq!(
      db_error(busy).status,
      StatusCode::INTERNAL_SERVER_ERROR,
      "the write lock being held is not a name conflict"
    );
  }
}

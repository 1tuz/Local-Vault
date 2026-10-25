use super::{model::*, service};
use crate::{
  extractors::{require_mutation, require_ui_mutation},
  http::{HttpError, HttpResponse, HttpResponseFormat},
  models::AuthIdentity,
  state::AppState,
};
use axum::{
  extract::{Path, State},
  http::HeaderMap,
};

#[utoipa::path(get, path = crate::constants::api::vault::FOLDERS, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), responses((status=200, description="Folder tree metadata", body=inline(HttpResponseFormat<Vec<VaultFolder>>))))]
pub async fn list_folders(
  State(state): State<AppState>,
  identity: AuthIdentity,
  Path(project_ref): Path<String>,
) -> Result<HttpResponse<Vec<VaultFolder>>, HttpError> {
  Ok(HttpResponse::ok(
    service::list_folders(&state, &identity, &project_ref).await?,
    "VAULT_FOLDERS_FETCHED",
  ))
}

/// Return the complete Vault tree and all file metadata in one request.
#[utoipa::path(get, path = crate::constants::api::vault::TREE, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), responses((status=200, description="Vault folders and file metadata", body=inline(HttpResponseFormat<Vec<VaultFolderContents>>))))]
pub async fn tree(
  State(state): State<AppState>,
  identity: AuthIdentity,
  Path(project_ref): Path<String>,
) -> Result<HttpResponse<Vec<VaultFolderContents>>, HttpError> {
  Ok(HttpResponse::ok(
    service::tree(&state, &identity, &project_ref).await?,
    "VAULT_TREE_FETCHED",
  ))
}

#[utoipa::path(post, path = crate::constants::api::vault::FOLDERS, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), request_body=CreateFolderRequest, responses((status=201, description="Folder created", body=inline(HttpResponseFormat<VaultFolder>))))]
pub async fn create_folder(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path(project_ref): Path<String>,
  axum::Json(request): axum::Json<CreateFolderRequest>,
) -> Result<HttpResponse<VaultFolder>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::created(
    service::create_folder(&state, &identity, &project_ref, request).await?,
    "VAULT_FOLDER_CREATED",
  ))
}

#[utoipa::path(put, path = crate::constants::api::vault::FOLDER, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), request_body=MoveFolderRequest, responses((status=200, description="Folder moved or renamed", body=inline(HttpResponseFormat<VaultFolder>))))]
pub async fn move_folder(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
  axum::Json(request): axum::Json<MoveFolderRequest>,
) -> Result<HttpResponse<VaultFolder>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::ok(
    service::move_folder(&state, &identity, &project_ref, &id, request).await?,
    "VAULT_FOLDER_UPDATED",
  ))
}

#[utoipa::path(put, path = crate::constants::api::vault::FOLDER_ENVIRONMENT, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), request_body=UpdateEnvironmentTagRequest, responses((status=200, description="Folder environment tag updated", body=inline(HttpResponseFormat<VaultFolder>))))]
pub async fn set_folder_environment(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
  axum::Json(request): axum::Json<UpdateEnvironmentTagRequest>,
) -> Result<HttpResponse<VaultFolder>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::ok(
    service::set_folder_environment(
      &state,
      &identity,
      &project_ref,
      &id,
      request.environment_id.as_deref(),
    )
    .await?,
    "VAULT_FOLDER_ENVIRONMENT_UPDATED",
  ))
}

#[utoipa::path(delete, path = crate::constants::api::vault::FOLDER, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), responses((status=200, description="Empty folder deleted", body=inline(HttpResponseFormat<serde_json::Value>))))]
pub async fn delete_folder(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
) -> Result<HttpResponse<serde_json::Value>, HttpError> {
  require_ui_mutation(&identity, &headers)?;
  service::delete_folder(&state, &identity, &project_ref, &id).await?;
  Ok(HttpResponse::done("VAULT_FOLDER_DELETED"))
}

#[utoipa::path(get, path = crate::constants::api::vault::FILES, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), responses((status=200, description="File metadata in folder", body=inline(HttpResponseFormat<Vec<VaultFileMetadata>>))))]
pub async fn list_files(
  State(state): State<AppState>,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
) -> Result<HttpResponse<Vec<VaultFileMetadata>>, HttpError> {
  Ok(HttpResponse::ok(
    service::list_files(&state, &identity, &project_ref, &id).await?,
    "VAULT_FILES_FETCHED",
  ))
}

#[utoipa::path(post, path = crate::constants::api::vault::FILES, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), request_body=CreateVaultFileRequest, responses((status=201, description="Encrypted file created", body=inline(HttpResponseFormat<VaultFileMetadata>))))]
pub async fn create_file(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
  axum::Json(request): axum::Json<CreateVaultFileRequest>,
) -> Result<HttpResponse<VaultFileMetadata>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::created(
    service::create_file(&state, &identity, &project_ref, &id, request).await?,
    "VAULT_FILE_CREATED",
  ))
}

#[utoipa::path(get, path = crate::constants::api::vault::FILE, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), responses((status=200, description="File metadata; content remains encrypted", body=inline(HttpResponseFormat<VaultFileMetadata>))))]
pub async fn file_metadata(
  State(state): State<AppState>,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
) -> Result<HttpResponse<VaultFileMetadata>, HttpError> {
  Ok(HttpResponse::ok(
    service::file_metadata(&state, &identity, &project_ref, &id).await?,
    "VAULT_FILE_FETCHED",
  ))
}

#[utoipa::path(put, path = crate::constants::api::vault::FILE, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), request_body=UpdateVaultFileRequest, responses((status=200, description="New encrypted file version saved", body=inline(HttpResponseFormat<VaultFileMetadata>))))]
pub async fn update_file(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
  axum::Json(request): axum::Json<UpdateVaultFileRequest>,
) -> Result<HttpResponse<VaultFileMetadata>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::ok(
    service::update_file(&state, &identity, &project_ref, &id, request).await?,
    "VAULT_FILE_UPDATED",
  ))
}

#[utoipa::path(put, path = crate::constants::api::vault::FILE_NAME, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), request_body=RenameVaultFileRequest, responses((status=200, description="Encrypted file renamed without changing its contents or versions", body=inline(HttpResponseFormat<VaultFileMetadata>))))]
pub async fn rename_file(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
  axum::Json(request): axum::Json<RenameVaultFileRequest>,
) -> Result<HttpResponse<VaultFileMetadata>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::ok(
    service::rename_file(&state, &identity, &project_ref, &id, &request.name).await?,
    "VAULT_FILE_RENAMED",
  ))
}

#[utoipa::path(post, path = crate::constants::api::vault::FILE_MOVE, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), request_body=MoveVaultFileRequest, responses((status=200, description="File moved to another folder in the project", body=inline(HttpResponseFormat<VaultFileMetadata>))))]
pub async fn move_file(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
  axum::Json(request): axum::Json<MoveVaultFileRequest>,
) -> Result<HttpResponse<VaultFileMetadata>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::ok(
    service::move_file(&state, &identity, &project_ref, &id, &request.folder_id).await?,
    "VAULT_FILE_MOVED",
  ))
}

#[utoipa::path(put, path = crate::constants::api::vault::FILE_ENVIRONMENT, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), request_body=UpdateEnvironmentTagRequest, responses((status=200, description="File environment tag updated", body=inline(HttpResponseFormat<VaultFileMetadata>))))]
pub async fn set_file_environment(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
  axum::Json(request): axum::Json<UpdateEnvironmentTagRequest>,
) -> Result<HttpResponse<VaultFileMetadata>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::ok(
    service::set_file_environment(
      &state,
      &identity,
      &project_ref,
      &id,
      request.environment_id.as_deref(),
    )
    .await?,
    "VAULT_FILE_ENVIRONMENT_UPDATED",
  ))
}

#[utoipa::path(delete, path = crate::constants::api::vault::FILE, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), responses((status=200, description="File deleted", body=inline(HttpResponseFormat<serde_json::Value>))))]
pub async fn delete_file(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
) -> Result<HttpResponse<serde_json::Value>, HttpError> {
  require_ui_mutation(&identity, &headers)?;
  service::delete_file(&state, &identity, &project_ref, &id).await?;
  Ok(HttpResponse::done("VAULT_FILE_DELETED"))
}

#[utoipa::path(get, path = crate::constants::api::vault::FILE_VERSIONS, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), responses((status=200, description="Version metadata without file contents", body=inline(HttpResponseFormat<Vec<VaultFileVersion>>))))]
pub async fn file_versions(
  State(state): State<AppState>,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
) -> Result<HttpResponse<Vec<VaultFileVersion>>, HttpError> {
  Ok(HttpResponse::ok(
    service::file_versions(&state, &identity, &project_ref, &id).await?,
    "VAULT_FILE_VERSIONS_FETCHED",
  ))
}

#[utoipa::path(delete, path = crate::constants::api::vault::FILE_VERSION, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path), ("version"=i64, Path)), responses((status=200, description="Archived file version deleted", body=inline(HttpResponseFormat<serde_json::Value>))))]
pub async fn delete_file_version(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id, version)): Path<(String, String, i64)>,
) -> Result<HttpResponse<serde_json::Value>, HttpError> {
  require_ui_mutation(&identity, &headers)?;
  service::delete_file_version(&state, &identity, &project_ref, &id, version).await?;
  Ok(HttpResponse::done("VAULT_FILE_VERSION_DELETED"))
}

#[utoipa::path(post, path = crate::constants::api::vault::FILE_ROLLBACK, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path), ("version"=i64, Path)), responses((status=200, description="Restored content saved as the next version", body=inline(HttpResponseFormat<VaultFileMetadata>))))]
pub async fn rollback_file(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id, version)): Path<(String, String, i64)>,
) -> Result<HttpResponse<VaultFileMetadata>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::ok(
    service::rollback_file(&state, &identity, &project_ref, &id, version).await?,
    "VAULT_FILE_ROLLED_BACK",
  ))
}

#[utoipa::path(post, path = crate::constants::api::vault::FILE_REVEAL, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), params(("id"=String, Path)), responses((status=200, description="File content returned to an authenticated project manager", body=inline(HttpResponseFormat<RevealedVaultFile>))))]
pub async fn reveal_file(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path((project_ref, id)): Path<(String, String)>,
) -> Result<HttpResponse<RevealedVaultFile>, HttpError> {
  require_mutation(&identity, &headers)?;
  Ok(HttpResponse::ok(
    service::reveal_file(&state, &identity, &project_ref, &id).await?,
    "VAULT_FILE_REVEALED",
  ))
}

/// Import a whole Local Vault hierarchy in one atomic request.
#[utoipa::path(post, path = crate::constants::api::vault::IMPORT, tag = "project files", security(("bearerAuth" = []), ("cookieAuth" = [])), request_body=ImportVaultRequest, responses((status=201, description="Folder tree imported atomically", body=inline(HttpResponseFormat<VaultImportSummary>)), (status=400, description="The import payload is invalid"), (status=409, description="The destination folder already exists")))]
pub async fn import(
  State(state): State<AppState>,
  headers: HeaderMap,
  identity: AuthIdentity,
  Path(project_ref): Path<String>,
  axum::Json(request): axum::Json<ImportVaultRequest>,
) -> Result<HttpResponse<VaultImportSummary>, HttpError> {
  service::authorize_project_write(&state, &identity, &headers, &project_ref).await?;
  Ok(HttpResponse::created(
    service::import(&state, &identity, &project_ref, request).await?,
    "VAULT_IMPORT_COMPLETED",
  ))
}

use super::{controller, model::*};
use crate::http::{ErrorBody, HttpResponseFormat};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
  paths(
    controller::tree, controller::list_folders, controller::create_folder, controller::move_folder,
    controller::delete_folder, controller::set_folder_environment, controller::set_file_environment, controller::list_files, controller::create_file,
    controller::file_metadata, controller::update_file, controller::rename_file, controller::move_file, controller::delete_file,
    controller::file_versions, controller::delete_file_version, controller::rollback_file, controller::reveal_file
  ),
  components(schemas(
    VaultFolder, VaultFolderContents, VaultFileKind, VaultFileMetadata, VaultFileVersion, CreateFolderRequest,
    MoveFolderRequest, MoveVaultFileRequest, RenameVaultFileRequest, CreateVaultFileRequest, UpdateVaultFileRequest, UpdateEnvironmentTagRequest, RevealedVaultFile,
    ErrorBody, HttpResponseFormat<Vec<VaultFolder>>, HttpResponseFormat<Vec<VaultFolderContents>>,
    HttpResponseFormat<VaultFolder>, HttpResponseFormat<Vec<VaultFileMetadata>>,
    HttpResponseFormat<VaultFileMetadata>, HttpResponseFormat<VaultFileVersion>,
    HttpResponseFormat<Vec<VaultFileVersion>>, HttpResponseFormat<RevealedVaultFile>,
    HttpResponseFormat<serde_json::Value>
  )),
  tags((name="vault"))
)]
struct VaultApi;

pub fn build() -> utoipa::openapi::OpenApi {
  VaultApi::openapi()
}

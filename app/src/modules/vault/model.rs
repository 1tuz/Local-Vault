use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultFolder {
  pub id: String,
  pub project_id: String,
  pub parent_id: Option<String>,
  pub environment_id: Option<String>,
  pub is_root: bool,
  pub name: String,
  pub created_at: String,
  pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultFolderContents {
  pub folder: VaultFolder,
  pub files: Vec<VaultFileMetadata>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum VaultFileKind {
  Secret,
  Env,
  Kubeconfig,
  SshPrivateKey,
  Certificate,
  Text,
}

impl VaultFileKind {
  pub fn as_db(self) -> &'static str {
    match self {
      Self::Secret => "secret",
      Self::Env => "env",
      Self::Kubeconfig => "kubeconfig",
      Self::SshPrivateKey => "sshPrivateKey",
      Self::Certificate => "certificate",
      Self::Text => "text",
    }
  }
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultFileMetadata {
  pub id: String,
  pub folder_id: String,
  pub environment_id: Option<String>,
  pub name: String,
  pub kind: String,
  pub encoding: String,
  pub version: i64,
  pub created_at: String,
  pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultFileVersion {
  pub version: i64,
  pub encoding: String,
  pub created_at: String,
  pub updated_at: String,
  pub archived_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateFolderRequest {
  pub name: String,
  #[serde(default)]
  pub parent_id: Option<String>,
  #[serde(default)]
  pub environment_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEnvironmentTagRequest {
  #[serde(default)]
  pub environment_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MoveFolderRequest {
  #[serde(default)]
  pub parent_id: Option<String>,
  pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MoveVaultFileRequest {
  pub folder_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RenameVaultFileRequest {
  pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultFileRequest {
  pub name: String,
  pub kind: VaultFileKind,
  pub content: String,
  #[serde(default = "default_encoding")]
  pub encoding: String,
  #[serde(default)]
  pub environment_id: Option<String>,
}

fn default_encoding() -> String {
  "utf-8".into()
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVaultFileRequest {
  pub content: String,
  #[serde(default)]
  pub encoding: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RevealedVaultFile {
  pub id: String,
  pub name: String,
  pub kind: String,
  pub encoding: String,
  pub content: String,
  pub version: i64,
}

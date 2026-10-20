use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentTokenAccess {
  #[default]
  Metadata,
  Project,
  Environment,
}

/// Service account (AI agent) representation.
#[derive(Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountResponse {
  /// Unique service account identifier with `aia_` prefix.
  pub id: String,
  /// Service account name.
  pub name: String,
  /// Account role (`ai_agent`).
  pub role: &'static str,
  /// ISO 8601 creation timestamp.
  pub created_at: String,
  /// ISO 8601 last update timestamp.
  pub updated_at: String,
}

/// Agent bearer token metadata.
#[derive(Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenResponse {
  /// Unique token identifier with `ait_` prefix.
  pub id: String,
  /// Associated service account identifier (`aia_...`).
  pub service_account_id: String,
  /// Human-readable token name or label.
  pub name: String,
  /// Granted operation profile.
  pub access: AgentTokenAccess,
  /// Environment id for scoped automation tokens.
  pub environment_id: Option<String>,
  /// Project id for project-scoped automation tokens.
  pub project_id: Option<String>,
  /// ISO 8601 creation timestamp.
  pub created_at: String,
  /// Optional ISO 8601 expiration timestamp.
  pub expires_at: Option<String>,
  /// Optional ISO 8601 timestamp of last token usage.
  pub last_used_at: Option<String>,
  /// Optional ISO 8601 revocation timestamp if revoked.
  pub revoked_at: Option<String>,
}

/// Newly created agent token containing the plaintext secret.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreatedAgentTokenResponse {
  /// Metadata for the generated token.
  pub token: AgentTokenResponse,
  /// Plaintext bearer token secret; the UI labels its scope as global, project, or environment access.
  pub plaintext_token: String,
}

/// Request to create a new service account.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateServiceAccountRequest {
  /// Unique name for the service account (2 to 100 characters).
  pub name: String,
}

/// Request to create a new agent bearer token.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateAgentTokenRequest {
  /// Name or label for the token.
  pub name: String,
  /// Optional ISO 8601 expiration timestamp (within 3 years). Defaults to 30 days.
  pub expires_at: Option<String>,
  /// Relative expiry such as 12h, 7d, or never. Cannot be combined with expiresAt.
  pub expires_in: Option<String>,
  /// Metadata-only (default) or scoped environment use and secret version writes.
  #[serde(default)]
  pub access: AgentTokenAccess,
  /// Required when access is `environment`.
  pub environment_id: Option<String>,
  /// Required when access is `project`.
  pub project_id: Option<String>,
}

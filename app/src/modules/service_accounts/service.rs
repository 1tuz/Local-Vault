use super::model::*;
use crate::{
  constants::tokens::{AGENT_TOKEN_ID_PREFIX, AGENT_TOKEN_PREFIX},
  extractors::{require_admin_browser, require_mutation, require_recent_browser_auth},
  http::HttpError,
  models::AuthIdentity,
  modules::common,
  services::token,
  state::AppState,
};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};

fn actor(identity: &AuthIdentity) -> (&str, &str) {
  match identity {
    AuthIdentity::Admin {
      admin_id, email, ..
    } => (admin_id, email),
    _ => ("", ""),
  }
}
fn validate_name(name: &str) -> Result<String, HttpError> {
  let value = name.trim();
  if value.len() < 2 || value.len() > 100 {
    return Err(HttpError::validation(std::collections::BTreeMap::from([(
      "NAME_INVALID".into(),
      "Names must contain between 2 and 100 characters.".into(),
    )])));
  }
  Ok(value.to_owned())
}
fn parse_expiry(
  expires_at: Option<String>,
  expires_in: Option<String>,
  now: DateTime<Utc>,
) -> Result<Option<String>, HttpError> {
  if expires_at.is_some() && expires_in.is_some() {
    return Err(HttpError::bad_request(
      "EXPIRY_INVALID",
      "Choose expiresAt or expiresIn, not both.",
    ));
  }
  if let Some(value) = expires_in {
    return token::expiry_duration(&value)
      .map_err(|message| HttpError::bad_request("EXPIRY_INVALID", message))
      .map(|duration| duration.map(|duration| (now + duration).to_rfc3339()));
  }
  let Some(value) = expires_at else {
    return Ok(Some((now + Duration::days(30)).to_rfc3339()));
  };
  let parsed = DateTime::parse_from_rfc3339(value.trim())
    .map_err(|_| {
      HttpError::bad_request("EXPIRY_INVALID", "expiresAt must be an RFC3339 timestamp.")
    })?
    .with_timezone(&Utc);
  if parsed <= now || parsed > now + Duration::days(token::MAX_EXPIRY_DAYS) {
    return Err(HttpError::bad_request(
      "EXPIRY_INVALID",
      "Agent tokens must expire within 3 years.",
    ));
  }
  Ok(Some(parsed.to_rfc3339()))
}
async fn account(
  state: &AppState,
  id: &str,
) -> Result<ServiceAccountResponse, HttpError> {
  sqlx::query_as::<_, (String, String, String, String, String)>(
    "SELECT id,name,role,created_at,updated_at FROM service_accounts WHERE id=?",
  )
  .bind(id)
  .fetch_optional(state.db.pool())
  .await?
  .map(
    |(id, name, _role, created_at, updated_at)| ServiceAccountResponse {
      id,
      name,
      role: "ai_agent",
      created_at,
      updated_at,
    },
  )
  .ok_or_else(|| {
    HttpError::not_found(
      "SERVICE_ACCOUNT_NOT_FOUND",
      "The service account was not found.",
    )
  })
}
type AgentTokenRow = (
  String,
  String,
  String,
  String,
  Option<String>,
  Option<String>,
  Option<String>,
  Option<String>,
  Option<String>,
);

fn map_token(row: AgentTokenRow) -> AgentTokenResponse {
  let (id, account, name, created, expires, last, revoked, environment_id, project_id) = row;
  AgentTokenResponse {
    id,
    service_account_id: account,
    name,
    access: if project_id.is_some() {
      AgentTokenAccess::Project
    } else if environment_id.is_some() {
      AgentTokenAccess::Environment
    } else {
      AgentTokenAccess::Metadata
    },
    environment_id,
    project_id,
    created_at: created,
    expires_at: expires,
    last_used_at: last,
    revoked_at: revoked,
  }
}
pub async fn list(
  state: &AppState,
  identity: &AuthIdentity,
) -> Result<Vec<ServiceAccountResponse>, HttpError> {
  require_admin_browser(identity)?;
  let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
    "SELECT id,name,role,created_at,updated_at FROM service_accounts ORDER BY name",
  )
  .fetch_all(state.db.pool())
  .await?;
  rows
    .into_iter()
    .map(|(id, name, _role, created, updated)| {
      Ok(ServiceAccountResponse {
        id,
        name,
        role: "ai_agent",
        created_at: created,
        updated_at: updated,
      })
    })
    .collect()
}
pub async fn get(
  state: &AppState,
  identity: &AuthIdentity,
  id: &str,
) -> Result<ServiceAccountResponse, HttpError> {
  require_admin_browser(identity)?;
  account(state, id).await
}
pub async fn create(
  state: &AppState,
  identity: &AuthIdentity,
  headers: &HeaderMap,
  request: CreateServiceAccountRequest,
) -> Result<ServiceAccountResponse, HttpError> {
  require_mutation(identity, headers)?;
  require_recent_browser_auth(identity)?;
  require_admin_browser(identity)?;
  let name = validate_name(&request.name)?;
  let id = token::public_id("aia_");
  let now = Utc::now().to_rfc3339();
  let mut tx = state.db.pool().begin().await?;
  if let Err(error) = sqlx::query(
    "INSERT INTO service_accounts(id,name,role,created_at,updated_at) VALUES(?,?, 'ai_agent', ?,?)",
  )
  .bind(&id)
  .bind(&name)
  .bind(&now)
  .bind(&now)
  .execute(&mut *tx)
  .await
  {
    if error.to_string().contains("UNIQUE") {
      return Err(HttpError::conflict(
        "SERVICE_ACCOUNT_EXISTS",
        "A service account with this name already exists.",
      ));
    }
    return Err(error.into());
  }
  let (aid, email) = actor(identity);
  common::audit(
    &mut *tx,
    "admin",
    Some(aid),
    Some(email),
    "service_account.created",
    None,
    None,
    Some("service_account"),
    Some(&id),
    serde_json::json!({"name":name}),
  )
  .await?;
  tx.commit().await?;
  Ok(ServiceAccountResponse {
    id,
    name,
    role: "ai_agent",
    created_at: now.clone(),
    updated_at: now,
  })
}
pub async fn delete(
  state: &AppState,
  identity: &AuthIdentity,
  headers: &HeaderMap,
  id: &str,
) -> Result<(), HttpError> {
  require_mutation(identity, headers)?;
  require_recent_browser_auth(identity)?;
  require_admin_browser(identity)?;
  let _ = account(state, id).await?;
  let (aid, email) = actor(identity);
  let mut tx = state.db.pool().begin().await?;
  sqlx::query("DELETE FROM service_accounts WHERE id=?")
    .bind(id)
    .execute(&mut *tx)
    .await?;
  common::audit(
    &mut *tx,
    "admin",
    Some(aid),
    Some(email),
    "service_account.deleted",
    None,
    None,
    Some("service_account"),
    Some(id),
    serde_json::json!({}),
  )
  .await?;
  tx.commit().await?;
  Ok(())
}
pub async fn tokens(
  state: &AppState,
  identity: &AuthIdentity,
  id: &str,
) -> Result<Vec<AgentTokenResponse>, HttpError> {
  require_admin_browser(identity)?;
  let _ = account(state, id).await?;
  let rows=sqlx::query_as::<_,AgentTokenRow>("SELECT id,service_account_id,name,created_at,expires_at,last_used_at,revoked_at,environment_id,project_id FROM agent_tokens WHERE service_account_id=? ORDER BY created_at DESC").bind(id).fetch_all(state.db.pool()).await?;
  Ok(rows.into_iter().map(map_token).collect())
}
pub async fn create_token(
  state: &AppState,
  identity: &AuthIdentity,
  headers: &HeaderMap,
  id: &str,
  request: CreateAgentTokenRequest,
) -> Result<CreatedAgentTokenResponse, HttpError> {
  require_mutation(identity, headers)?;
  require_admin_browser(identity)?;
  let _ = account(state, id).await?;
  let name = validate_name(&request.name)?;
  let (environment_id, project_id) =
    match (request.access, request.environment_id, request.project_id) {
      (AgentTokenAccess::Metadata, None, None) => (None, None),
      (AgentTokenAccess::Metadata, _, _) => {
        return Err(HttpError::bad_request(
          "TOKEN_SCOPE_INVALID",
          "Metadata-only tokens cannot have a project or environment scope.",
        ));
      }
      (AgentTokenAccess::Project, None, Some(project_id)) if !project_id.is_empty() => {
        let project = crate::modules::projects::service::show(state, &project_id).await?;
        (None, Some(project.id))
      }
      (AgentTokenAccess::Project, _, _) => {
        return Err(HttpError::bad_request(
          "TOKEN_SCOPE_INVALID",
          "Project tokens require an existing project id.",
        ));
      }
      (AgentTokenAccess::Environment, Some(environment_id), None) if !environment_id.is_empty() => {
        crate::modules::environments::service::show(state, &environment_id).await?;
        (Some(environment_id), None)
      }
      (AgentTokenAccess::Environment, _, _) => {
        return Err(HttpError::bad_request(
          "TOKEN_SCOPE_INVALID",
          "Environment tokens require an existing environment id only.",
        ));
      }
    };
  let now = Utc::now();
  let expires = parse_expiry(request.expires_at, request.expires_in, now)?;
  let token_id = token::public_id(AGENT_TOKEN_ID_PREFIX);
  let prefix = if environment_id.is_some() {
    crate::constants::tokens::ENVIRONMENT_AGENT_TOKEN_PREFIX
  } else if project_id.is_some() {
    crate::constants::tokens::PROJECT_AGENT_TOKEN_PREFIX
  } else {
    AGENT_TOKEN_PREFIX
  };
  let raw = token::generate(prefix).map_err(|_| HttpError::internal())?;
  let now = now.to_rfc3339();
  let mut tx = state.db.pool().begin().await?;
  let result=sqlx::query("INSERT INTO agent_tokens(id,service_account_id,name,token_hash,created_at,expires_at,environment_id,project_id) VALUES(?,?,?,?,?,?,?,?)").bind(&token_id).bind(id).bind(&name).bind(token::hash(&raw)).bind(&now).bind(&expires).bind(&environment_id).bind(&project_id).execute(&mut *tx).await;
  if let Err(error) = result {
    if error.to_string().contains("UNIQUE") {
      return Err(HttpError::conflict(
        "TOKEN_ALREADY_EXISTS",
        "A token with this name already exists.",
      ));
    }
    return Err(error.into());
  }
  let (aid, email) = actor(identity);
  common::audit(
    &mut *tx,
    "admin",
    Some(aid),
    Some(email),
    "service_account.token_created",
    None,
    None,
    Some("agent_token"),
    Some(&token_id),
    serde_json::json!({"serviceAccountId":id,"name":name,"access":request.access,"environmentId":environment_id,"projectId":project_id}),
  )
  .await?;
  tx.commit().await?;
  Ok(CreatedAgentTokenResponse {
    token: AgentTokenResponse {
      id: token_id,
      service_account_id: id.into(),
      name,
      access: if project_id.is_some() {
        AgentTokenAccess::Project
      } else if environment_id.is_some() {
        AgentTokenAccess::Environment
      } else {
        AgentTokenAccess::Metadata
      },
      environment_id,
      project_id,
      created_at: now,
      expires_at: expires,
      last_used_at: None,
      revoked_at: None,
    },
    plaintext_token: raw,
  })
}
pub async fn revoke_token(
  state: &AppState,
  identity: &AuthIdentity,
  headers: &HeaderMap,
  id: &str,
  token_id: &str,
) -> Result<AgentTokenResponse, HttpError> {
  require_mutation(identity, headers)?;
  require_recent_browser_auth(identity)?;
  require_admin_browser(identity)?;
  let mut tx = state.db.pool().begin().await?;
  let now = Utc::now().to_rfc3339();
  let result=sqlx::query("UPDATE agent_tokens SET revoked_at=? WHERE id=? AND service_account_id=? AND revoked_at IS NULL").bind(&now).bind(token_id).bind(id).execute(&mut *tx).await?;
  if result.rows_affected() != 1 {
    return Err(HttpError::not_found(
      "TOKEN_NOT_FOUND",
      "The active agent token was not found.",
    ));
  }
  let (aid, email) = actor(identity);
  common::audit(
    &mut *tx,
    "admin",
    Some(aid),
    Some(email),
    "service_account.token_revoked",
    None,
    None,
    Some("agent_token"),
    Some(token_id),
    serde_json::json!({}),
  )
  .await?;
  tx.commit().await?;
  let row=sqlx::query_as::<_,AgentTokenRow>("SELECT id,service_account_id,name,created_at,expires_at,last_used_at,revoked_at,environment_id,project_id FROM agent_tokens WHERE id=?").bind(token_id).fetch_one(state.db.pool()).await?;
  Ok(map_token(row))
}

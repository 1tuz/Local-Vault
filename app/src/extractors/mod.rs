use std::convert::Infallible;

use axum::{
  extract::FromRequestParts,
  http::{HeaderMap, header, request::Parts},
};
use chrono::{Duration, Utc};
use subtle::ConstantTimeEq;

use crate::{
  constants::{
    errors::{AUTHENTICATION_INVALID, AUTHORIZATION_DENIED, CSRF_REQUIRED_MESSAGE},
    limits::{CLI_SESSION_IDLE_DAYS, RECENT_AUTHENTICATION_MINUTES},
  },
  http::HttpError,
  models::{AdminRole, AuthIdentity, SessionKind},
  services::token,
  state::AppState,
};

#[derive(sqlx::FromRow)]
struct SessionRow {
  session_id: String,
  admin_id: String,
  email: String,
  role: String,
  kind: String,
  csrf_hash: Option<Vec<u8>>,
  created_at: String,
  idle_expires_at: String,
  absolute_expires_at: String,
}

#[derive(sqlx::FromRow)]
struct AgentTokenRow {
  token_id: String,
  service_account_id: String,
  name: String,
  environment_id: Option<String>,
  project_id: Option<String>,
}

fn parse_role(value: &str) -> Result<AdminRole, HttpError> {
  match value {
    "root" => Ok(AdminRole::Root),
    "admin" => Ok(AdminRole::Admin),
    "member" => Ok(AdminRole::Member),
    "ai_agent" => Ok(AdminRole::AiAgent),
    _ => Err(HttpError::unauthorized(
      AUTHENTICATION_INVALID,
      "The account role is invalid.",
    )),
  }
}

impl FromRequestParts<AppState> for AuthIdentity {
  type Rejection = HttpError;

  async fn from_request_parts(
    parts: &mut Parts,
    state: &AppState,
  ) -> Result<Self, Self::Rejection> {
    let (raw_token, cookie_auth) = credential(&parts.headers).ok_or_else(|| {
      HttpError::unauthorized("AUTHENTICATION_REQUIRED", "Please log in to continue.")
    })?;
    let hash = token::hash(&raw_token);
    let now = Utc::now();

    let session: Option<SessionRow> = sqlx::query_as(
            "SELECT s.id AS session_id, a.id AS admin_id, a.email, a.role, s.kind, s.csrf_hash, s.created_at, s.idle_expires_at, s.absolute_expires_at FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ? AND s.revoked_at IS NULL",
        ).bind(&hash).fetch_optional(state.db.pool()).await.map_err(HttpError::from)?;
    if let Some(session) = session {
      let created_at = chrono::DateTime::parse_from_rfc3339(&session.created_at)
        .map_err(|_| HttpError::internal())?
        .with_timezone(&Utc);
      let idle = chrono::DateTime::parse_from_rfc3339(&session.idle_expires_at)
        .map_err(|_| HttpError::internal())?
        .with_timezone(&Utc);
      let absolute = chrono::DateTime::parse_from_rfc3339(&session.absolute_expires_at)
        .map_err(|_| HttpError::internal())?
        .with_timezone(&Utc);
      let session_kind = if session.kind == "browser" {
        SessionKind::Browser
      } else {
        SessionKind::Cli
      };
      if session_kind == SessionKind::Cli && (now >= idle || now >= absolute) {
        return Err(HttpError::unauthorized(
          AUTHENTICATION_INVALID,
          "Your session has expired.",
        ));
      }
      let recent: String = sqlx::query_scalar("SELECT recent_auth_at FROM sessions WHERE id = ?")
        .bind(&session.session_id)
        .fetch_one(state.db.pool())
        .await
        .map_err(HttpError::from)?;
      let recent_auth_at = chrono::DateTime::parse_from_rfc3339(&recent)
        .map_err(|_| HttpError::internal())?
        .with_timezone(&Utc);
      if cookie_auth && session_kind != SessionKind::Browser {
        return Err(HttpError::unauthorized(
          AUTHENTICATION_INVALID,
          "The session type is invalid.",
        ));
      }
      if session_kind == SessionKind::Browser {
        sqlx::query("UPDATE sessions SET last_used_at = ? WHERE id = ?")
          .bind(now.to_rfc3339())
          .bind(&session.session_id)
          .execute(state.db.pool())
          .await
          .map_err(HttpError::from)?;
      } else {
        let next_idle = now + Duration::days(CLI_SESSION_IDLE_DAYS);
        sqlx::query("UPDATE sessions SET last_used_at = ?, idle_expires_at = MIN(?, absolute_expires_at) WHERE id = ?")
          .bind(now.to_rfc3339())
          .bind(next_idle.to_rfc3339())
          .bind(&session.session_id)
          .execute(state.db.pool())
          .await
          .map_err(HttpError::from)?;
      }
      return Ok(AuthIdentity::Admin {
        admin_id: session.admin_id,
        email: session.email,
        role: parse_role(&session.role)?,
        session_id: session.session_id,
        kind: session_kind,
        recent_auth_at,
        created_at,
        csrf_hash: session.csrf_hash,
      });
    }

    let agent: Option<AgentTokenRow> = sqlx::query_as(
      "SELECT t.id AS token_id, a.id AS service_account_id, a.name, t.environment_id, t.project_id FROM agent_tokens t JOIN service_accounts a ON a.id=t.service_account_id WHERE t.token_hash=? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>?)",
    )
    .bind(&hash)
    .bind(now.to_rfc3339())
    .fetch_optional(state.db.pool())
    .await
    .map_err(HttpError::from)?;
    if let Some(AgentTokenRow {
      token_id,
      service_account_id,
      name,
      environment_id,
      project_id,
    }) = agent
    {
      sqlx::query("UPDATE agent_tokens SET last_used_at=? WHERE id=?")
        .bind(now.to_rfc3339())
        .bind(&token_id)
        .execute(state.db.pool())
        .await
        .map_err(HttpError::from)?;
      return Ok(AuthIdentity::ServiceAccount {
        service_account_id,
        name,
        token_id,
        environment_id,
        project_id,
      });
    }

    let runner: Option<(String, String)> = sqlx::query_as(
      "SELECT id, environment_id FROM runner_tokens WHERE token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(&hash)
    .bind(now.to_rfc3339())
    .fetch_optional(state.db.pool())
    .await
    .map_err(HttpError::from)?;
    if let Some((token_id, environment_id)) = runner {
      sqlx::query("UPDATE runner_tokens SET last_used_at = ? WHERE id = ?")
        .bind(now.to_rfc3339())
        .bind(&token_id)
        .execute(state.db.pool())
        .await
        .map_err(HttpError::from)?;
      return Ok(AuthIdentity::Runner {
        token_id,
        environment_id,
      });
    }
    Err(HttpError::unauthorized(
      AUTHENTICATION_INVALID,
      "The provided credential is invalid.",
    ))
  }
}

fn credential(headers: &HeaderMap) -> Option<(String, bool)> {
  if let Some(value) = headers
    .get(header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    && let Some(value) = value.strip_prefix("Bearer ")
  {
    return Some((value.to_owned(), false));
  }
  let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
  cookies.split(';').map(str::trim).find_map(|cookie| {
    cookie
      .strip_prefix("dopbase_session=")
      .map(|value| (value.to_owned(), true))
  })
}

pub fn require_admin(identity: &AuthIdentity) -> Result<(&str, &str), HttpError> {
  match identity {
    AuthIdentity::Admin {
      admin_id,
      email,
      role: AdminRole::Root | AdminRole::Admin,
      ..
    } => Ok((admin_id, email)),
    _ => Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation requires an administrator.",
    )),
  }
}

pub fn require_project_manager(identity: &AuthIdentity) -> Result<(&str, &str), HttpError> {
  match identity {
    AuthIdentity::Admin {
      admin_id,
      email,
      role: AdminRole::Root | AdminRole::Admin | AdminRole::Member,
      ..
    } => Ok((admin_id, email)),
    _ => Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation requires a human project account.",
    )),
  }
}

pub fn require_read_access(identity: &AuthIdentity) -> Result<(), HttpError> {
  match identity {
    AuthIdentity::Admin { .. }
    | AuthIdentity::ServiceAccount {
      environment_id: None,
      project_id: None,
      ..
    } => Ok(()),
    AuthIdentity::Runner { .. } | AuthIdentity::ServiceAccount { .. } => Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation is not available to automation tokens.",
    )),
  }
}

pub fn require_metadata_access(identity: &AuthIdentity) -> Result<(), HttpError> {
  match identity {
    AuthIdentity::Admin { .. }
    | AuthIdentity::ServiceAccount {
      environment_id: None,
      project_id: None,
      ..
    } => Ok(()),
    _ => Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation requires an authenticated account.",
    )),
  }
}

pub fn require_project_access(
  identity: &AuthIdentity,
  project_id: &str,
) -> Result<(), HttpError> {
  match identity {
    AuthIdentity::Admin { .. }
    | AuthIdentity::ServiceAccount {
      environment_id: None,
      project_id: None,
      ..
    } => Ok(()),
    AuthIdentity::ServiceAccount {
      project_id: Some(scope),
      ..
    } if scope == project_id => Ok(()),
    _ => Err(HttpError::forbidden(
      crate::constants::errors::AUTHORIZATION_DENIED,
      "This token is not allowed to access the requested project.",
    )),
  }
}

pub fn require_project_write(
  identity: &AuthIdentity,
  project_id: &str,
) -> Result<(), HttpError> {
  match identity {
    AuthIdentity::Admin { .. } => require_project_manager(identity).map(|_| ()),
    AuthIdentity::ServiceAccount {
      project_id: Some(scope),
      ..
    } if scope == project_id => Ok(()),
    _ => Err(HttpError::forbidden(
      crate::constants::errors::AUTHORIZATION_DENIED,
      "Only a human account or token scoped to this project may write project data.",
    )),
  }
}

pub fn require_project_write_mutation(
  identity: &AuthIdentity,
  headers: &HeaderMap,
  project_id: &str,
) -> Result<(), HttpError> {
  require_project_write(identity, project_id)?;
  if matches!(identity, AuthIdentity::Admin { .. }) {
    require_mutation(identity, headers)?;
  }
  Ok(())
}

pub fn require_secret_metadata(
  identity: &AuthIdentity,
  environment_id: &str,
  project_id: &str,
) -> Result<(), HttpError> {
  match identity {
    AuthIdentity::Admin { .. }
    | AuthIdentity::ServiceAccount {
      environment_id: None,
      project_id: None,
      ..
    } => Ok(()),
    AuthIdentity::ServiceAccount {
      environment_id: Some(scope),
      project_id: None,
      ..
    } if scope == environment_id => Ok(()),
    AuthIdentity::ServiceAccount {
      environment_id: None,
      project_id: Some(scope),
      ..
    } if scope == project_id => Ok(()),
    AuthIdentity::Runner { .. } | AuthIdentity::ServiceAccount { .. } => Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This automation token is restricted to a different environment.",
    )),
  }
}

pub fn require_secret_write(
  identity: &AuthIdentity,
  environment_id: &str,
  project_id: &str,
) -> Result<(), HttpError> {
  match identity {
    AuthIdentity::Admin { .. } => require_project_manager(identity).map(|_| ()),
    AuthIdentity::ServiceAccount {
      environment_id: Some(scope),
      project_id: None,
      ..
    } if scope == environment_id => Ok(()),
    AuthIdentity::ServiceAccount {
      environment_id: None,
      project_id: Some(scope),
      ..
    } if scope == project_id => Ok(()),
    _ => Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "Only a human project account or a token scoped to this environment may write secret versions.",
    )),
  }
}

pub fn require_secret_write_mutation(
  identity: &AuthIdentity,
  headers: &HeaderMap,
  environment_id: &str,
  project_id: &str,
) -> Result<(), HttpError> {
  require_secret_write(identity, environment_id, project_id)?;
  if matches!(identity, AuthIdentity::Admin { .. }) {
    require_mutation(identity, headers)?;
  }
  Ok(())
}

pub fn require_root(identity: &AuthIdentity) -> Result<(&str, &str), HttpError> {
  match identity {
    AuthIdentity::Admin {
      admin_id,
      email,
      role: AdminRole::Root,
      ..
    } => Ok((admin_id, email)),
    _ => Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation requires the root administrator.",
    )),
  }
}

pub fn require_root_browser(identity: &AuthIdentity) -> Result<(&str, &str), HttpError> {
  let result = require_root(identity)?;
  if !matches!(
    identity,
    AuthIdentity::Admin {
      kind: SessionKind::Browser,
      ..
    }
  ) {
    return Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation is available from the Admin UI only.",
    ));
  }
  Ok(result)
}

pub fn require_admin_browser(identity: &AuthIdentity) -> Result<(&str, &str), HttpError> {
  let result = require_admin(identity)?;
  if !matches!(
    identity,
    AuthIdentity::Admin {
      kind: SessionKind::Browser,
      ..
    }
  ) {
    return Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation is available from the Admin UI only.",
    ));
  }
  Ok(result)
}

pub fn require_mutation(
  identity: &AuthIdentity,
  headers: &HeaderMap,
) -> Result<(), HttpError> {
  require_project_manager(identity)?;
  if let AuthIdentity::Admin {
    kind: SessionKind::Browser,
    csrf_hash,
    ..
  } = identity
  {
    let provided = headers
      .get("x-dopbase-csrf")
      .and_then(|value| value.to_str().ok())
      .ok_or_else(|| HttpError::forbidden(AUTHORIZATION_DENIED, CSRF_REQUIRED_MESSAGE))?;
    let expected = csrf_hash
      .as_ref()
      .ok_or_else(|| HttpError::forbidden(AUTHORIZATION_DENIED, CSRF_REQUIRED_MESSAGE))?;
    if token::hash(provided).ct_eq(expected).unwrap_u8() != 1 {
      return Err(HttpError::forbidden(
        AUTHORIZATION_DENIED,
        CSRF_REQUIRED_MESSAGE,
      ));
    }
  }
  Ok(())
}

/// Permit destructive data changes only from an authenticated Admin UI session.
/// CLI sessions and automation credentials may create or version data, but cannot delete it.
pub fn require_ui_mutation(
  identity: &AuthIdentity,
  headers: &HeaderMap,
) -> Result<(), HttpError> {
  require_mutation(identity, headers)?;
  if !matches!(
    identity,
    AuthIdentity::Admin {
      kind: SessionKind::Browser,
      ..
    }
  ) {
    return Err(HttpError::forbidden(
      AUTHORIZATION_DENIED,
      "This operation is available from the Admin UI only.",
    ));
  }
  Ok(())
}

pub fn require_recent_browser_auth(identity: &AuthIdentity) -> Result<(), HttpError> {
  if let AuthIdentity::Admin {
    kind: SessionKind::Browser,
    recent_auth_at,
    ..
  } = identity
    && Utc::now() - *recent_auth_at > Duration::minutes(RECENT_AUTHENTICATION_MINUTES)
  {
    return Err(HttpError::forbidden(
      "RECENT_AUTHENTICATION_REQUIRED",
      "Please confirm your password before continuing.",
    ));
  }
  require_project_manager(identity).map(|_| ())
}

pub struct OptionalIdentity(pub Option<AuthIdentity>);

impl FromRequestParts<AppState> for OptionalIdentity {
  type Rejection = Infallible;
  async fn from_request_parts(
    parts: &mut Parts,
    state: &AppState,
  ) -> Result<Self, Self::Rejection> {
    Ok(Self(
      AuthIdentity::from_request_parts(parts, state).await.ok(),
    ))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use chrono::Utc;

  fn admin(kind: SessionKind) -> AuthIdentity {
    AuthIdentity::Admin {
      admin_id: "admin-id".into(),
      email: "admin@example.test".into(),
      role: AdminRole::Admin,
      session_id: "session-id".into(),
      kind,
      recent_auth_at: Utc::now(),
      created_at: Utc::now(),
      csrf_hash: Some(token::hash("csrf-token")),
    }
  }

  #[test]
  fn ui_only_mutations_require_a_browser_session_and_csrf() {
    let mut headers = HeaderMap::new();
    headers.insert("x-dopbase-csrf", "csrf-token".parse().unwrap());
    assert!(require_ui_mutation(&admin(SessionKind::Browser), &headers).is_ok());
    assert!(require_ui_mutation(&admin(SessionKind::Cli), &headers).is_err());
    assert!(require_ui_mutation(&admin(SessionKind::Browser), &HeaderMap::new()).is_err());
  }
}

use app::{config::ServerConfig, server};
use axum::{
  Router,
  body::{Body, to_bytes},
  http::{Request, header},
};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn call(
  router: &Router,
  method: &str,
  path: &str,
  credential: Option<&str>,
  csrf: Option<&str>,
  body: Option<Value>,
) -> (u16, Value, axum::http::HeaderMap) {
  let mut request = Request::builder().method(method).uri(path);
  if let Some(credential) = credential {
    if credential.starts_with("Bearer ") {
      request = request.header(header::AUTHORIZATION, credential);
    } else {
      request = request.header(header::COOKIE, credential);
    }
  }
  if let Some(csrf) = csrf {
    request = request.header("x-dopbase-csrf", csrf);
  }
  if body.is_some() {
    request = request.header(header::CONTENT_TYPE, "application/json");
  }
  let response = router
    .clone()
    .oneshot(
      request
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap(),
    )
    .await
    .unwrap();
  let status = response.status().as_u16();
  let headers = response.headers().clone();
  let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  (
    status,
    serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    headers,
  )
}

#[tokio::test]
async fn environment_agent_can_use_and_version_secrets_but_cannot_delete_or_administer() {
  let directory = tempfile::TempDir::new().unwrap();
  let config = ServerConfig {
    data_dir: directory.path().to_path_buf(),
    database_url: format!("sqlite://{}", directory.path().join("dopbase.db").display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: directory.path().join("master.key"),
    },
    ..ServerConfig::default()
  };
  let state = server::build_setup_state(config).await.unwrap();
  let router = server::router(state.clone());
  let setup_token = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken":setup_token,"email":"root@example.com","password":"fixture-password-123"})),
  )
  .await;
  assert_eq!(status, 201);
  let cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_owned();
  let csrf = bootstrap["data"]["csrfToken"].as_str().unwrap().to_owned();

  let (status, project, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"agent-access-test"})),
  )
  .await;
  assert_eq!(status, 201);
  let project_id = project["data"]["id"].as_str().unwrap();
  let (status, environment, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"production"})),
  )
  .await;
  assert_eq!(status, 201);
  let environment_id = environment["data"]["id"].as_str().unwrap().to_owned();

  let (status, _, _) = call(
    &router,
    "PUT",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"value":"original-value"})),
  )
  .await;
  assert_eq!(status, 200);
  let (status, other_environment, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"staging"})),
  )
  .await;
  assert_eq!(status, 201);
  let other_environment_id = other_environment["data"]["id"].as_str().unwrap();

  let (status, account, _) = call(
    &router,
    "POST",
    "/api/v1/service-accounts",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"production-agent"})),
  )
  .await;
  assert_eq!(status, 201);
  let account_id = account["data"]["id"].as_str().unwrap();
  let (status, token, _) = call(
    &router,
    "POST",
    &format!("/api/v1/service-accounts/{account_id}/tokens"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"production-write","access":"environment","environmentId":environment_id,"expiresIn":"7d"})),
  )
  .await;
  assert_eq!(status, 201);
  let raw_token = token["data"]["plaintextToken"].as_str().unwrap();
  assert!(raw_token.starts_with("dpe_"));
  let bearer = format!("Bearer {raw_token}");

  let (status, runtime, _) = call(
    &router,
    "GET",
    &format!("/api/v1/environments/{environment_id}/secrets/runtime"),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(runtime["data"]["entries"][0]["value"], "original-value");

  let (status, updated, _) = call(
    &router,
    "PUT",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY"),
    Some(&bearer),
    None,
    Some(json!({"value":"agent-value"})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(updated["data"]["version"], 2);

  let (status, versions, _) = call(
    &router,
    "GET",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY/versions"),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(versions["data"][0]["version"], 1);
  assert!(versions["data"][0].get("ciphertext").is_none());

  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY/versions/1"),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403, "agent tokens must not delete secret versions");

  let (status, rolled_back, _) = call(
    &router,
    "POST",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY/rollback"),
    Some(&bearer),
    None,
    Some(json!({"version":1})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(rolled_back["data"]["version"], 3);

  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY/versions/1"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 200, "the Admin UI can delete an archived version");
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY/versions/3"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(
    status, 409,
    "the current version cannot be deleted directly"
  );

  let (_, cli_login, _) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    None,
    Some(json!({"email":"root@example.com","password":"fixture-password-123","sessionKind":"cli"})),
  )
  .await;
  let cli_bearer = format!("Bearer {}", cli_login["data"]["token"].as_str().unwrap());
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("/api/v1/environments/{environment_id}/secrets/API_KEY"),
    Some(&cli_bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403, "CLI sessions must not delete secrets");
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("/api/v1/projects/{project_id}"),
    Some(&cli_bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403, "CLI sessions must not delete projects");

  for (method, path, body) in [
    (
      "DELETE",
      format!("/api/v1/environments/{environment_id}/secrets/API_KEY"),
      None,
    ),
    (
      "DELETE",
      format!("/api/v1/environments/{other_environment_id}"),
      None,
    ),
    (
      "POST",
      "/api/v1/instance/factory-reset".to_owned(),
      Some(
        json!({"confirmation":"FACTORY RESET","acknowledged":true,"currentPassword":"fixture-password-123"}),
      ),
    ),
  ] {
    let (status, _, _) = call(&router, method, &path, Some(&bearer), None, body).await;
    assert_eq!(status, 403, "unexpected authorization for {method} {path}");
  }

  let (status, denied_scope, _) = call(
    &router,
    "GET",
    &format!("/api/v1/environments/{other_environment_id}/secrets/runtime"),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403);
  assert!(denied_scope["error"].is_object());
  state.db.close().await;
}

#[tokio::test]
async fn browser_admin_can_generate_agent_token_after_recent_auth_expires() {
  let directory = tempfile::TempDir::new().unwrap();
  let config = ServerConfig {
    data_dir: directory.path().to_path_buf(),
    database_url: format!("sqlite://{}", directory.path().join("dopbase.db").display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: directory.path().join("master.key"),
    },
    ..ServerConfig::default()
  };
  let state = server::build_setup_state(config).await.unwrap();
  let router = server::router(state.clone());
  let setup_token = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken":setup_token,"email":"root@example.com","password":"fixture-password-123"})),
  )
  .await;
  assert_eq!(status, 201);
  let cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_owned();
  let csrf = bootstrap["data"]["csrfToken"].as_str().unwrap();
  let (status, account, _) = call(
    &router,
    "POST",
    "/api/v1/service-accounts",
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"token-test-agent"})),
  )
  .await;
  assert_eq!(status, 201);
  let account_id = account["data"]["id"].as_str().unwrap();
  sqlx::query("UPDATE sessions SET recent_auth_at='2020-01-01T00:00:00Z'")
    .execute(state.db.pool())
    .await
    .unwrap();

  let (status, token, _) = call(
    &router,
    "POST",
    &format!("/api/v1/service-accounts/{account_id}/tokens"),
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"token-after-auth-timeout","access":"metadata","expiresIn":"30d"})),
  )
  .await;
  assert_eq!(status, 201, "{token}");
  assert!(
    token["data"]["plaintextToken"]
      .as_str()
      .unwrap()
      .starts_with("dpa_")
  );
  state.db.close().await;
}

#[tokio::test]
async fn project_agent_is_confined_to_one_project_and_can_write_without_deleting() {
  let directory = tempfile::TempDir::new().unwrap();
  let config = ServerConfig {
    data_dir: directory.path().to_path_buf(),
    database_url: format!("sqlite://{}", directory.path().join("dopbase.db").display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: directory.path().join("master.key"),
    },
    ..ServerConfig::default()
  };
  let state = server::build_setup_state(config).await.unwrap();
  let router = server::router(state.clone());
  let setup_token = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken":setup_token,"email":"root@example.com","password":"fixture-password-123"})),
  ).await;
  assert_eq!(status, 201);
  let cookie = headers
    .get(header::SET_COOKIE)
    .unwrap()
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_owned();
  let csrf = bootstrap["data"]["csrfToken"].as_str().unwrap();

  let mut project_ids = Vec::new();
  let mut environment_ids = Vec::new();
  for name in ["project-one", "project-two"] {
    let (status, project, _) = call(
      &router,
      "POST",
      "/api/v1/projects",
      Some(&cookie),
      Some(csrf),
      Some(json!({"name":name})),
    )
    .await;
    assert_eq!(status, 201);
    let project_id = project["data"]["id"].as_str().unwrap().to_owned();
    let (status, environment, _) = call(
      &router,
      "POST",
      &format!("/api/v1/projects/{project_id}/environments"),
      Some(&cookie),
      Some(csrf),
      Some(json!({"name":"production"})),
    )
    .await;
    assert_eq!(status, 201);
    project_ids.push(project_id);
    environment_ids.push(environment["data"]["id"].as_str().unwrap().to_owned());
  }
  let (status, account, _) = call(
    &router,
    "POST",
    "/api/v1/service-accounts",
    Some(&cookie),
    Some(csrf),
    Some(json!({"name":"project-agent"})),
  )
  .await;
  assert_eq!(status, 201);
  let account_id = account["data"]["id"].as_str().unwrap();
  let (status, token, _) = call(&router, "POST", &format!("/api/v1/service-accounts/{account_id}/tokens"), Some(&cookie), Some(csrf), Some(json!({"name":"project-write","access":"project","projectId":project_ids[0],"expiresIn":"7d"}))).await;
  assert_eq!(status, 201);
  let raw_token = token["data"]["plaintextToken"].as_str().unwrap();
  assert!(raw_token.starts_with("dpp_"));
  let bearer = format!("Bearer {raw_token}");

  let (status, projects, _) = call(
    &router,
    "GET",
    "/api/v1/projects",
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(projects["data"].as_array().unwrap().len(), 1);
  assert_eq!(projects["data"][0]["id"], project_ids[0]);
  let (status, _, _) = call(
    &router,
    "GET",
    &format!("/api/v1/projects/{}", project_ids[1]),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403);
  let (status, environments, _) = call(
    &router,
    "GET",
    "/api/v1/environments",
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(environments["data"].as_array().unwrap().len(), 1);

  let (status, parent, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{}/files/folders", project_ids[0]),
    Some(&bearer),
    None,
    Some(json!({"name":"parent"})),
  )
  .await;
  assert_eq!(status, 201);
  let parent_id = parent["data"]["id"].as_str().unwrap();
  let (status, child, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{}/files/folders", project_ids[0]),
    Some(&bearer),
    None,
    Some(json!({"name":"child","parentId":parent_id})),
  )
  .await;
  assert_eq!(status, 201);
  let child_id = child["data"]["id"].as_str().unwrap();
  let (status, file, _) = call(
    &router,
    "POST",
    &format!(
      "/api/v1/projects/{}/files/folders/{child_id}/files",
      project_ids[0]
    ),
    Some(&bearer),
    None,
    Some(json!({"name":"config","kind":"text","content":"v1","encoding":"utf-8"})),
  )
  .await;
  assert_eq!(status, 201);
  let file_id = file["data"]["id"].as_str().unwrap();
  let (status, updated, _) = call(
    &router,
    "PUT",
    &format!("/api/v1/projects/{}/files/{file_id}", project_ids[0]),
    Some(&bearer),
    None,
    Some(json!({"content":"v2"})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(updated["data"]["version"], 2);
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("/api/v1/projects/{}/files/{file_id}", project_ids[0]),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403);

  let (status, secret, _) = call(
    &router,
    "PUT",
    &format!(
      "/api/v1/environments/{}/secrets/API_KEY",
      environment_ids[0]
    ),
    Some(&bearer),
    None,
    Some(json!({"value":"fixture-secret"})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(secret["data"]["version"], 1);
  let (status, runtime, _) = call(
    &router,
    "GET",
    &format!(
      "/api/v1/environments/{}/secrets/runtime",
      environment_ids[0]
    ),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(runtime["data"]["entries"][0]["value"], "fixture-secret");
  let (status, _, _) = call(
    &router,
    "GET",
    &format!(
      "/api/v1/environments/{}/secrets/runtime",
      environment_ids[1]
    ),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403);
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!(
      "/api/v1/environments/{}/secrets/API_KEY",
      environment_ids[0]
    ),
    Some(&bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403);
  state.db.close().await;
}

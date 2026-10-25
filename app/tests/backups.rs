use app::modules::backups::service::{sanitize_key, sanitize_name};
use app::{config::ServerConfig, server};
use axum::{
  Router,
  body::{Body, to_bytes},
  http::{Request, header},
};
use chrono::Utc;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

async fn test_app() -> (TempDir, app::state::AppState, Router) {
  let directory = TempDir::new().unwrap();
  let database = directory.path().join("dopbase.db");
  let config = ServerConfig {
    data_dir: directory.path().to_path_buf(),
    database_url: format!("sqlite://{}", database.display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: directory.path().join("master.key"),
    },
    docs_enabled: true,
    ..ServerConfig::default()
  };
  let state = server::build_setup_state(config).await.unwrap();
  let router = server::router(state.clone());
  (directory, state, router)
}

async fn call(
  router: &Router,
  method: &str,
  path: &str,
  token: Option<&str>,
  body: Option<Value>,
) -> (u16, Value, axum::http::HeaderMap) {
  let mut builder = Request::builder().method(method).uri(path);
  if let Some(token) = token {
    builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
  }
  if body.is_some() {
    builder = builder.header(header::CONTENT_TYPE, "application/json");
  }
  let request = builder
    .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
    .unwrap();
  let response = router.clone().oneshot(request).await.unwrap();
  let status = response.status().as_u16();
  let headers = response.headers().clone();
  let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
  (status, json, headers)
}

async fn call_raw(
  router: &Router,
  method: &str,
  path: &str,
  token: Option<&str>,
) -> (u16, Vec<u8>, axum::http::HeaderMap) {
  let mut builder = Request::builder().method(method).uri(path);
  if let Some(token) = token {
    builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
  }
  let request = builder.body(Body::empty()).unwrap();
  let response = router.clone().oneshot(request).await.unwrap();
  let status = response.status().as_u16();
  let headers = response.headers().clone();
  let bytes = to_bytes(response.into_body(), usize::MAX)
    .await
    .unwrap()
    .to_vec();
  (status, bytes, headers)
}

async fn admin_setup() -> (TempDir, app::state::AppState, Router, String) {
  let (directory, state, router) = test_app().await;
  let setup = state.setup.read().await.token.clone().unwrap();
  let (status, _, _) = call(
    &router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    Some(
      json!({"setupToken": setup, "email": "admin@example.com", "password": "correct-horse-123"}),
    ),
  )
  .await;
  assert_eq!(status, 201);
  let (_, login, _) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    Some(
      json!({"email": "admin@example.com", "password": "correct-horse-123", "sessionKind": "cli"}),
    ),
  )
  .await;
  let token = login["data"]["token"].as_str().unwrap().to_owned();
  (directory, state, router, token)
}

#[tokio::test]
async fn backup_and_restore_lifecycle() {
  let (_dir, state, router, token) = admin_setup().await;

  // 1. Create a project and environment with secrets
  let (status, project, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&token),
    Some(json!({"name": "backup-test-project"})),
  )
  .await;
  assert_eq!(status, 201);
  let project_id = project["data"]["id"].as_str().unwrap();

  let (status, env, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(&token),
    Some(json!({"name": "staging"})),
  )
  .await;
  assert_eq!(status, 201);
  let env_id = env["data"]["id"].as_str().unwrap();

  let (status, _, _) = call(
    &router,
    "PUT",
    &format!("/api/v1/environments/{env_id}/secrets/API_KEY"),
    Some(&token),
    Some(json!({"value": "super-secret-key-123"})),
  )
  .await;
  assert_eq!(status, 200);

  // 2. Initialize new backup with custom name
  let (status, create_res, _) = call(
    &router,
    "POST",
    "/api/v1/backups",
    Some(&token),
    Some(json!({"name": "snapshot_v1"})),
  )
  .await;
  assert_eq!(status, 201);
  assert_eq!(create_res["data"]["key"], "snapshot_v1.dop");
  assert!(create_res["data"]["size"].as_u64().unwrap() > 0);

  // 3. List backups
  let (status, list_res, _) = call(&router, "GET", "/api/v1/backups", Some(&token), None).await;
  assert_eq!(status, 200);
  let list = list_res["data"].as_array().unwrap();
  assert_eq!(list.len(), 1);
  assert_eq!(list[0]["key"], "snapshot_v1.dop");

  // 4. Download backup
  let (status, raw_bytes, headers) = call_raw(
    &router,
    "GET",
    "/api/v1/backups/snapshot_v1.dop",
    Some(&token),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    headers.get(header::CONTENT_DISPOSITION).unwrap(),
    "attachment; filename=\"snapshot_v1.dop\""
  );
  assert!(!raw_bytes.is_empty());
  assert!(raw_bytes.starts_with(b"DOPBASE_BK1\0"));

  // 5. Test tamper resistance
  let mut tampered = raw_bytes.clone();
  let last = tampered.len() - 1;
  tampered[last] ^= 0xFF;
  // Decrypting tampered should fail
  assert!(state.crypto.decrypt_backup(&tampered).is_err());

  // 6. Modify secret and add a new secret after backup was taken
  let (status, _, _) = call(
    &router,
    "PUT",
    &format!("/api/v1/environments/{env_id}/secrets/API_KEY"),
    Some(&token),
    Some(json!({"value": "MODIFIED_KEY_VALUE"})),
  )
  .await;
  assert_eq!(status, 200);

  let (status, _, _) = call(
    &router,
    "PUT",
    &format!("/api/v1/environments/{env_id}/secrets/NEW_SECRET"),
    Some(&token),
    Some(json!({"value": "temporary"})),
  )
  .await;
  assert_eq!(status, 200);

  // 7. Restore from backup
  let (status, restore_res, _) = call(
    &router,
    "POST",
    "/api/v1/backups/snapshot_v1.dop/restore",
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(restore_res["data"]["restored"], true);

  let restored_audit_history: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE environment_id = ?")
      .bind(env_id)
      .fetch_one(state.db.pool())
      .await
      .unwrap();
  assert!(restored_audit_history > 0);

  // 8. Verify secrets are restored to their original snapshot state!
  let (status, reveal_res, _) = call(
    &router,
    "POST",
    &format!("/api/v1/environments/{env_id}/secrets/API_KEY/reveal"),
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(reveal_res["data"]["value"], "super-secret-key-123");

  // Verify NEW_SECRET is gone (restored to point-in-time)
  let (status, _, _) = call(
    &router,
    "GET",
    &format!("/api/v1/environments/{env_id}/secrets/NEW_SECRET"),
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 404);

  // 9. Delete backup
  let (status, delete_res, _) = call(
    &router,
    "DELETE",
    "/api/v1/backups/snapshot_v1.dop",
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(delete_res["data"]["deleted"], true);

  // 10. Verify list is now empty
  let (status, empty_res, _) = call(&router, "GET", "/api/v1/backups", Some(&token), None).await;
  assert_eq!(status, 200);
  assert_eq!(empty_res["data"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn backup_upload_and_tamper_rejection() {
  let (_dir, _state, router, token) = admin_setup().await;

  // 1. Create a backup
  let (status, _, _) = call(
    &router,
    "POST",
    "/api/v1/backups",
    Some(&token),
    Some(json!({"name": "upload_src"})),
  )
  .await;
  assert_eq!(status, 201);

  // 2. Download it
  let (status, raw_bytes, _) = call_raw(
    &router,
    "GET",
    "/api/v1/backups/upload_src.dop",
    Some(&token),
  )
  .await;
  assert_eq!(status, 200);

  // 3. Upload valid backup with a new filename
  let boundary = "---------------------------974767299852498929531610575";
  let mut body = Vec::new();
  body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"file\"; filename=\"uploaded_copy.dop\"\r\n",
  );
  body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  body.extend_from_slice(&raw_bytes);
  body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let req = Request::builder()
    .method("POST")
    .uri("/api/v1/backups/upload")
    .header(header::AUTHORIZATION, format!("Bearer {token}"))
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(body))
    .unwrap();

  let res = router.clone().oneshot(req).await.unwrap();
  assert_eq!(res.status().as_u16(), 201);

  // Verify it appears in list
  let (status, list_res, _) = call(&router, "GET", "/api/v1/backups", Some(&token), None).await;
  assert_eq!(status, 200);
  let keys: Vec<_> = list_res["data"]
    .as_array()
    .unwrap()
    .iter()
    .map(|item| item["key"].as_str().unwrap())
    .collect();
  assert!(keys.contains(&"uploaded_copy.dop"));

  // 4. Upload corrupted/tampered bytes -> should return 400 Bad Request
  let mut corrupted = raw_bytes.clone();
  corrupted[15] ^= 0xAA;
  let mut body_corrupt = Vec::new();
  body_corrupt.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  body_corrupt.extend_from_slice(
    b"Content-Disposition: form-data; name=\"file\"; filename=\"corrupt.dop\"\r\n",
  );
  body_corrupt.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  body_corrupt.extend_from_slice(&corrupted);
  body_corrupt.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let req_corrupt = Request::builder()
    .method("POST")
    .uri("/api/v1/backups/upload")
    .header(header::AUTHORIZATION, format!("Bearer {token}"))
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(body_corrupt))
    .unwrap();

  let res_corrupt = router.clone().oneshot(req_corrupt).await.unwrap();
  assert_eq!(res_corrupt.status().as_u16(), 400);
}

#[tokio::test]
async fn bootstrap_restore_lifecycle() {
  // 1. Create source server with admin and a secret
  let (dir1, _state1, router1, token1) = admin_setup().await;
  let (_, project_res, _) = call(
    &router1,
    "POST",
    "/api/v1/projects",
    Some(&token1),
    Some(json!({ "name": "bootstrapped-app" })),
  )
  .await;
  let project_id = project_res["data"]["id"].as_str().unwrap();

  let (_, env_res, _) = call(
    &router1,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(&token1),
    Some(json!({ "name": "production" })),
  )
  .await;
  let env_id = env_res["data"]["id"].as_str().unwrap();

  let _ = call(
    &router1,
    "POST",
    &format!("/api/v1/environments/{env_id}/secrets"),
    Some(&token1),
    Some(json!({ "key": "DATABASE_URL", "value": "postgres://prod/db" })),
  )
  .await;

  // Create backup and download raw bytes
  let (_, backup_res, _) = call(
    &router1,
    "POST",
    "/api/v1/backups",
    Some(&token1),
    Some(json!({ "name": "initial_seed" })),
  )
  .await;
  let key = backup_res["data"]["key"].as_str().unwrap();
  let (status, raw_bytes, _) = call_raw(
    &router1,
    "GET",
    &format!("/api/v1/backups/{key}"),
    Some(&token1),
  )
  .await;
  assert_eq!(status, 200);

  // 2. Create brand-new uninitialized server sharing the same master key
  let dir2 = TempDir::new().unwrap();
  let db2 = dir2.path().join("dopbase.db");
  let key_path = dir1.path().join("master.key"); // use same master key
  let config2 = ServerConfig {
    data_dir: dir2.path().to_path_buf(),
    database_url: format!("sqlite://{}", db2.display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: key_path,
    },
    docs_enabled: true,
    ..ServerConfig::default()
  };
  let state2 = server::build_setup_state(config2).await.unwrap();
  let router2 = server::router(state2.clone());
  let setup_token2 = state2.setup.read().await.token.clone().unwrap();

  // Confirm server2 is in setupRequired state
  let (status, status_res, _) = call(&router2, "GET", "/api/v1/bootstrap/status", None, None).await;
  assert_eq!(status, 200);
  assert_eq!(status_res["data"]["state"], "setupRequired");

  // 3. Post backup to /api/v1/bootstrap/restore
  let boundary = "---------------------------974767299852498929531610575";
  let mut body = Vec::new();
  body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"file\"; filename=\"initial_seed.dop\"\r\n",
  );
  body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  body.extend_from_slice(&raw_bytes);
  body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
  body.extend_from_slice(b"Content-Disposition: form-data; name=\"setup_token\"\r\n\r\n");
  body.extend_from_slice(setup_token2.as_bytes());
  body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let req = Request::builder()
    .method("POST")
    .uri("/api/v1/bootstrap/restore")
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(body))
    .unwrap();

  let res = router2.clone().oneshot(req).await.unwrap();
  assert_eq!(res.status().as_u16(), 200);

  // Confirm server2 is now ready
  let (status, status_res2, _) =
    call(&router2, "GET", "/api/v1/bootstrap/status", None, None).await;
  assert_eq!(status, 200);
  assert_eq!(status_res2["data"]["state"], "ready");

  // Sign in on server2 using the admin account restored from backup!
  let (status, login, _) = call(
    &router2,
    "POST",
    "/api/v1/auth/login",
    None,
    Some(
      json!({"email": "admin@example.com", "password": "correct-horse-123", "sessionKind": "cli"}),
    ),
  )
  .await;
  assert_eq!(status, 200);
  let token2 = login["data"]["token"].as_str().unwrap();

  // Verify restored project and secret
  let (status, projects_res, _) =
    call(&router2, "GET", "/api/v1/projects", Some(token2), None).await;
  assert_eq!(status, 200);
  let projects = projects_res["data"].as_array().unwrap();
  assert_eq!(projects.len(), 1);
  assert_eq!(projects[0]["name"], "bootstrapped-app");

  // 4. Attempting restore again on initialized server returns 409 Conflict
  let mut body_again = Vec::new();
  body_again.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  body_again.extend_from_slice(
    b"Content-Disposition: form-data; name=\"file\"; filename=\"again.dop\"\r\n",
  );
  body_again.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  body_again.extend_from_slice(&raw_bytes);
  body_again.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let req_again = Request::builder()
    .method("POST")
    .uri("/api/v1/bootstrap/restore")
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(body_again))
    .unwrap();

  let res_again = router2.clone().oneshot(req_again).await.unwrap();
  assert_eq!(res_again.status().as_u16(), 409);
}

#[tokio::test]
async fn bootstrap_restore_with_different_master_key() {
  let (dir1, _state1, router1, token1) = admin_setup().await;

  // 1. Create secret on Server 1
  let (status, project, _) = call(
    &router1,
    "POST",
    "/api/v1/projects",
    Some(&token1),
    Some(json!({"name": "cross-server-app"})),
  )
  .await;
  assert_eq!(status, 201);
  let project_id = project["data"]["id"].as_str().unwrap();

  let (status, env, _) = call(
    &router1,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(&token1),
    Some(json!({"name": "production"})),
  )
  .await;
  assert_eq!(status, 201);
  let env_id = env["data"]["id"].as_str().unwrap();

  let (status, _, _) = call(
    &router1,
    "PUT",
    &format!("/api/v1/environments/{env_id}/secrets/DATABASE_URL"),
    Some(&token1),
    Some(json!({"value": "postgres://prod:secret@db.internal:5432/main"})),
  )
  .await;
  assert_eq!(status, 200);

  // Download Server 1 backup
  let (status, backup_item, _) = call(
    &router1,
    "POST",
    "/api/v1/backups",
    Some(&token1),
    Some(json!({"name": "migration_snapshot"})),
  )
  .await;
  assert_eq!(status, 201);
  let backup_key = backup_item["data"]["key"].as_str().unwrap();

  let (status, raw_bytes, _) = call_raw(
    &router1,
    "GET",
    &format!("/api/v1/backups/{backup_key}"),
    Some(&token1),
  )
  .await;
  assert_eq!(status, 200);

  // Read Server 1 master key
  let server1_key_bytes = std::fs::read(dir1.path().join("master.key")).unwrap();

  // 2. Initialize fresh Server 2 with its OWN separate master key
  let dir2 = TempDir::new().unwrap();
  let db2 = dir2.path().join("dopbase.db");
  let server2_key_path = dir2.path().join("master.key");
  let config2 = ServerConfig {
    data_dir: dir2.path().to_path_buf(),
    database_url: format!("sqlite://{}", db2.display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: server2_key_path.clone(),
    },
    docs_enabled: true,
    ..ServerConfig::default()
  };
  let state2 = server::build_setup_state(config2).await.unwrap();
  let router2 = server::router(state2.clone());
  let setup_token2 = state2.setup.read().await.token.clone().unwrap();

  let server2_original_key = std::fs::read(&server2_key_path).unwrap();
  assert_ne!(server2_original_key, server1_key_bytes);

  // Confirm server2 is in setupRequired state
  let (status, status_res, _) = call(&router2, "GET", "/api/v1/bootstrap/status", None, None).await;
  assert_eq!(status, 200);
  assert_eq!(status_res["data"]["state"], "setupRequired");

  // Attempting to restore without master key fails with 400 BACKUP_KEY_REQUIRED
  let boundary = "---------------------------123456789012345678901234567";
  let mut fail_body = Vec::new();
  fail_body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  fail_body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"file\"; filename=\"migration.dop\"\r\n",
  );
  fail_body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  fail_body.extend_from_slice(&raw_bytes);
  fail_body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
  fail_body.extend_from_slice(b"Content-Disposition: form-data; name=\"setup_token\"\r\n\r\n");
  fail_body.extend_from_slice(setup_token2.as_bytes());
  fail_body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let req_fail = Request::builder()
    .method("POST")
    .uri("/api/v1/bootstrap/restore")
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(fail_body))
    .unwrap();
  let res_fail = router2.clone().oneshot(req_fail).await.unwrap();
  assert_eq!(res_fail.status().as_u16(), 400);

  // Now restore with both backup file AND server1's master key
  let mut restore_body = Vec::new();
  restore_body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  restore_body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"file\"; filename=\"migration.dop\"\r\n",
  );
  restore_body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  restore_body.extend_from_slice(&raw_bytes);
  restore_body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
  restore_body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"master_key\"; filename=\"master.key\"\r\n",
  );
  restore_body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  restore_body.extend_from_slice(&server1_key_bytes);
  restore_body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
  restore_body.extend_from_slice(b"Content-Disposition: form-data; name=\"setup_token\"\r\n\r\n");
  restore_body.extend_from_slice(setup_token2.as_bytes());
  restore_body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let req_success = Request::builder()
    .method("POST")
    .uri("/api/v1/bootstrap/restore")
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(restore_body))
    .unwrap();
  let res_success = router2.clone().oneshot(req_success).await.unwrap();
  assert_eq!(res_success.status().as_u16(), 200);

  // Confirm server2 master.key file on disk was NOT replaced with server1's key! It keeps its own key!
  let server2_updated_key = std::fs::read(&server2_key_path).unwrap();
  assert_eq!(server2_updated_key, server2_original_key);
  assert_ne!(server2_updated_key, server1_key_bytes);

  // Sign in on server2 using restored admin account
  let (status, login, _) = call(
    &router2,
    "POST",
    "/api/v1/auth/login",
    None,
    Some(
      json!({"email": "admin@example.com", "password": "correct-horse-123", "sessionKind": "cli"}),
    ),
  )
  .await;
  assert_eq!(status, 200);
  let token2 = login["data"]["token"].as_str().unwrap();

  // Decrypt secret on server2 using server2's own re-keyed master key!
  let (status, secret_res, _) = call(
    &router2,
    "POST",
    &format!("/api/v1/environments/{env_id}/secrets/DATABASE_URL/reveal"),
    Some(token2),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    secret_res["data"]["value"],
    "postgres://prod:secret@db.internal:5432/main"
  );
}

#[tokio::test]
async fn test_download_master_key_cookie_session_without_csrf() {
  let (_dir, _state, router, _) = admin_setup().await;

  // Login as browser session
  let (status, _, headers) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    Some(json!({"email": "admin@example.com", "password": "correct-horse-123", "sessionKind": "browser"})),
  )
  .await;
  assert_eq!(status, 200);

  let cookie = headers
    .get(header::SET_COOKIE)
    .and_then(|v| v.to_str().ok())
    .unwrap()
    .to_string();

  // Browser download of master key should NOT require X-Dopbase-CSRF header on GET
  let req = Request::builder()
    .method("GET")
    .uri("/api/v1/backups/master-key")
    .header(header::COOKIE, &cookie)
    .body(Body::empty())
    .unwrap();
  let res = router.clone().oneshot(req).await.unwrap();
  assert_eq!(res.status().as_u16(), 200);

  let body = axum::body::to_bytes(res.into_body(), 1024 * 1024)
    .await
    .unwrap();
  assert_eq!(body.len(), 32);
}

#[tokio::test]
async fn test_dashboard_upload_cross_key_rekeys_cleanly() {
  // Server 1 creates secret and backup
  let (dir1, _state1, router1, token1) = admin_setup().await;

  let (status, proj, _) = call(
    &router1,
    "POST",
    "/api/v1/projects",
    Some(&token1),
    Some(json!({"name": "shop-project"})),
  )
  .await;
  assert_eq!(status, 201);
  let project_id = proj["data"]["id"].as_str().unwrap();

  let (status, env, _) = call(
    &router1,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(&token1),
    Some(json!({"name": "production"})),
  )
  .await;
  assert_eq!(status, 201);
  let env_id = env["data"]["id"].as_str().unwrap();

  let (status, _, _) = call(
    &router1,
    "PUT",
    &format!("/api/v1/environments/{env_id}/secrets/API_KEY"),
    Some(&token1),
    Some(json!({"value": "super-secret-key-12345"})),
  )
  .await;
  assert_eq!(status, 200);

  let (status, backup_res, _) = call(
    &router1,
    "POST",
    "/api/v1/backups",
    Some(&token1),
    Some(json!({"name": "shop_backup"})),
  )
  .await;
  assert_eq!(status, 201);
  let backup_key = backup_res["data"]["key"].as_str().unwrap();

  let (status, raw_backup, _) = call_raw(
    &router1,
    "GET",
    &format!("/api/v1/backups/{backup_key}"),
    Some(&token1),
  )
  .await;
  assert_eq!(status, 200);

  let server1_key_bytes = std::fs::read(dir1.path().join("master.key")).unwrap();

  // Server 2 is an established server with its own key and admin
  let (dir2, _state2, router2, token2) = admin_setup().await;
  let server2_orig_key = std::fs::read(dir2.path().join("master.key")).unwrap();
  assert_ne!(server1_key_bytes, server2_orig_key);

  // Upload Server 1 backup with Server 1 master key to Server 2
  let boundary = "---------------------------987654321098765432109876543";
  let mut upload_body = Vec::new();
  upload_body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  upload_body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"file\"; filename=\"shop_migrated.dop\"\r\n",
  );
  upload_body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  upload_body.extend_from_slice(&raw_backup);
  upload_body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
  upload_body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"master_key\"; filename=\"master.key\"\r\n",
  );
  upload_body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  upload_body.extend_from_slice(&server1_key_bytes);
  upload_body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let req_upload = Request::builder()
    .method("POST")
    .uri("/api/v1/backups/upload")
    .header(header::AUTHORIZATION, format!("Bearer {token2}"))
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(upload_body))
    .unwrap();
  let res_upload = router2.clone().oneshot(req_upload).await.unwrap();
  assert_eq!(res_upload.status().as_u16(), 201);
  let upload_res_body = axum::body::to_bytes(res_upload.into_body(), 1024 * 1024)
    .await
    .unwrap();
  let upload_json: Value = serde_json::from_slice(&upload_res_body).unwrap();
  let uploaded_key = upload_json["data"]["key"].as_str().unwrap();

  // Now restore on Server 2 directly WITHOUT any master key!
  // Because it was already re-keyed during upload to Server 2's master key!
  let (status, _, _) = call(
    &router2,
    "POST",
    &format!("/api/v1/backups/{uploaded_key}/restore"),
    Some(&token2),
    None,
  )
  .await;
  assert_eq!(status, 200);

  // Server 2 master key was NOT changed
  let server2_key_after = std::fs::read(dir2.path().join("master.key")).unwrap();
  assert_eq!(server2_key_after, server2_orig_key);

  // Reveal restored secret on Server 2
  let (status, secret_res, _) = call(
    &router2,
    "POST",
    &format!("/api/v1/environments/{env_id}/secrets/API_KEY/reveal"),
    Some(&token2),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(secret_res["data"]["value"], "super-secret-key-12345");
}

#[tokio::test]
async fn restore_recovers_agent_and_expiring_runner_tokens() {
  let (_dir, state, router, token) = admin_setup().await;
  let now = Utc::now().to_rfc3339();
  sqlx::query("INSERT INTO service_accounts(id,name,role,created_at,updated_at) VALUES(?,?,?,?,?)")
    .bind("aia_backup_test")
    .bind("backup-agent")
    .bind("ai_agent")
    .bind(&now)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .unwrap();
  sqlx::query(
    "INSERT INTO agent_tokens(id,service_account_id,name,token_hash,created_at) VALUES(?,?,?,?,?)",
  )
  .bind("ait_backup_test")
  .bind("aia_backup_test")
  .bind("restore-token")
  .bind(app::services::token::hash("dpa_restore_test"))
  .bind(&now)
  .execute(state.db.pool())
  .await
  .unwrap();

  sqlx::query("INSERT INTO projects(id,name,created_at,updated_at) VALUES('prj_backup_test','backup-project',?,?)")
    .bind(&now).bind(&now).execute(state.db.pool()).await.unwrap();
  sqlx::query("INSERT INTO environments(id,project_id,name,created_at,updated_at) VALUES('env_backup_test','prj_backup_test','production',?,?)")
    .bind(&now).bind(&now).execute(state.db.pool()).await.unwrap();
  let runner_expiry = (Utc::now() + chrono::Duration::days(7)).to_rfc3339();
  sqlx::query("INSERT INTO runner_tokens(id,environment_id,name,token_hash,created_at,expires_at) VALUES('tok_backup_test','env_backup_test','restore-runner',?,?,?)")
    .bind(app::services::token::hash("dbs_restore_test"))
    .bind(&now).bind(&runner_expiry).execute(state.db.pool()).await.unwrap();

  let (status, backup, _) = call(
    &router,
    "POST",
    "/api/v1/backups",
    Some(&token),
    Some(json!({"name":"accounts_snapshot"})),
  )
  .await;
  assert_eq!(status, 201);
  let key = backup["data"]["key"].as_str().unwrap();

  sqlx::query("DELETE FROM agent_tokens")
    .execute(state.db.pool())
    .await
    .unwrap();
  sqlx::query("DELETE FROM runner_tokens")
    .execute(state.db.pool())
    .await
    .unwrap();
  sqlx::query("DELETE FROM service_accounts")
    .execute(state.db.pool())
    .await
    .unwrap();

  let (status, _, _) = call(
    &router,
    "POST",
    &format!("/api/v1/backups/{key}/restore"),
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);

  let account_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM service_accounts")
    .fetch_one(state.db.pool())
    .await
    .unwrap();
  let token_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_tokens")
    .fetch_one(state.db.pool())
    .await
    .unwrap();
  assert_eq!(account_count, 1);
  assert_eq!(token_count, 1);
  let restored_expiry: String =
    sqlx::query_scalar("SELECT expires_at FROM runner_tokens WHERE id='tok_backup_test'")
      .fetch_one(state.db.pool())
      .await
      .unwrap();
  assert_eq!(restored_expiry, runner_expiry);
}

#[test]
fn backup_keys_are_single_safe_path_components() {
  let directory = TempDir::new().unwrap();
  let backup_directory = directory.path().join("backups");

  for key in ["snapshot.dop", "release_2026-09-07.dop"] {
    let safe_key = sanitize_key(key).unwrap();
    let path = backup_directory.join(&safe_key);
    assert!(path.starts_with(&backup_directory));
    assert_eq!(path.parent(), Some(backup_directory.as_path()));
  }

  for key in [
    "../snapshot.dop",
    "/tmp/snapshot.dop",
    r"C:\temp\snapshot.dop",
    "nested/snapshot.dop",
    "snapshot..dop",
    ".dop",
    "snapshot.dop.exe",
    "snapshot%2fdanger.dop",
    "snapshot․report.dop",
  ] {
    assert!(
      sanitize_key(key).is_err(),
      "expected {key:?} to be rejected"
    );
  }
}

#[test]
fn backup_names_reject_path_syntax_and_deceptive_extensions() {
  for name in ["snapshot", "release_2026-09-07", "snapshot.dop"] {
    assert!(
      sanitize_name(name).is_ok(),
      "expected {name:?} to be accepted"
    );
  }

  for name in [
    "../snapshot",
    "/tmp/snapshot",
    r"C:\temp\snapshot",
    "nested/snapshot",
    "snapshot..dop",
    "snapshot.dop.exe",
    "snapshot․report",
  ] {
    assert!(
      sanitize_name(name).is_err(),
      "expected {name:?} to be rejected"
    );
  }
}

const VAULT_KUBECONFIG_V1: &str = "apiVersion: v1\nkind: Config\nclusters:\n  - name: prod\n";
const VAULT_KUBECONFIG_V2: &str = "apiVersion: v1\nkind: Config\nclusters:\n  - name: prod-v2\n";
const VAULT_SSH_KEY: &str =
  "-----BEGIN OPENSSH PRIVATE KEY-----\nbackup-seed\n-----END OPENSSH PRIVATE KEY-----\n";
const VAULT_SECRET_V1: &str = "token-version-one";
const VAULT_SECRET_V2: &str = "token-version-two";

struct VaultSeed {
  project_id: String,
  environment_id: String,
  parent_folder_id: String,
  child_folder_id: String,
  file_id: String,
  sibling_file_id: String,
}

/// Build a project Vault with a nested tree, a two-revision file, a sibling
/// file and a two-revision secret. Both the current value and the archived
/// revision therefore have to survive a backup/restore round trip.
async fn seed_vault(
  router: &Router,
  token: &str,
  project_name: &str,
) -> VaultSeed {
  let (status, project, _) = call(
    router,
    "POST",
    "/api/v1/projects",
    Some(token),
    Some(json!({"name": project_name})),
  )
  .await;
  assert_eq!(status, 201);
  let project_id = project["data"]["id"].as_str().unwrap().to_owned();

  let (status, environment, _) = call(
    router,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(token),
    Some(json!({"name": "production"})),
  )
  .await;
  assert_eq!(status, 201);
  let environment_id = environment["data"]["id"].as_str().unwrap().to_owned();

  let files = format!("/api/v1/projects/{project_id}/files");

  let (status, parent, _) = call(
    router,
    "POST",
    &format!("{files}/folders"),
    Some(token),
    Some(json!({"name": "clusters", "environmentId": environment_id})),
  )
  .await;
  assert_eq!(status, 201);
  let parent_folder_id = parent["data"]["id"].as_str().unwrap().to_owned();

  let (status, child, _) = call(
    router,
    "POST",
    &format!("{files}/folders"),
    Some(token),
    Some(json!({"name": "production", "parentId": parent_folder_id})),
  )
  .await;
  assert_eq!(status, 201);
  let child_folder_id = child["data"]["id"].as_str().unwrap().to_owned();

  let (status, file, _) = call(
    router,
    "POST",
    &format!("{files}/folders/{child_folder_id}/files"),
    Some(token),
    Some(json!({
      "name": "kubeconfig",
      "kind": "kubeconfig",
      "content": VAULT_KUBECONFIG_V1,
      "encoding": "utf-8",
      "environmentId": environment_id,
    })),
  )
  .await;
  assert_eq!(status, 201);
  assert_eq!(file["data"]["version"], 1);
  let file_id = file["data"]["id"].as_str().unwrap().to_owned();

  let (status, updated, _) = call(
    router,
    "PUT",
    &format!("{files}/{file_id}"),
    Some(token),
    Some(json!({"content": VAULT_KUBECONFIG_V2})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(updated["data"]["version"], 2);

  let (status, sibling, _) = call(
    router,
    "POST",
    &format!("{files}/folders/{parent_folder_id}/files"),
    Some(token),
    Some(json!({
      "name": "deploy-key",
      "kind": "sshPrivateKey",
      "content": VAULT_SSH_KEY,
    })),
  )
  .await;
  assert_eq!(status, 201);
  let sibling_file_id = sibling["data"]["id"].as_str().unwrap().to_owned();

  let secret_path = format!("/api/v1/environments/{environment_id}/secrets/API_TOKEN");
  let (status, _, _) = call(
    router,
    "PUT",
    &secret_path,
    Some(token),
    Some(json!({"value": VAULT_SECRET_V1})),
  )
  .await;
  assert_eq!(status, 200);
  let (status, _, _) = call(
    router,
    "PUT",
    &secret_path,
    Some(token),
    Some(json!({"value": VAULT_SECRET_V2})),
  )
  .await;
  assert_eq!(status, 200);

  VaultSeed {
    project_id,
    environment_id,
    parent_folder_id,
    child_folder_id,
    file_id,
    sibling_file_id,
  }
}

async fn reveal_vault_file(
  router: &Router,
  token: &str,
  project_id: &str,
  file_id: &str,
) -> String {
  let (status, body, _) = call(
    router,
    "POST",
    &format!("/api/v1/projects/{project_id}/files/{file_id}/reveal"),
    Some(token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  body["data"]["content"].as_str().unwrap().to_owned()
}

async fn reveal_secret(
  router: &Router,
  token: &str,
  environment_id: &str,
  key: &str,
) -> String {
  let (status, body, _) = call(
    router,
    "POST",
    &format!("/api/v1/environments/{environment_id}/secrets/{key}/reveal"),
    Some(token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  body["data"]["value"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn restore_recovers_vault_tree_files_and_archived_versions() {
  let (_dir, state, router, token) = admin_setup().await;
  let seed = seed_vault(&router, &token, "vault-restore-project").await;
  let files = format!("/api/v1/projects/{}/files", seed.project_id);

  // Take the snapshot while the tree, the current file value, the archived
  // file revision and the archived secret revision all exist.
  let (status, backup, _) = call(
    &router,
    "POST",
    "/api/v1/backups",
    Some(&token),
    Some(json!({"name": "vault_snapshot"})),
  )
  .await;
  assert_eq!(status, 201);
  let backup_key = backup["data"]["key"].as_str().unwrap().to_owned();

  // Diverge after the snapshot: new file revision, deleted files, deleted
  // folder, extra folder and a deleted secret.
  let (status, _, _) = call(
    &router,
    "PUT",
    &format!("{files}/{}", seed.file_id),
    Some(&token),
    Some(json!({"content": "mutated after backup"})),
  )
  .await;
  assert_eq!(status, 200);
  for file_id in [&seed.file_id, &seed.sibling_file_id] {
    sqlx::query("DELETE FROM vault_files WHERE id = ?")
      .bind(file_id)
      .execute(state.db.pool())
      .await
      .unwrap();
  }
  sqlx::query("DELETE FROM vault_folders WHERE id = ?")
    .bind(&seed.child_folder_id)
    .execute(state.db.pool())
    .await
    .unwrap();
  let (status, _, _) = call(
    &router,
    "POST",
    &format!("{files}/folders"),
    Some(&token),
    Some(json!({"name": "post-backup"})),
  )
  .await;
  assert_eq!(status, 201);
  sqlx::query("DELETE FROM secrets WHERE environment_id = ? AND key = 'API_TOKEN'")
    .bind(&seed.environment_id)
    .execute(state.db.pool())
    .await
    .unwrap();

  let (status, _, _) = call(
    &router,
    "POST",
    &format!("/api/v1/backups/{backup_key}/restore"),
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);

  // Folder tree is back, including the nested child and without the folder
  // created after the snapshot.
  let (status, tree, _) = call(&router, "GET", &format!("{files}/tree"), Some(&token), None).await;
  assert_eq!(status, 200);
  let tree = tree["data"].as_array().unwrap();
  let mut folder_names: Vec<&str> = tree
    .iter()
    .map(|entry| entry["folder"]["name"].as_str().unwrap())
    .collect();
  folder_names.sort();
  assert_eq!(folder_names, vec!["Project root", "clusters", "production"]);
  assert_eq!(
    tree
      .iter()
      .find(|entry| entry["folder"]["id"] == seed.child_folder_id)
      .unwrap()["files"][0]["id"],
    seed.file_id
  );
  assert_eq!(
    tree
      .iter()
      .find(|entry| entry["folder"]["id"] == seed.parent_folder_id)
      .unwrap()["files"][0]["id"],
    seed.sibling_file_id
  );

  // The restore keeps the audit trail that existed in the snapshot.
  let audit_count: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE project_id = ?")
      .bind(&seed.project_id)
      .fetch_one(state.db.pool())
      .await
      .unwrap();
  assert!(audit_count > 0);

  let folder_count: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM vault_folders WHERE project_id = ? AND is_root = 0")
      .bind(&seed.project_id)
      .fetch_one(state.db.pool())
      .await
      .unwrap();
  assert_eq!(folder_count, 2);
  let file_count: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM vault_files WHERE folder_id IN (SELECT id FROM vault_folders WHERE project_id = ?)")
      .bind(&seed.project_id)
      .fetch_one(state.db.pool())
      .await
      .unwrap();
  assert_eq!(file_count, 2);
  let archived_file_count: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM vault_file_versions WHERE file_id = ?")
      .bind(&seed.file_id)
      .fetch_one(state.db.pool())
      .await
      .unwrap();
  assert_eq!(archived_file_count, 1);
  let archived_secret_count: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM secret_versions WHERE environment_id = ? AND key = 'API_TOKEN'",
  )
  .bind(&seed.environment_id)
  .fetch_one(state.db.pool())
  .await
  .unwrap();
  assert_eq!(archived_secret_count, 1);

  // Current and archived file contents decrypt byte-exactly.
  assert_eq!(
    reveal_vault_file(&router, &token, &seed.project_id, &seed.file_id).await,
    VAULT_KUBECONFIG_V2
  );
  assert_eq!(
    reveal_vault_file(&router, &token, &seed.project_id, &seed.sibling_file_id).await,
    VAULT_SSH_KEY
  );
  let (status, file_versions, _) = call(
    &router,
    "GET",
    &format!("{files}/{}/versions", seed.file_id),
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  let file_versions = file_versions["data"].as_array().unwrap();
  assert_eq!(file_versions.len(), 1);
  assert_eq!(file_versions[0]["version"], 1);
  let (status, _, _) = call(
    &router,
    "POST",
    &format!("{files}/{}/versions/1/rollback", seed.file_id),
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    reveal_vault_file(&router, &token, &seed.project_id, &seed.file_id).await,
    VAULT_KUBECONFIG_V1
  );

  // Secret current value and archived revision decrypt byte-exactly.
  assert_eq!(
    reveal_secret(&router, &token, &seed.environment_id, "API_TOKEN").await,
    VAULT_SECRET_V2
  );
  let (status, secret_versions, _) = call(
    &router,
    "GET",
    &format!(
      "/api/v1/environments/{}/secrets/API_TOKEN/versions",
      seed.environment_id
    ),
    Some(&token),
    None,
  )
  .await;
  assert_eq!(status, 200);
  let secret_versions = secret_versions["data"].as_array().unwrap();
  assert_eq!(secret_versions.len(), 1);
  assert_eq!(secret_versions[0]["version"], 1);
  let (status, _, _) = call(
    &router,
    "POST",
    &format!(
      "/api/v1/environments/{}/secrets/API_TOKEN/rollback",
      seed.environment_id
    ),
    Some(&token),
    Some(json!({"version": 1})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    reveal_secret(&router, &token, &seed.environment_id, "API_TOKEN").await,
    VAULT_SECRET_V1
  );
}

async fn upload_backup_with_master_key(
  router: &Router,
  token: &str,
  filename: &str,
  backup_bytes: &[u8],
  master_key: &[u8],
) -> String {
  let boundary = "---------------------------backupvaultupload";
  let mut body = Vec::new();
  body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
  body.extend_from_slice(
    format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
      .as_bytes(),
  );
  body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  body.extend_from_slice(backup_bytes);
  body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
  body.extend_from_slice(
    b"Content-Disposition: form-data; name=\"master_key\"; filename=\"master.key\"\r\n",
  );
  body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
  body.extend_from_slice(master_key);
  body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

  let request = Request::builder()
    .method("POST")
    .uri("/api/v1/backups/upload")
    .header(header::AUTHORIZATION, format!("Bearer {token}"))
    .header(
      header::CONTENT_TYPE,
      format!("multipart/form-data; boundary={boundary}"),
    )
    .body(Body::from(body))
    .unwrap();
  let response = router.clone().oneshot(request).await.unwrap();
  assert_eq!(response.status().as_u16(), 201);
  let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
  let json: Value = serde_json::from_slice(&bytes).unwrap();
  json["data"]["key"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn vault_data_still_decrypts_after_cross_master_key_restore() {
  // Server 1 owns the Vault and the backup.
  let (dir1, _state1, router1, token1) = admin_setup().await;
  let seed = seed_vault(&router1, &token1, "vault-cross-key-project").await;
  let (status, backup, _) = call(
    &router1,
    "POST",
    "/api/v1/backups",
    Some(&token1),
    Some(json!({"name": "vault_cross_key"})),
  )
  .await;
  assert_eq!(status, 201);
  let backup_key = backup["data"]["key"].as_str().unwrap().to_owned();
  let (status, raw_backup, _) = call_raw(
    &router1,
    "GET",
    &format!("/api/v1/backups/{backup_key}"),
    Some(&token1),
  )
  .await;
  assert_eq!(status, 200);
  let server1_key = std::fs::read(dir1.path().join("master.key")).unwrap();

  // Server 2 has its own master key. Uploading the backup re-keys the snapshot
  // to that key, and restoring then copies the Vault rows into the live db.
  let (dir2, _state2, router2, token2) = admin_setup().await;
  let server2_key = std::fs::read(dir2.path().join("master.key")).unwrap();
  assert_ne!(server1_key, server2_key);

  let uploaded_key = upload_backup_with_master_key(
    &router2,
    &token2,
    "vault_migrated.dop",
    &raw_backup,
    &server1_key,
  )
  .await;
  let (status, _, _) = call(
    &router2,
    "POST",
    &format!("/api/v1/backups/{uploaded_key}/restore"),
    Some(&token2),
    None,
  )
  .await;
  assert_eq!(status, 200);

  // Server 2's key file must not be replaced by the source server's key.
  assert_eq!(
    std::fs::read(dir2.path().join("master.key")).unwrap(),
    server2_key
  );

  // Current file value, archived file revision, current secret value and
  // archived secret revision all still decrypt under the target key.
  assert_eq!(
    reveal_vault_file(&router2, &token2, &seed.project_id, &seed.file_id).await,
    VAULT_KUBECONFIG_V2
  );
  assert_eq!(
    reveal_vault_file(&router2, &token2, &seed.project_id, &seed.sibling_file_id).await,
    VAULT_SSH_KEY
  );
  let files = format!("/api/v1/projects/{}/files", seed.project_id);
  let (status, _, _) = call(
    &router2,
    "POST",
    &format!("{files}/{}/versions/1/rollback", seed.file_id),
    Some(&token2),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    reveal_vault_file(&router2, &token2, &seed.project_id, &seed.file_id).await,
    VAULT_KUBECONFIG_V1
  );

  assert_eq!(
    reveal_secret(&router2, &token2, &seed.environment_id, "API_TOKEN").await,
    VAULT_SECRET_V2
  );
  let (status, _, _) = call(
    &router2,
    "POST",
    &format!(
      "/api/v1/environments/{}/secrets/API_TOKEN/rollback",
      seed.environment_id
    ),
    Some(&token2),
    Some(json!({"version": 1})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    reveal_secret(&router2, &token2, &seed.environment_id, "API_TOKEN").await,
    VAULT_SECRET_V1
  );

  // The restore endpoint itself also re-keys. Drop the original backup (still
  // encrypted with server 1's key) into server 2's backup directory and
  // restore it while supplying that source key in the request body.
  let direct_key = "vault_direct.dop";
  let backup_dir = dir2.path().join("backups");
  std::fs::create_dir_all(&backup_dir).unwrap();
  std::fs::write(backup_dir.join(direct_key), &raw_backup).unwrap();
  let (status, body, _) = call(
    &router2,
    "POST",
    &format!("/api/v1/backups/{direct_key}/restore"),
    Some(&token2),
    Some(json!({"master_key": hex::encode(&server1_key)})),
  )
  .await;
  assert_eq!(status, 200, "direct restore failed: {body}");

  assert_eq!(
    reveal_vault_file(&router2, &token2, &seed.project_id, &seed.file_id).await,
    VAULT_KUBECONFIG_V2
  );
  let (status, _, _) = call(
    &router2,
    "POST",
    &format!("{files}/{}/versions/1/rollback", seed.file_id),
    Some(&token2),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    reveal_vault_file(&router2, &token2, &seed.project_id, &seed.file_id).await,
    VAULT_KUBECONFIG_V1
  );
  assert_eq!(
    reveal_secret(&router2, &token2, &seed.environment_id, "API_TOKEN").await,
    VAULT_SECRET_V2
  );
  let (status, _, _) = call(
    &router2,
    "POST",
    &format!(
      "/api/v1/environments/{}/secrets/API_TOKEN/rollback",
      seed.environment_id
    ),
    Some(&token2),
    Some(json!({"version": 1})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(
    reveal_secret(&router2, &token2, &seed.environment_id, "API_TOKEN").await,
    VAULT_SECRET_V1
  );
}

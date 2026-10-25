//! Atomic Vault import: `POST /projects/{project}/files/import`.

use app::{config::ServerConfig, services::crypto::EncryptedValue, state::AppState};
use axum::{
  Router,
  body::{Body, to_bytes},
  http::{Request, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::collections::HashMap;
use tempfile::TempDir;
use tower::ServiceExt;

async fn fixture() -> (TempDir, AppState, Router) {
  fixture_with_docs(false).await
}

async fn fixture_with_docs(docs_enabled: bool) -> (TempDir, AppState, Router) {
  let dir = TempDir::new().unwrap();
  let config = ServerConfig {
    data_dir: dir.path().to_path_buf(),
    database_url: format!("sqlite://{}", dir.path().join("dopbase.db").display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: dir.path().join("master.key"),
    },
    docs_enabled,
    ..ServerConfig::default()
  };
  let state = app::server::build_setup_state(config).await.unwrap();
  let router = app::server::router(state.clone());
  (dir, state, router)
}

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

struct Admin {
  cookie: String,
  csrf: String,
  project_id: String,
}

/// `(version, ciphertext, value_nonce, wrapped_key, key_nonce, encoding, archived_at)`
type ArchivedVersion = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, String);

async fn admin_project(
  router: &Router,
  state: &AppState,
) -> Admin {
  let setup_token = state.setup.read().await.token.clone().unwrap();
  let (status, bootstrap, headers) = call(
    router,
    "POST",
    "/api/v1/bootstrap/admin",
    None,
    None,
    Some(json!({"setupToken":setup_token,"email":"root@example.com","password":"fixture-password-123"})),
  )
  .await;
  assert_eq!(status, 201, "{bootstrap}");
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
    router,
    "POST",
    "/api/v1/projects",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"import-test"})),
  )
  .await;
  assert_eq!(status, 201, "{project}");
  Admin {
    cookie,
    csrf,
    project_id: project["data"]["id"].as_str().unwrap().to_owned(),
  }
}

fn import_path(admin: &Admin) -> String {
  format!("/api/v1/projects/{}/files/import", admin.project_id)
}

fn files_path(admin: &Admin) -> String {
  format!("/api/v1/projects/{}/files", admin.project_id)
}

async fn vault_counts(
  state: &AppState,
  project_id: &str,
) -> (i64, i64, i64) {
  let folders: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_folders WHERE project_id=?")
    .bind(project_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap();
  let files: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM vault_files WHERE folder_id IN (SELECT id FROM vault_folders WHERE project_id=?)",
  )
  .bind(project_id)
  .fetch_one(state.db.pool())
  .await
  .unwrap();
  let versions: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM vault_file_versions WHERE file_id IN (SELECT id FROM vault_files WHERE folder_id IN (SELECT id FROM vault_folders WHERE project_id=?))",
  )
  .bind(project_id)
  .fetch_one(state.db.pool())
  .await
  .unwrap();
  (folders, files, versions)
}

#[tokio::test]
async fn import_creates_nested_folders_and_keeps_every_revision() {
  let (_directory, state, router) = fixture().await;
  let admin = admin_project(&router, &state).await;
  let second_revision = "#!/bin/sh\necho two\n";
  let second_revision_base64 = STANDARD.encode(second_revision.as_bytes());
  let payload = json!({
    "folder": "Imported vault",
    "entries": [
      {
        "name": "deploy.sh",
        "folder": "ssh/prod",
        "kind": "sshPrivateKey",
        "versions": [
          {"encoding": "utf-8", "content": "#!/bin/sh\necho one\n"},
          {"encoding": "base64", "content": second_revision_base64},
          {"encoding": "utf-8", "content": "#!/bin/sh\necho three\n"}
        ]
      },
      {
        "name": "notes.txt",
        "folder": "",
        "kind": "text",
        "versions": [{"encoding": "utf-8", "content": "root note"}]
      },
      {
        "name": "config.yaml",
        "folder": "kube\\prod",
        "kind": "kubeconfig",
        "versions": [{"encoding": "utf-8", "content": "apiVersion: v1\n"}]
      }
    ]
  });
  let (status, body, _) = call(
    &router,
    "POST",
    &import_path(&admin),
    Some(&admin.cookie),
    Some(&admin.csrf),
    Some(payload),
  )
  .await;
  assert_eq!(status, 201, "{body}");
  assert_eq!(body["success"], true);
  assert_eq!(body["message"], "VAULT_IMPORT_COMPLETED");
  let root_id = body["data"]["folderId"].as_str().unwrap().to_owned();
  assert_eq!(body["data"]["folders"], 5, "{body}");
  assert_eq!(body["data"]["files"], 3, "{body}");
  assert_eq!(body["data"]["versions"], 5, "{body}");
  assert_eq!(
    vault_counts(&state, &admin.project_id).await,
    (6, 3, 2),
    "root project folder + imported tree; two archived revisions"
  );

  let (status, tree, _) = call(
    &router,
    "GET",
    &format!("{}/tree", files_path(&admin)),
    Some(&admin.cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200, "{tree}");
  let mut folders = HashMap::<String, Value>::new();
  let mut files = Vec::<(String, Value)>::new();
  for contents in tree["data"].as_array().unwrap() {
    let folder = contents["folder"].clone();
    folders.insert(folder["id"].as_str().unwrap().to_owned(), folder);
    for file in contents["files"].as_array().unwrap() {
      files.push((
        contents["folder"]["id"].as_str().unwrap().to_owned(),
        file.clone(),
      ));
    }
  }
  let folder_named = |parent: &Value, name: &str| {
    folders
      .values()
      .find(|folder| folder["parentId"] == parent["id"] && folder["name"] == name)
      .unwrap_or_else(|| panic!("folder {name:?} must exist below {parent}"))
      .clone()
  };
  let root = folders.get(&root_id).expect("imported root folder");
  assert_eq!(root["name"], "Imported vault");
  let project_root = folders
    .get(root["parentId"].as_str().unwrap())
    .expect("project root folder");
  assert_eq!(project_root["isRoot"], true);
  let ssh = folder_named(root, "ssh");
  let ssh_prod = folder_named(&ssh, "prod");
  let kube = folder_named(root, "kube");
  let kube_prod = folder_named(&kube, "prod");

  let file_named = |folder: &Value, name: &str| {
    files
      .iter()
      .find(|(folder_id, file)| folder_id == folder["id"].as_str().unwrap() && file["name"] == name)
      .map(|(_, file)| file.clone())
      .unwrap_or_else(|| panic!("file {name:?} must exist in {folder}"))
  };
  let deploy = file_named(&ssh_prod, "deploy.sh");
  assert_eq!(deploy["kind"], "sshPrivateKey");
  assert_eq!(deploy["version"], 3);
  assert_eq!(deploy["encoding"], "utf-8");
  let notes = file_named(root, "notes.txt");
  assert_eq!(notes["kind"], "text");
  assert_eq!(notes["version"], 1);
  let config = file_named(&kube_prod, "config.yaml");
  assert_eq!(config["kind"], "kubeconfig");
  assert_eq!(config["version"], 1);

  let deploy_id = deploy["id"].as_str().unwrap();
  let (status, revealed, _) = call(
    &router,
    "POST",
    &format!("{}/{}/reveal", files_path(&admin), deploy_id),
    Some(&admin.cookie),
    Some(&admin.csrf),
    None,
  )
  .await;
  assert_eq!(status, 200, "{revealed}");
  assert_eq!(revealed["data"]["content"], "#!/bin/sh\necho three\n");
  assert_eq!(revealed["data"]["version"], 3);
  assert_eq!(revealed["data"]["encoding"], "utf-8");

  let archived: Vec<ArchivedVersion> = sqlx::query_as(
      "SELECT version,ciphertext,value_nonce,wrapped_key,key_nonce,encoding,archived_at FROM vault_file_versions WHERE file_id=? ORDER BY version",
    )
    .bind(deploy_id)
    .fetch_all(state.db.pool())
    .await
    .unwrap();
  assert_eq!(archived.len(), 2, "revisions 1 and 2 are archived");
  let expected = ["#!/bin/sh\necho one\n", second_revision_base64.as_str()];
  for (index, row) in archived.iter().enumerate() {
    assert_eq!(row.0, i64::try_from(index).unwrap() + 1);
    assert!(!row.6.is_empty(), "archived_at must be recorded");
    let encrypted = EncryptedValue {
      ciphertext: row.1.clone(),
      value_nonce: row.2.clone(),
      wrapped_key: row.3.clone(),
      key_nonce: row.4.clone(),
    };
    let clear = state
      .crypto
      .decrypt(&encrypted, deploy_id, "vault-file", row.0)
      .unwrap();
    assert_eq!(
      clear.as_slice(),
      expected[index].as_bytes(),
      "revision {} must decrypt byte-for-byte",
      row.0
    );
  }
  assert_eq!(archived[0].5, "utf-8");
  assert_eq!(archived[1].5, "base64");

  let events: Vec<(String, String, String, String)> = sqlx::query_as(
    "SELECT action,resource_type,resource_id,metadata FROM audit_events WHERE action='vault.import.completed' AND project_id=?",
  )
  .bind(&admin.project_id)
  .fetch_all(state.db.pool())
  .await
  .unwrap();
  assert_eq!(events.len(), 1, "one import must record one audit event");
  let (action, resource_type, resource_id, metadata) = &events[0];
  assert_eq!(action, "vault.import.completed");
  assert_eq!(resource_type, "vault_folder");
  assert_eq!(resource_id, &root_id);
  let metadata: Value = serde_json::from_str(metadata).unwrap();
  assert_eq!(
    metadata,
    json!({"folders": 5, "files": 3, "versions": 5, "destination": "Imported vault"})
  );
}

#[tokio::test]
async fn import_rejects_an_existing_destination_without_writing() {
  let (_directory, state, router) = fixture().await;
  let admin = admin_project(&router, &state).await;
  let payload = json!({
    "folder": "Imported vault",
    "entries": [{
      "name": "first.txt",
      "folder": "nested",
      "kind": "text",
      "versions": [{"encoding": "utf-8", "content": "first"}]
    }]
  });
  let (status, body, _) = call(
    &router,
    "POST",
    &import_path(&admin),
    Some(&admin.cookie),
    Some(&admin.csrf),
    Some(payload),
  )
  .await;
  assert_eq!(status, 201, "{body}");
  let before = vault_counts(&state, &admin.project_id).await;
  assert_eq!(before, (3, 1, 0));

  let (status, conflict, _) = call(
    &router,
    "POST",
    &import_path(&admin),
    Some(&admin.cookie),
    Some(&admin.csrf),
    Some(json!({
      "folder": "imported VAULT",
      "entries": [{
        "name": "second.txt",
        "folder": "",
        "kind": "text",
        "versions": [{"encoding": "utf-8", "content": "second"}]
      }]
    })),
  )
  .await;
  assert_eq!(status, 409, "{conflict}");
  assert!(
    conflict["error"]["VAULT_NAME_CONFLICT"].is_string(),
    "{conflict}"
  );
  assert_eq!(
    vault_counts(&state, &admin.project_id).await,
    before,
    "a rejected import must not add folders, files, or revisions"
  );
}

#[tokio::test]
async fn import_rejects_invalid_payloads_without_writing() {
  let (_directory, state, router) = fixture().await;
  let admin = admin_project(&router, &state).await;
  let import = |payload: Value| {
    let router = router.clone();
    let cookie = admin.cookie.clone();
    let csrf = admin.csrf.clone();
    let path = import_path(&admin);
    async move {
      call(
        &router,
        "POST",
        &path,
        Some(&cookie),
        Some(&csrf),
        Some(payload),
      )
      .await
    }
  };
  let entry = |name: &str, folder: &str, content: &str| {
    json!({
      "name": name,
      "folder": folder,
      "kind": "text",
      "versions": [{"encoding": "utf-8", "content": content}]
    })
  };

  let (status, body, _) = import(json!({"folder": "Import", "entries": []})).await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [entry("..", "nested", "value")]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [entry("ok.txt", "nested/..", "value")]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "..",
    "entries": [entry("ok.txt", "", "value")]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [
      entry("Deploy.sh", "Ops/Prod", "one"),
      entry("deploy.sh", "ops/prod", "two")
    ]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [{
      "name": "empty.txt",
      "folder": "",
      "kind": "text",
      "versions": []
    }]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let oversized = "x".repeat(1024 * 1024 + 1);
  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [entry("large.txt", "", &oversized)]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [entry("nul.txt", "", "before\0after")]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [entry("ansi\u{1b}[2Jevil.txt", "", "value")]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [entry("ok.txt", "ops\tprod", "value")]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let deep = vec!["a"; 33].join("/");
  assert!(
    deep.chars().count() <= 160,
    "the depth limit must trigger, not the path length"
  );
  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [entry("deep.txt", &deep, "value")]
  }))
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let too_many: Vec<Value> = (0..1001)
    .map(|index| entry(&format!("file-{index}.txt"), "", "value"))
    .collect();
  let (status, body, _) = import(json!({"folder": "Import", "entries": too_many})).await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");

  let (status, body, _) = import(json!({
    "folder": "Import",
    "entries": [{
      "name": "bad.txt",
      "folder": "",
      "kind": "text",
      "versions": [{"encoding": "hex", "content": "value"}]
    }]
  }))
  .await;
  assert_eq!(status, 422, "{body}");
  assert!(
    body["error"]["VAULT_ENCODING_INVALID"].is_string(),
    "{body}"
  );

  assert_eq!(
    vault_counts(&state, &admin.project_id).await,
    (0, 0, 0),
    "rejected payloads must leave the project untouched"
  );
  let events: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM audit_events WHERE action='vault.import.completed' AND project_id=?",
  )
  .bind(&admin.project_id)
  .fetch_one(state.db.pool())
  .await
  .unwrap();
  assert_eq!(events, 0);
}

#[tokio::test]
async fn import_rejects_more_than_the_total_content_budget() {
  let (_directory, state, router) = fixture().await;
  let admin = admin_project(&router, &state).await;
  let chunk = "x".repeat(1024 * 1024);
  let entries: Vec<Value> = (0..33)
    .map(|index| {
      json!({
        "name": format!("chunk-{index}.txt"),
        "folder": "",
        "kind": "text",
        "versions": [{"encoding": "utf-8", "content": chunk}]
      })
    })
    .collect();
  let payload = json!({"folder": "Import", "entries": entries});
  assert!(
    payload.to_string().len() > 3 * 1024 * 1024,
    "the payload must exceed the global 3 MiB body limit"
  );
  let (status, body, _) = call(
    &router,
    "POST",
    &import_path(&admin),
    Some(&admin.cookie),
    Some(&admin.csrf),
    Some(payload),
  )
  .await;
  assert_eq!(status, 400, "{body}");
  assert!(body["error"]["VAULT_IMPORT_INVALID"].is_string(), "{body}");
  assert_eq!(vault_counts(&state, &admin.project_id).await, (0, 0, 0));
}

#[tokio::test]
async fn import_rejects_more_than_the_total_revision_budget() {
  let (_directory, state, router) = fixture().await;
  let admin = admin_project(&router, &state).await;
  // Empty revisions cost no content budget, so the revision count is the only
  // bound on how many rows one import can insert under the write lock.
  let entries: Vec<Value> = (0..6)
    .map(|index| {
      json!({
        "name": format!("file-{index}.txt"),
        "folder": "",
        "kind": "text",
        "versions": (0..1000)
          .map(|_| json!({"encoding":"utf-8","content":""}))
          .collect::<Vec<_>>()
      })
    })
    .collect();
  let (status, body, _) = call(
    &router,
    "POST",
    &import_path(&admin),
    Some(&admin.cookie),
    Some(&admin.csrf),
    Some(json!({"folder": "Import", "entries": entries})),
  )
  .await;
  assert_eq!(status, 400, "{body}");
  let message = body["error"]["VAULT_IMPORT_INVALID"]
    .as_str()
    .unwrap_or_else(|| panic!("expected VAULT_IMPORT_INVALID: {body}"));
  assert!(
    message.contains("5000") && message.contains("revisions"),
    "the rejection must name the total revision limit: {message}"
  );
  assert_eq!(
    vault_counts(&state, &admin.project_id).await,
    (0, 0, 0),
    "a rejected import must not write any rows"
  );
  let events: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM audit_events WHERE action='vault.import.completed' AND project_id=?",
  )
  .bind(&admin.project_id)
  .fetch_one(state.db.pool())
  .await
  .unwrap();
  assert_eq!(events, 0);
}

#[tokio::test]
async fn import_requires_project_write_access() {
  let (_directory, state, router) = fixture().await;
  let admin = admin_project(&router, &state).await;
  let (status, account, _) = call(
    &router,
    "POST",
    "/api/v1/service-accounts",
    Some(&admin.cookie),
    Some(&admin.csrf),
    Some(json!({"name":"fixture-agent"})),
  )
  .await;
  assert_eq!(status, 201, "{account}");
  let account_id = account["data"]["id"].as_str().unwrap();
  let (status, token, _) = call(
    &router,
    "POST",
    &format!("/api/v1/service-accounts/{account_id}/tokens"),
    Some(&admin.cookie),
    Some(&admin.csrf),
    Some(json!({"name":"fixture"})),
  )
  .await;
  assert_eq!(status, 201, "{token}");
  let agent = format!(
    "Bearer {}",
    token["data"]["plaintextToken"].as_str().unwrap()
  );
  let (status, denied, _) = call(
    &router,
    "POST",
    &import_path(&admin),
    Some(&agent),
    None,
    Some(json!({
      "folder": "Imported vault",
      "entries": [{
        "name": "secret.txt",
        "folder": "",
        "kind": "secret",
        "versions": [{"encoding": "utf-8", "content": "value"}]
      }]
    })),
  )
  .await;
  assert_eq!(status, 403, "{denied}");
  assert!(denied["error"].is_object());
  assert_eq!(vault_counts(&state, &admin.project_id).await, (0, 0, 0));
}

#[tokio::test]
async fn import_route_is_documented() {
  let (_directory, _state, router) = fixture_with_docs(true).await;
  let (status, spec, _) = call(&router, "GET", "/api/v1/openapi.json", None, None, None).await;
  assert_eq!(status, 200, "{spec}");
  assert!(
    spec["paths"]["/api/v1/projects/{project_ref}/files/import"]["post"].is_object(),
    "{spec}"
  );
  for schema in [
    "ImportVaultRequest",
    "ImportEntry",
    "ImportVersion",
    "VaultImportSummary",
  ] {
    assert!(
      spec["components"]["schemas"][schema].is_object(),
      "schema {schema} must be documented"
    );
  }
}

use app::{config::ServerConfig, server};
use axum::{
  Router,
  body::{Body, to_bytes},
  http::{Request, header},
};
use serde_json::{Value, json};
use std::{
  io::Write,
  process::{Command, Output, Stdio},
};
use tempfile::TempDir;
use tower::ServiceExt;

async fn fixture() -> (TempDir, app::state::AppState, Router) {
  let dir = TempDir::new().unwrap();
  let config = ServerConfig {
    data_dir: dir.path().to_path_buf(),
    database_url: format!("sqlite://{}", dir.path().join("dopbase.db").display()),
    master_key: app::config::MasterKeyConfig {
      provider: "file".into(),
      path: dir.path().join("master.key"),
    },
    ..ServerConfig::default()
  };
  let state = server::build_setup_state(config).await.unwrap();
  let router = server::router(state.clone());
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

async fn admin_session(
  router: &Router,
  state: &app::state::AppState,
) -> (String, String) {
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
  (cookie, csrf)
}

async fn run_cli(
  url: String,
  token: String,
  arguments: Vec<String>,
) -> Output {
  tokio::task::spawn_blocking(move || {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dopbase"));
    for name in app::constants::config::executable_environment_names() {
      command.env_remove(name);
    }
    command
      .arg("--json")
      .args(arguments)
      .env("DOPBASE_URL", url)
      .env("DOPBASE_TOKEN", token)
      .output()
      .unwrap()
  })
  .await
  .unwrap()
}

async fn run_mcp(
  url: String,
  token: String,
  messages: Vec<Value>,
) -> Output {
  tokio::task::spawn_blocking(move || {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dopbase"))
      .args(["mcp", "serve"])
      .env("DOPBASE_URL", url)
      .env("DOPBASE_TOKEN", token)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .unwrap();
    {
      let stdin = child.stdin.as_mut().unwrap();
      for message in messages {
        writeln!(stdin, "{}", serde_json::to_string(&message).unwrap()).unwrap();
      }
    }
    child.wait_with_output().unwrap()
  })
  .await
  .unwrap()
}

#[tokio::test]
async fn encrypted_files_keep_versions_and_agent_tokens_cannot_reveal_or_write() {
  let (directory, state, router) = fixture().await;
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
    Some(json!({"name":"files-test"})),
  )
  .await;
  assert_eq!(status, 201);
  let project_id = project["data"]["id"].as_str().unwrap().to_owned();
  let vault_project_id = project_id.clone();
  let files_path = format!("/api/v1/projects/{project_id}/files");

  let (status, folder, _) = call(
    &router,
    "POST",
    &format!("{files_path}/folders"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"production"})),
  )
  .await;
  assert_eq!(status, 201);
  let root_id = folder["data"]["id"].as_str().unwrap().to_owned();
  let (status, empty_folder, _) = call(
    &router,
    "POST",
    &format!("{files_path}/folders"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"to-delete","parentId":root_id})),
  )
  .await;
  assert_eq!(status, 201);
  let empty_folder_id = empty_folder["data"]["id"].as_str().unwrap();
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("{files_path}/folders/{empty_folder_id}"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 200, "Admin UI should delete an empty folder");

  let (status, child, _) = call(
    &router,
    "POST",
    &format!("{files_path}/folders"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"cluster","parentId":root_id})),
  )
  .await;
  assert_eq!(status, 201);
  let child_id = child["data"]["id"].as_str().unwrap().to_owned();

  let (status, environment, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{project_id}/environments"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"Release Candidate (EU)"})),
  )
  .await;
  assert_eq!(status, 201);
  let environment_id = environment["data"]["id"].as_str().unwrap();
  let vault_environment_id = environment_id.to_owned();

  let (status, created, _) = call(
    &router,
    "POST",
    &format!("{files_path}/folders/{child_id}/files"),
    Some(&cookie),
    Some(&csrf),
    Some(
      json!({"name":"config","kind":"kubeconfig","content":"apiVersion: v1\n","encoding":"utf-8","environmentId":environment_id}),
    ),
  )
  .await;
  assert_eq!(status, 201);
  assert!(created["data"].get("content").is_none());
  assert_eq!(created["data"]["environmentId"], environment_id);
  let file_id = created["data"]["id"].as_str().unwrap().to_owned();

  let (status, renamed_folder, _) = call(
    &router,
    "PUT",
    &format!("{files_path}/folders/{child_id}"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"cluster-renamed","parentId":root_id})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(renamed_folder["data"]["name"], "cluster-renamed");

  let (status, _, _) = call(
    &router,
    "PUT",
    &format!("{files_path}/folders/{child_id}"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"cluster","parentId":root_id})),
  )
  .await;
  assert_eq!(status, 200);

  let (status, destination, _) = call(
    &router,
    "POST",
    &format!("{files_path}/folders"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"staging"})),
  )
  .await;
  assert_eq!(status, 201);
  let destination_id = destination["data"]["id"].as_str().unwrap();
  let (status, moved_file, _) = call(
    &router,
    "POST",
    &format!("{files_path}/{file_id}/move"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"folderId":destination_id})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(moved_file["data"]["folderId"], destination_id);
  assert_eq!(moved_file["data"]["id"], file_id);
  assert_eq!(moved_file["data"]["environmentId"], environment_id);
  assert_eq!(moved_file["data"]["version"], 1);
  let (status, _, _) = call(
    &router,
    "POST",
    &format!("{files_path}/{file_id}/move"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"folderId":child_id})),
  )
  .await;
  assert_eq!(status, 200);
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("{files_path}/folders/{destination_id}"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 200);

  let (status, tree, _) = call(
    &router,
    "GET",
    &format!("{files_path}/tree"),
    Some(&cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(tree["data"].as_array().unwrap().len(), 3);
  assert_eq!(
    tree["data"]
      .as_array()
      .unwrap()
      .iter()
      .find(|entry| entry["folder"]["id"] == child_id)
      .unwrap()["files"][0]["id"],
    file_id
  );

  let (status, revealed, _) = call(
    &router,
    "POST",
    &format!("{files_path}/{file_id}/reveal"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(revealed["data"]["content"], "apiVersion: v1\n");

  let (status, updated, _) = call(
    &router,
    "PUT",
    &format!("{files_path}/{file_id}"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"content":"apiVersion: v2\n","encoding":"utf-8"})),
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(updated["data"]["version"], 2);
  let (status, versions, _) = call(
    &router,
    "GET",
    &format!("{files_path}/{file_id}/versions"),
    Some(&cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(versions["data"][0]["version"], 1);
  assert!(versions["data"][0].get("ciphertext").is_none());

  let (status, rolled_back, _) = call(
    &router,
    "POST",
    &format!("{files_path}/{file_id}/versions/1/rollback"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(rolled_back["data"]["version"], 3);
  let rollback_events: Vec<(String,)> = sqlx::query_as(
    "SELECT metadata FROM audit_events WHERE action='vault.file.rolled_back' AND resource_id=?",
  )
  .bind(&file_id)
  .fetch_all(state.db.pool())
  .await
  .unwrap();
  assert_eq!(
    rollback_events.len(),
    1,
    "a rollback must record its own audit event"
  );
  let rollback_metadata: Value = serde_json::from_str(&rollback_events[0].0).unwrap();
  assert_eq!(rollback_metadata, json!({"fromVersion":1,"toVersion":3}));
  let (status, restored, _) = call(
    &router,
    "POST",
    &format!("{files_path}/{file_id}/reveal"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 200);
  assert_eq!(restored["data"]["content"], "apiVersion: v1\n");

  let (status, account, _) = call(
    &router,
    "POST",
    "/api/v1/service-accounts",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"fixture-agent"})),
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
    Some(json!({"name":"fixture"})),
  )
  .await;
  assert_eq!(status, 201);
  let agent = format!(
    "Bearer {}",
    token["data"]["plaintextToken"].as_str().unwrap()
  );
  let (folder_status, folder_list, _) = call(
    &router,
    "GET",
    &format!("{files_path}/folders"),
    Some(&agent),
    None,
    None,
  )
  .await;
  assert_eq!(folder_status, 200, "{folder_list}");
  let (status, agent_tree, _) = call(
    &router,
    "GET",
    &format!("{files_path}/tree"),
    Some(&agent),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200, "{agent_tree}");
  assert_eq!(agent_tree["data"].as_array().unwrap().len(), 3);
  let (status, denied, _) = call(
    &router,
    "POST",
    &format!("{files_path}/{file_id}/reveal"),
    Some(&agent),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403);
  assert!(denied["error"].is_object());
  let (status, _denied, _) = call(
    &router,
    "PUT",
    &format!("{files_path}/{file_id}"),
    Some(&agent),
    None,
    Some(json!({"content":"malicious","encoding":"utf-8"})),
  )
  .await;
  assert_eq!(status, 403);

  let (_, login, _) = call(
    &router,
    "POST",
    "/api/v1/auth/login",
    None,
    None,
    Some(json!({"email":"root@example.com","password":"fixture-password-123","sessionKind":"cli"})),
  )
  .await;
  let cli_token = login["data"]["token"].as_str().unwrap().to_owned();
  let cli_bearer = format!("Bearer {cli_token}");
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("{files_path}/{file_id}"),
    Some(&cli_bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403, "CLI sessions must not delete files");
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("{files_path}/folders/{root_id}"),
    Some(&cli_bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403, "CLI sessions must not delete folders");
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("{files_path}/{file_id}/versions/2"),
    Some(&cli_bearer),
    None,
    None,
  )
  .await;
  assert_eq!(status, 403, "CLI sessions must not delete file versions");
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let url = format!("http://{}", listener.local_addr().unwrap());
  let serve_router = router.clone();
  let server = tokio::spawn(async move {
    axum::serve(listener, serve_router).await.unwrap();
  });

  let agent_tree = run_cli(
    url.clone(),
    agent.trim_start_matches("Bearer ").to_owned(),
    vec!["files".into(), project_id.clone(), "tree".into()],
  )
  .await;
  assert!(
    agent_tree.status.success(),
    "{}",
    String::from_utf8_lossy(&agent_tree.stderr)
  );
  let agent_tree: Value = serde_json::from_slice(&agent_tree.stdout).unwrap();
  assert_eq!(agent_tree["items"].as_array().unwrap().len(), 4);
  let denied_reveal = run_cli(
    url.clone(),
    agent.trim_start_matches("Bearer ").to_owned(),
    vec![
      "files".into(),
      project_id.clone(),
      "file".into(),
      "reveal".into(),
      "production/cluster/config".into(),
    ],
  )
  .await;
  assert!(!denied_reveal.status.success());
  assert!(!String::from_utf8_lossy(&denied_reveal.stdout).contains("apiVersion"));

  let cli_reveal = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "files".into(),
      project_id.clone(),
      "file".into(),
      "reveal".into(),
      "production/cluster/config".into(),
    ],
  )
  .await;
  assert!(
    cli_reveal.status.success(),
    "{}",
    String::from_utf8_lossy(&cli_reveal.stderr)
  );
  let cli_reveal: Value = serde_json::from_slice(&cli_reveal.stdout).unwrap();
  assert_eq!(cli_reveal["content"], "apiVersion: v1\n");

  let created_folder = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "files".into(),
      project_id.clone(),
      "folder".into(),
      "create".into(),
      "cli".into(),
    ],
  )
  .await;
  assert!(
    created_folder.status.success(),
    "{}",
    String::from_utf8_lossy(&created_folder.stderr)
  );
  let input = directory.path().join("cli.env");
  std::fs::write(&input, b"FROM_CLI=one\n").unwrap();
  let created_file = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "files".into(),
      project_id.clone(),
      "file".into(),
      "create".into(),
      "cli".into(),
      "settings".into(),
      "--kind".into(),
      "env".into(),
      "--input".into(),
      input.display().to_string(),
    ],
  )
  .await;
  assert!(
    created_file.status.success(),
    "{}",
    String::from_utf8_lossy(&created_file.stderr)
  );
  let created_file: Value = serde_json::from_slice(&created_file.stdout).unwrap();
  assert_eq!(created_file["version"], 1);

  let updated_input = directory.path().join("updated-kubeconfig");
  std::fs::write(&updated_input, b"apiVersion: v3\n").unwrap();
  let updated = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "files".into(),
      project_id.clone(),
      "file".into(),
      "update".into(),
      "production/cluster/config".into(),
      "--input".into(),
      updated_input.display().to_string(),
    ],
  )
  .await;
  assert!(
    updated.status.success(),
    "{}",
    String::from_utf8_lossy(&updated.stderr)
  );
  let versions = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "files".into(),
      project_id.clone(),
      "file".into(),
      "versions".into(),
      "production/cluster/config".into(),
    ],
  )
  .await;
  assert!(
    versions.status.success(),
    "{}",
    String::from_utf8_lossy(&versions.stderr)
  );
  let versions: Value = serde_json::from_slice(&versions.stdout).unwrap();
  assert!(
    versions
      .as_array()
      .unwrap()
      .iter()
      .any(|version| version["version"] == 2)
  );
  let rollback = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "files".into(),
      project_id.clone(),
      "file".into(),
      "rollback".into(),
      "production/cluster/config".into(),
      "1".into(),
      "--yes".into(),
    ],
  )
  .await;
  assert!(
    rollback.status.success(),
    "{}",
    String::from_utf8_lossy(&rollback.stderr)
  );
  let rollback: Value = serde_json::from_slice(&rollback.stdout).unwrap();
  assert_eq!(rollback["version"], 5);

  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("{files_path}/{file_id}/versions/2"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(
    status, 200,
    "the Admin UI can delete archived file versions"
  );
  let (status, _, _) = call(
    &router,
    "DELETE",
    &format!("{files_path}/{file_id}/versions/5"),
    Some(&cookie),
    Some(&csrf),
    None,
  )
  .await;
  assert_eq!(status, 409, "the current file version is retained");

  let (status, project, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"cli-version-test"})),
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
  let environment_id = environment["data"]["id"].as_str().unwrap();
  for value in ["first", "second"] {
    let (status, _, _) = call(
      &router,
      "PUT",
      &format!("/api/v1/environments/{environment_id}/secrets/API_KEY"),
      Some(&cookie),
      Some(&csrf),
      Some(json!({"value":value})),
    )
    .await;
    assert_eq!(status, 200);
  }
  let secret_versions = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "secret".into(),
      "versions".into(),
      environment_id.into(),
      "API_KEY".into(),
    ],
  )
  .await;
  assert!(
    secret_versions.status.success(),
    "{}",
    String::from_utf8_lossy(&secret_versions.stderr)
  );
  let secret_versions: Value = serde_json::from_slice(&secret_versions.stdout).unwrap();
  assert_eq!(secret_versions.as_array().unwrap().len(), 1);
  let secret_rollback = run_cli(
    url.clone(),
    cli_token.clone(),
    vec![
      "secret".into(),
      "rollback".into(),
      environment_id.into(),
      "API_KEY".into(),
      "1".into(),
      "--yes".into(),
    ],
  )
  .await;
  assert!(
    secret_rollback.status.success(),
    "{}",
    String::from_utf8_lossy(&secret_rollback.stderr)
  );
  let secret_rollback: Value = serde_json::from_slice(&secret_rollback.stdout).unwrap();
  assert_eq!(secret_rollback["version"], 3);

  let client_meta = json!({
    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
    "io.modelcontextprotocol/clientInfo":{"name":"integration","version":"1"},
    "io.modelcontextprotocol/clientCapabilities":{}
  });
  let messages = vec![
    json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":client_meta}}),
    json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":client_meta}}),
    json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"_meta":client_meta,"name":"dopbase_list_project_files","arguments":{"projectRef":project_id}}}),
    json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"_meta":client_meta,"name":"dopbase_list_secret_versions","arguments":{"environmentId":environment_id,"key":"API_KEY"}}}),
    json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"_meta":client_meta,"name":"dopbase_list_project_file_versions","arguments":{"projectRef":project_id,"fileId":file_id}}}),
  ];
  let mcp = run_mcp(
    url.clone(),
    agent.trim_start_matches("Bearer ").to_owned(),
    messages,
  )
  .await;
  assert!(
    mcp.status.success(),
    "{}",
    String::from_utf8_lossy(&mcp.stderr)
  );
  let mcp_output = String::from_utf8_lossy(&mcp.stdout);
  let responses = mcp_output
    .lines()
    .map(|line| serde_json::from_str::<Value>(line).unwrap())
    .collect::<Vec<_>>();
  assert_eq!(responses.len(), 5);
  assert!(
    responses[0]["result"]["instructions"]
      .as_str()
      .unwrap()
      .contains("Never ask for the Dopbase administrator password")
  );
  assert!(
    responses[1]["result"]["tools"]
      .as_array()
      .unwrap()
      .iter()
      .all(|tool| !tool["name"].as_str().unwrap_or_default().contains("reveal"))
  );
  assert!(!mcp_output.contains("apiVersion: v1"));
  assert!(!mcp_output.contains("FROM_CLI=one"));
  assert!(!mcp_output.contains("first"));
  assert!(!mcp_output.contains("second"));

  let (status, scoped_token, _) = call(
    &router,
    "POST",
    &format!("/api/v1/service-accounts/{account_id}/tokens"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"project-writer","access":"project","projectId":vault_project_id})),
  )
  .await;
  assert_eq!(status, 201);
  let scoped_token = scoped_token["data"]["plaintextToken"]
    .as_str()
    .unwrap()
    .to_owned();
  let created_environment = run_cli(
    url.clone(),
    scoped_token.clone(),
    vec![
      "env".into(),
      "create".into(),
      format!("{vault_project_id}/runtime"),
    ],
  )
  .await;
  assert!(
    created_environment.status.success(),
    "{}",
    String::from_utf8_lossy(&created_environment.stderr)
  );
  let created_environment: Value = serde_json::from_slice(&created_environment.stdout).unwrap();
  assert_eq!(created_environment["name"], "runtime");
  assert_eq!(created_environment["projectId"], vault_project_id);
  let messages = vec![
    json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":client_meta}}),
    json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":client_meta,"name":"dopbase_move_project_file","arguments":{"projectRef":vault_project_id,"fileId":file_id,"folderId":root_id}}}),
    json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"_meta":client_meta,"name":"dopbase_list_project_files","arguments":{"projectRef":vault_project_id}}}),
  ];
  let mcp = run_mcp(url.clone(), scoped_token, messages).await;
  assert!(
    mcp.status.success(),
    "{}",
    String::from_utf8_lossy(&mcp.stderr)
  );
  let responses = String::from_utf8_lossy(&mcp.stdout)
    .lines()
    .map(|line| serde_json::from_str::<Value>(line).unwrap())
    .collect::<Vec<_>>();
  assert_eq!(responses.len(), 3);
  let moved = &responses[1]["result"]["structuredContent"];
  assert_eq!(moved["id"], file_id);
  assert_eq!(moved["folderId"], root_id);
  let refreshed = &responses[2]["result"]["structuredContent"]["items"];
  assert!(refreshed.as_array().unwrap().iter().any(|entry| {
    entry["folder"]["id"] == root_id
      && entry["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| file["id"] == file_id && file["environmentId"] == vault_environment_id)
  }));
  assert!(!String::from_utf8_lossy(&mcp.stdout).contains("apiVersion: v1"));

  let moved_by_cli = run_cli(
    url.clone(),
    cli_token,
    vec![
      "files".into(),
      vault_project_id,
      "file".into(),
      "move".into(),
      file_id.clone(),
      "--to".into(),
      child_id.clone(),
    ],
  )
  .await;
  assert!(
    moved_by_cli.status.success(),
    "{}",
    String::from_utf8_lossy(&moved_by_cli.stderr)
  );
  let moved_by_cli: Value = serde_json::from_slice(&moved_by_cli.stdout).unwrap();
  assert_eq!(moved_by_cli["id"], file_id);
  assert_eq!(moved_by_cli["folderId"], child_id);

  server.abort();
  let _ = server.await;

  state.db.close().await;
}

async fn vault_row_counts(
  state: &app::state::AppState,
  project_id: &str,
) -> (i64, i64) {
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
  (folders, files)
}

#[tokio::test]
async fn tree_does_not_provision_the_project_root() {
  let (_directory, state, router) = fixture().await;
  let (cookie, csrf) = admin_session(&router, &state).await;
  let (status, project, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"read-only-tree"})),
  )
  .await;
  assert_eq!(status, 201, "{project}");
  let project_id = project["data"]["id"].as_str().unwrap().to_owned();
  let before = vault_row_counts(&state, &project_id).await;
  assert_eq!(before, (0, 0), "a new project has no Vault rows");

  let (status, tree, _) = call(
    &router,
    "GET",
    &format!("/api/v1/projects/{project_id}/files/tree"),
    Some(&cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200, "{tree}");
  assert_eq!(
    tree["data"],
    json!([]),
    "a project without a root has an empty tree"
  );

  let (status, folders, _) = call(
    &router,
    "GET",
    &format!("/api/v1/projects/{project_id}/files/folders"),
    Some(&cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200, "{folders}");
  assert_eq!(folders["data"], json!([]));
  assert_eq!(
    vault_row_counts(&state, &project_id).await,
    before,
    "reading the tree must not create the project root"
  );
}

#[tokio::test]
async fn project_references_prefer_the_id_over_a_name() {
  let (_directory, state, router) = fixture().await;
  let (cookie, csrf) = admin_session(&router, &state).await;
  let (status, first, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"named-project"})),
  )
  .await;
  assert_eq!(status, 201, "{first}");
  let id = first["data"]["id"].as_str().unwrap().to_owned();
  let (status, folder, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{id}/files/folders"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"owned-by-id"})),
  )
  .await;
  assert_eq!(status, 201, "{folder}");

  // A project may legally carry another project's ID as its name.
  let (status, second, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name": id})),
  )
  .await;
  assert_eq!(status, 201, "{second}");
  let second_id = second["data"]["id"].as_str().unwrap().to_owned();
  assert_ne!(second_id, id);

  let (status, resolved, _) = call(
    &router,
    "GET",
    &format!("/api/v1/projects/{id}"),
    Some(&cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200, "{resolved}");
  assert_eq!(resolved["data"]["id"], id);
  assert_eq!(resolved["data"]["name"], "named-project");

  let (status, tree, _) = call(
    &router,
    "GET",
    &format!("/api/v1/projects/{id}/files/tree"),
    Some(&cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200, "{tree}");
  assert!(
    tree["data"]
      .as_array()
      .unwrap()
      .iter()
      .any(|entry| entry["folder"]["name"] == "owned-by-id"),
    "the ID must address the project it belongs to: {tree}"
  );

  let (status, other, _) = call(
    &router,
    "GET",
    &format!("/api/v1/projects/{second_id}/files/tree"),
    Some(&cookie),
    None,
    None,
  )
  .await;
  assert_eq!(status, 200, "{other}");
  assert_eq!(other["data"], json!([]));
}

#[tokio::test]
async fn control_characters_are_rejected_in_vault_names() {
  let (_directory, state, router) = fixture().await;
  let (cookie, csrf) = admin_session(&router, &state).await;
  let (status, project, _) = call(
    &router,
    "POST",
    "/api/v1/projects",
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"control-chars"})),
  )
  .await;
  assert_eq!(status, 201, "{project}");
  let project_id = project["data"]["id"].as_str().unwrap().to_owned();

  let (status, body, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{project_id}/files/folders"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"ansi\u{1b}[31mred"})),
  )
  .await;
  assert_eq!(status, 422, "{body}");
  let message = body["error"]["VAULT_NAME_INVALID"]
    .as_str()
    .unwrap_or_else(|| panic!("expected VAULT_NAME_INVALID: {body}"));
  assert!(message.contains("control characters"), "{message}");

  let (status, folder, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{project_id}/files/folders"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"safe"})),
  )
  .await;
  assert_eq!(status, 201, "{folder}");
  let folder_id = folder["data"]["id"].as_str().unwrap();
  let (status, body, _) = call(
    &router,
    "POST",
    &format!("/api/v1/projects/{project_id}/files/folders/{folder_id}/files"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"line\nbreak","kind":"text","content":"value","encoding":"utf-8"})),
  )
  .await;
  assert_eq!(status, 422, "{body}");
  assert!(body["error"]["VAULT_NAME_INVALID"].is_string(), "{body}");

  let (status, body, _) = call(
    &router,
    "PUT",
    &format!("/api/v1/projects/{project_id}/files/folders/{folder_id}"),
    Some(&cookie),
    Some(&csrf),
    Some(json!({"name":"tab\tname"})),
  )
  .await;
  assert_eq!(status, 422, "{body}");
  assert!(body["error"]["VAULT_NAME_INVALID"].is_string(), "{body}");

  let files: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_files WHERE folder_id=?")
    .bind(folder_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap();
  assert_eq!(files, 0);
  let renamed: String = sqlx::query_scalar("SELECT name FROM vault_folders WHERE id=?")
    .bind(folder_id)
    .fetch_one(state.db.pool())
    .await
    .unwrap();
  assert_eq!(renamed, "safe");
}

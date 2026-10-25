use crate::cli::{
  client::{self, ApiClient},
  local_config::ResolvedServer,
};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use reqwest::Method;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
const LEGACY_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
const INSTRUCTIONS: &str = "MCP can read project metadata and, with a project-scoped token, create, version, and move typed project files. File IDs stay stable after moves; call dopbase_list_project_files to refresh the hierarchy. Secret and project-file contents are never returned. Never ask for the Dopbase administrator password; it cannot enable MCP content access. If content is needed, explain this limitation and direct the user to the Admin UI. Deletion is available only in the Admin UI.";

#[derive(Subcommand, Debug)]
pub enum McpCommand {
  /// Run the MCP server on stdin/stdout; file tools accept writes but never return secret values.
  #[command(after_help = SERVE_HELP)]
  Serve(McpServeArgs),
}

pub(crate) const HELP: &str = "\
Examples:
  dopbase mcp serve

Requires a dedicated AI-agent token in DOPBASE_TOKEN.
";

const SERVE_HELP: &str = "\
Examples:
  DOPBASE_TOKEN=<agent-token> dopbase mcp serve
";

#[derive(Args, Debug, Default)]
pub struct McpServeArgs {}

pub async fn execute(
  command: McpCommand,
  server: &ResolvedServer,
) -> Result<i32> {
  match command {
    McpCommand::Serve(_) => {
      let credential = client::credential(server)?;
      let Some(token) = credential.token.as_deref() else {
        bail!("MCP requires a dedicated AI agent token. Set DOPBASE_TOKEN.");
      };
      if !token.starts_with(crate::constants::tokens::AGENT_TOKEN_PREFIX)
        && !token.starts_with(crate::constants::tokens::PROJECT_AGENT_TOKEN_PREFIX)
      {
        bail!(
          "MCP requires an AI agent token. Create one in Dopbase Admin → Users → Add AI agent, then set DOPBASE_TOKEN."
        );
      }
      let api = client::authenticated_client(server, credential)?;
      serve_stdio(api).await?;
      Ok(0)
    }
  }
}

async fn serve_stdio(api: ApiClient) -> Result<()> {
  let mut input = BufReader::new(tokio::io::stdin()).lines();
  let mut output = tokio::io::stdout();
  let mut mode = ProtocolMode::Undecided;
  while let Some(line) = input
    .next_line()
    .await
    .context("failed to read MCP stdin")?
  {
    let request: Value = match serde_json::from_str(&line) {
      Ok(value) => value,
      Err(error) => {
        write_message(&mut output, json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("Parse error: {error}")}})).await?;
        continue;
      }
    };
    let Some(id) = request.get("id").cloned() else {
      // MCP notifications, including notifications/initialized, have no response.
      continue;
    };
    let response = handle_request(&api, &request, id.clone(), &mut mode).await;
    write_message(&mut output, response).await?;
  }
  Ok(())
}

#[derive(Clone, Debug)]
enum ProtocolMode {
  Undecided,
  Legacy,
  Modern,
}

async fn handle_request(
  api: &ApiClient,
  request: &Value,
  id: Value,
  mode: &mut ProtocolMode,
) -> Value {
  let method = request
    .get("method")
    .and_then(Value::as_str)
    .unwrap_or_default();
  if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
    return rpc_error(id, -32600, "Invalid JSON-RPC request", Value::Null);
  }
  let params = request.get("params").unwrap_or(&Value::Null);
  if method == "initialize" {
    if !matches!(mode, ProtocolMode::Undecided) {
      return rpc_error(
        id,
        -32600,
        "MCP lifecycle is already established",
        Value::Null,
      );
    }
    let requested = params
      .get("protocolVersion")
      .and_then(Value::as_str)
      .unwrap_or_default();
    let Some(version) = LEGACY_PROTOCOL_VERSIONS
      .iter()
      .find(|version| **version == requested)
    else {
      return rpc_error(
        id,
        -32602,
        "No mutually supported legacy MCP protocol version",
        json!({"supported":LEGACY_PROTOCOL_VERSIONS,"requested":requested}),
      );
    };
    *mode = ProtocolMode::Legacy;
    return rpc_result(
      id,
      json!({
        "protocolVersion":version,
        "capabilities":{"tools":{"listChanged":false}},
        "serverInfo":{"name":"dopbase","version":env!("CARGO_PKG_VERSION")},
        "instructions":INSTRUCTIONS
      }),
    );
  }

  if method == "server/discover" {
    let Some(version) = modern_request_version(params) else {
      return rpc_error(
        id,
        -32602,
        "server/discover requires modern MCP request metadata",
        Value::Null,
      );
    };
    if version != MODERN_PROTOCOL_VERSION {
      return unsupported_version(id, version);
    }
    *mode = ProtocolMode::Modern;
    return rpc_result(
      id,
      json!({
        "resultType":"complete",
        "supportedVersions":[MODERN_PROTOCOL_VERSION],
        "capabilities":{"tools":{}},
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"dopbase","version":env!("CARGO_PKG_VERSION")}},
        "instructions":INSTRUCTIONS,
        "ttlMs":30000,
        "cacheScope":"private"
      }),
    );
  }

  let modern = match mode {
    ProtocolMode::Legacy => false,
    ProtocolMode::Modern => {
      let Some(version) = modern_request_version(params) else {
        return rpc_error(
          id,
          -32602,
          "Modern MCP requests must include protocol metadata",
          Value::Null,
        );
      };
      if version != MODERN_PROTOCOL_VERSION {
        return unsupported_version(id, version);
      }
      true
    }
    ProtocolMode::Undecided => {
      let Some(version) = modern_request_version(params) else {
        return rpc_error(
          id,
          -32002,
          "Call server/discover or initialize before sending MCP requests",
          Value::Null,
        );
      };
      if version != MODERN_PROTOCOL_VERSION {
        return unsupported_version(id, version);
      }
      *mode = ProtocolMode::Modern;
      true
    }
  };

  let result = match method {
    "ping" => json!({}),
    "tools/list" => {
      let mut result = json!({"tools":tools()});
      if modern {
        result["resultType"] = json!("complete");
        result["ttlMs"] = json!(30000);
        result["cacheScope"] = json!("private");
      }
      result
    }
    "tools/call" => {
      let result = call_tool(api, params).await;
      if modern {
        let mut result = result;
        result["resultType"] = json!("complete");
        result
      } else {
        result
      }
    }
    _ => return rpc_error(id, -32601, "Method not found", Value::Null),
  };
  rpc_result(id, result)
}

fn modern_request_version(params: &Value) -> Option<&str> {
  let meta = params.get("_meta")?.as_object()?;
  let version = meta
    .get("io.modelcontextprotocol/protocolVersion")?
    .as_str()?;
  let client_info = meta
    .get("io.modelcontextprotocol/clientInfo")?
    .as_object()?;
  if client_info.get("name")?.as_str()?.is_empty()
    || client_info.get("version")?.as_str()?.is_empty()
  {
    return None;
  }
  meta
    .get("io.modelcontextprotocol/clientCapabilities")?
    .as_object()?;
  Some(version)
}

fn unsupported_version(
  id: Value,
  requested: &str,
) -> Value {
  rpc_error(
    id,
    -32022,
    "Unsupported protocol version",
    json!({"supported":[MODERN_PROTOCOL_VERSION],"requested":requested}),
  )
}

fn rpc_result(
  id: Value,
  result: Value,
) -> Value {
  json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn rpc_error(
  id: Value,
  code: i64,
  message: &str,
  data: Value,
) -> Value {
  let mut error = json!({"code":code,"message":message});
  if !data.is_null() {
    error["data"] = data;
  }
  json!({"jsonrpc":"2.0","id":id,"error":error})
}

fn tools() -> Vec<Value> {
  vec![
    json!({"name":"dopbase_list_projects","title":"List Dopbase projects","description":"List project names and metadata. Secret values are not returned.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    json!({"name":"dopbase_list_environments","title":"List project environments","description":"List environment names and metadata for one project. Secret values are not returned.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1,"description":"Project name or ID."}},"required":["projectRef"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    json!({"name":"dopbase_list_secret_metadata","title":"List secret metadata","description":"List secret keys, current versions, and timestamps for one environment. Secret values are never returned.","inputSchema":{"type":"object","properties":{"environmentId":{"type":"string","minLength":1,"description":"Dopbase environment ID."}},"required":["environmentId"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    json!({"name":"dopbase_list_secret_versions","title":"List secret version metadata","description":"List retained version numbers and timestamps for one secret. Secret values are never returned.","inputSchema":{"type":"object","properties":{"environmentId":{"type":"string","minLength":1},"key":{"type":"string","minLength":1}},"required":["environmentId","key"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    json!({"name":"dopbase_list_project_files","title":"List project files","description":"List folder hierarchy and typed-file metadata for one project. File contents are never returned.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1,"description":"Project name or ID."}},"required":["projectRef"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    json!({"name":"dopbase_list_project_file_versions","title":"List project file version metadata","description":"List retained version numbers and encoding metadata. File contents are never returned.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1},"fileId":{"type":"string","minLength":1}},"required":["projectRef","fileId"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    json!({"name":"dopbase_create_project_folder","title":"Create project folder","description":"Create a folder in a project. Omit parentFolderId for the project root; omit environmentId to inherit the parent folder tag. Deletion remains UI-only.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1},"name":{"type":"string","minLength":1},"parentFolderId":{"type":"string","minLength":1},"environmentId":{"type":"string","minLength":1}},"required":["projectRef","name"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
    json!({"name":"dopbase_create_project_file","title":"Create encrypted project file","description":"Create a typed encrypted file. Content is submitted for encryption but only metadata is returned. An optional environmentId overrides the inherited folder environment tag; omit it to inherit or remain shared.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1},"folderId":{"type":"string","minLength":1},"name":{"type":"string","minLength":1},"kind":{"type":"string","enum":["secret","env","kubeconfig","sshPrivateKey","certificate","text"]},"content":{"type":"string"},"environmentId":{"type":"string","minLength":1}},"required":["projectRef","folderId","name","kind","content"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
    json!({"name":"dopbase_move_project_file","title":"Move project file","description":"Move a file to another folder without changing its ID, content, or versions. Refresh with dopbase_list_project_files; the response includes the same file ID and its new folder ID.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1},"fileId":{"type":"string","minLength":1},"folderId":{"type":"string","minLength":1}},"required":["projectRef","fileId","folderId"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    json!({"name":"dopbase_update_project_file","title":"Save new project file version","description":"Update encrypted file content, creating a new version. Only metadata is returned.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1},"fileId":{"type":"string","minLength":1},"content":{"type":"string"},"encoding":{"type":"string","enum":["utf-8","base64"]}},"required":["projectRef","fileId","content"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
    json!({"name":"dopbase_restore_project_file_version","title":"Restore project file version","description":"Restore a retained version as a new current version. History is preserved and only metadata is returned.","inputSchema":{"type":"object","properties":{"projectRef":{"type":"string","minLength":1},"fileId":{"type":"string","minLength":1},"version":{"type":"integer","minimum":1}},"required":["projectRef","fileId","version"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
  ]
}

async fn call_tool(
  api: &ApiClient,
  params: &Value,
) -> Value {
  let name = params
    .get("name")
    .and_then(Value::as_str)
    .unwrap_or_default();
  let arguments = match params.get("arguments") {
    None => json!({}),
    Some(value) if value.is_object() => value.clone(),
    Some(_) => return tool_error("arguments must be a JSON object"),
  };
  let Some(arguments) = arguments.as_object() else {
    return tool_error("arguments must be a JSON object");
  };
  let result = match name {
    "dopbase_list_projects" => {
      if !arguments.is_empty() {
        return tool_error("dopbase_list_projects accepts no arguments");
      }
      api
        .request(
          Method::GET,
          crate::constants::api::projects::COLLECTION,
          None,
        )
        .await
    }
    "dopbase_list_environments" => {
      if !arguments.keys().all(|key| key == "projectRef") {
        return tool_error("dopbase_list_environments accepts only projectRef");
      }
      let Some(project_ref) = arguments
        .get("projectRef")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
      else {
        return tool_error("projectRef is required and must be a non-empty string");
      };
      api
        .request(
          Method::GET,
          &crate::constants::api::projects::environments(&encode_path_segment(project_ref)),
          None,
        )
        .await
    }
    "dopbase_list_secret_metadata" => {
      if !arguments.keys().all(|key| key == "environmentId") {
        return tool_error("dopbase_list_secret_metadata accepts only environmentId");
      }
      let Some(environment_id) = arguments
        .get("environmentId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
      else {
        return tool_error("environmentId is required and must be a non-empty string");
      };
      api
        .request(
          Method::GET,
          &crate::constants::api::secrets::collection(&encode_path_segment(environment_id)),
          None,
        )
        .await
    }
    "dopbase_list_secret_versions" => {
      if !arguments
        .keys()
        .all(|key| key == "environmentId" || key == "key")
      {
        return tool_error("dopbase_list_secret_versions accepts only environmentId and key");
      }
      let (Some(environment_id), Some(secret_key)) = (
        arguments
          .get("environmentId")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("key")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
      ) else {
        return tool_error("environmentId and key are required non-empty strings");
      };
      api
        .request(
          Method::GET,
          &crate::constants::api::secrets::versions(
            &encode_path_segment(environment_id),
            &encode_path_segment(secret_key),
          ),
          None,
        )
        .await
    }
    "dopbase_list_project_files" => {
      if !arguments.keys().all(|key| key == "projectRef") {
        return tool_error("dopbase_list_project_files accepts only projectRef");
      }
      let Some(project_ref) = arguments
        .get("projectRef")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
      else {
        return tool_error("projectRef is required and must be a non-empty string");
      };
      api
        .request(
          Method::GET,
          &crate::constants::api::vault::tree(&encode_path_segment(project_ref)),
          None,
        )
        .await
        .map(response_data)
    }
    "dopbase_list_project_file_versions" => {
      if !arguments
        .keys()
        .all(|key| key == "projectRef" || key == "fileId")
      {
        return tool_error("dopbase_list_project_file_versions accepts only projectRef and fileId");
      }
      let (Some(project_ref), Some(file_id)) = (
        arguments
          .get("projectRef")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("fileId")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
      ) else {
        return tool_error("projectRef and fileId are required non-empty strings");
      };
      api
        .request(
          Method::GET,
          &crate::constants::api::vault::file_versions(
            &encode_path_segment(project_ref),
            &encode_path_segment(file_id),
          ),
          None,
        )
        .await
    }
    "dopbase_create_project_folder" => {
      if !arguments.keys().all(|key| {
        matches!(
          key.as_str(),
          "projectRef" | "name" | "parentFolderId" | "environmentId"
        )
      }) {
        return tool_error(
          "dopbase_create_project_folder accepts projectRef, name, and optional parentFolderId and environmentId",
        );
      }
      let (Some(project_ref), Some(name)) = (
        arguments
          .get("projectRef")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("name")
          .and_then(Value::as_str)
          .filter(|value| !value.trim().is_empty()),
      ) else {
        return tool_error("projectRef and name are required non-empty strings");
      };
      let parent_id = match arguments.get("parentFolderId") {
        Some(value) => match value.as_str().filter(|value| !value.is_empty()) {
          Some(value) => Some(value),
          None => return tool_error("parentFolderId must be a non-empty string when provided"),
        },
        None => None,
      };
      let environment_id = match arguments.get("environmentId") {
        Some(value) => match value.as_str().filter(|value| !value.is_empty()) {
          Some(value) => Some(value),
          None => return tool_error("environmentId must be a non-empty string when provided"),
        },
        None => None,
      };
      api
        .request(
          Method::POST,
          &crate::constants::api::vault::folders(&encode_path_segment(project_ref)),
          Some(json!({"name":name,"parentId":parent_id,"environmentId":environment_id})),
        )
        .await
    }
    "dopbase_create_project_file" => {
      if !arguments.keys().all(|key| {
        matches!(
          key.as_str(),
          "projectRef" | "folderId" | "name" | "kind" | "content" | "environmentId"
        )
      }) {
        return tool_error(
          "dopbase_create_project_file accepts projectRef, folderId, name, kind, content, and optional environmentId",
        );
      }
      let (Some(project_ref), Some(folder_id), Some(name), Some(kind), Some(content)) = (
        arguments
          .get("projectRef")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("folderId")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("name")
          .and_then(Value::as_str)
          .filter(|value| !value.trim().is_empty()),
        arguments.get("kind").and_then(Value::as_str),
        arguments.get("content").and_then(Value::as_str),
      ) else {
        return tool_error("projectRef, folderId, name, kind, and content are required");
      };
      let environment_id = match arguments.get("environmentId") {
        Some(value) => match value.as_str().filter(|value| !value.is_empty()) {
          Some(value) => Some(value),
          None => return tool_error("environmentId must be a non-empty string when provided"),
        },
        None => None,
      };
      api
        .request(
          Method::POST,
          &crate::constants::api::vault::folder_files(
            &encode_path_segment(project_ref),
            &encode_path_segment(folder_id),
          ),
          Some(json!({"name":name,"kind":kind,"content":content,"environmentId":environment_id})),
        )
        .await
    }
    "dopbase_move_project_file" => {
      if !arguments
        .keys()
        .all(|key| matches!(key.as_str(), "projectRef" | "fileId" | "folderId"))
      {
        return tool_error(
          "dopbase_move_project_file accepts only projectRef, fileId, and folderId",
        );
      }
      let (Some(project_ref), Some(file_id), Some(folder_id)) = (
        arguments
          .get("projectRef")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("fileId")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("folderId")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
      ) else {
        return tool_error("projectRef, fileId, and folderId are required non-empty strings");
      };
      api
        .request(
          Method::POST,
          &crate::constants::api::vault::file_move(
            &encode_path_segment(project_ref),
            &encode_path_segment(file_id),
          ),
          Some(json!({"folderId":folder_id})),
        )
        .await
    }
    "dopbase_update_project_file" => {
      if !arguments.keys().all(|key| {
        matches!(
          key.as_str(),
          "projectRef" | "fileId" | "content" | "encoding"
        )
      }) {
        return tool_error(
          "dopbase_update_project_file accepts projectRef, fileId, content, and optional encoding",
        );
      }
      let (Some(project_ref), Some(file_id), Some(content)) = (
        arguments
          .get("projectRef")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("fileId")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments.get("content").and_then(Value::as_str),
      ) else {
        return tool_error("projectRef, fileId, and content are required");
      };
      let encoding = match arguments.get("encoding") {
        Some(value) => match value
          .as_str()
          .filter(|value| matches!(*value, "utf-8" | "base64"))
        {
          Some(value) => Some(value),
          None => return tool_error("encoding must be utf-8 or base64"),
        },
        None => None,
      };
      let mut body = json!({"content":content});
      if let Some(encoding) = encoding {
        body["encoding"] = json!(encoding);
      }
      api
        .request(
          Method::PUT,
          &crate::constants::api::vault::file(
            &encode_path_segment(project_ref),
            &encode_path_segment(file_id),
          ),
          Some(body),
        )
        .await
    }
    "dopbase_restore_project_file_version" => {
      if !arguments
        .keys()
        .all(|key| matches!(key.as_str(), "projectRef" | "fileId" | "version"))
      {
        return tool_error(
          "dopbase_restore_project_file_version accepts only projectRef, fileId, and version",
        );
      }
      let (Some(project_ref), Some(file_id), Some(version)) = (
        arguments
          .get("projectRef")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("fileId")
          .and_then(Value::as_str)
          .filter(|value| !value.is_empty()),
        arguments
          .get("version")
          .and_then(Value::as_i64)
          .filter(|value| *value > 0),
      ) else {
        return tool_error("projectRef, fileId, and a positive version are required");
      };
      api
        .request(
          Method::POST,
          &crate::constants::api::vault::rollback_file(
            &encode_path_segment(project_ref),
            &encode_path_segment(file_id),
            version,
          ),
          None,
        )
        .await
    }
    _ => return tool_error("Unknown Dopbase tool"),
  };
  match result {
    Ok(data) => {
      let data = match data {
        Value::Array(items) => json!({"items":items}),
        value => value,
      };
      json!({"content":[{"type":"text","text":data.to_string()}],"structuredContent":data,"isError":false})
    }
    Err(error) => tool_error(&error.to_string()),
  }
}

fn response_data(value: Value) -> Value {
  value.get("data").cloned().unwrap_or(value)
}

fn encode_path_segment(value: &str) -> String {
  let mut encoded = String::with_capacity(value.len());
  for byte in value.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      encoded.push(char::from(byte));
    } else {
      use std::fmt::Write as _;
      let _ = write!(encoded, "%{byte:02X}");
    }
  }
  encoded
}

fn tool_error(message: &str) -> Value {
  json!({"content":[{"type":"text","text":message}],"isError":true})
}

async fn write_message(
  output: &mut tokio::io::Stdout,
  message: Value,
) -> Result<()> {
  let mut bytes = serde_json::to_vec(&message)?;
  bytes.push(b'\n');
  output
    .write_all(&bytes)
    .await
    .context("failed to write MCP response")?;
  output
    .flush()
    .await
    .context("failed to flush MCP response")?;
  Ok(())
}

use super::args::{FileCommand, FolderCommand, VaultCommand};
use crate::cli::{client, local_config, output, prompt};
use crate::constants::api as api_paths;
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
  collections::HashMap,
  fs,
  io::{self, Read, Write},
  path::Path,
};
use zeroize::Zeroizing;

const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) async fn execute(
  project_ref: &str,
  command: VaultCommand,
  server: &local_config::ResolvedServer,
  json_output: bool,
) -> Result<i32> {
  let api = match &command {
    VaultCommand::Tree
    | VaultCommand::File {
      command: FileCommand::List { .. } | FileCommand::Show { .. } | FileCommand::Versions { .. },
    } => client::metadata_client(server).await?,
    VaultCommand::File {
      command:
        FileCommand::Create { .. }
        | FileCommand::Move { .. }
        | FileCommand::SetEnvironment { .. }
        | FileCommand::Update { .. }
        | FileCommand::Rollback { .. },
    } => client::secret_writer_client(server).await?,
    VaultCommand::Folder {
      command: FolderCommand::Create { .. } | FolderCommand::SetEnvironment { .. },
    } => client::secret_writer_client(server).await?,
    VaultCommand::File {
      command: FileCommand::Reveal { .. },
    } => client::human_client(server).await?,
    _ => client::human_client(server).await?,
  };
  match command {
    VaultCommand::Tree => tree(&api, project_ref, json_output).await?,
    VaultCommand::Folder { command } => {
      folder_command(&api, project_ref, command, json_output).await?
    }
    VaultCommand::File { command } => file_command(&api, project_ref, command, json_output).await?,
  }
  Ok(0)
}

async fn tree(
  api: &client::ApiClient,
  project_ref: &str,
  json_output: bool,
) -> Result<()> {
  let folders = load_tree(api, project_ref).await?;
  let folder_items = output::array(&folders);
  let mut names = HashMap::<String, (String, Option<String>, bool)>::new();
  for entry in folder_items {
    let folder = entry.get("folder").unwrap_or(entry);
    let id = output::string(folder, "id");
    if id != "-" {
      names.insert(
        id,
        (
          output::string(folder, "name"),
          folder
            .get("parentId")
            .and_then(Value::as_str)
            .map(str::to_owned),
          folder
            .get("isRoot")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ),
      );
    }
  }
  let mut rows = Vec::new();
  for entry in folder_items {
    let folder = entry.get("folder").unwrap_or(entry);
    let id = output::string(folder, "id");
    let path = folder_path(&id, &names)?;
    let display_path = if folder.get("isRoot").and_then(Value::as_bool) == Some(true) {
      "Project root"
    } else {
      &path
    };
    rows.push(json!({"path":display_path,"type":"folder","id":id,"version":Value::Null}));
    for file in output::array(entry.get("files").unwrap_or(&Value::Null)) {
      let name = output::string(file, "name");
      rows.push(json!({
        "path":if path.is_empty() { name } else { format!("{path}/{name}") },
        "type":output::string(file,"kind"),
        "id":output::string(file,"id"),
        "version":file.get("version").cloned().unwrap_or(Value::Null),
      }));
    }
  }
  if json_output {
    output::print_json(&json!({"items":rows}))?;
  } else {
    let table = rows
      .iter()
      .map(|item| {
        vec![
          output::string(item, "path"),
          output::string(item, "type"),
          item
            .get("version")
            .and_then(Value::as_i64)
            .map_or_else(|| "-".into(), |v| v.to_string()),
          output::string(item, "id"),
        ]
      })
      .collect::<Vec<_>>();
    output::print_table(
      &["PATH", "TYPE", "VERSION", "ID"],
      &table,
      "Vault is empty. Create a folder with: dopbase files <PROJECT_REF> folder create <name>",
      &format!("{} item(s)", table.len()),
    );
  }
  Ok(())
}

async fn load_tree(
  api: &client::ApiClient,
  project_ref: &str,
) -> Result<Value> {
  api
    .request(
      Method::GET,
      &api_paths::vault::tree(&encode_path_segment(project_ref)),
      None,
    )
    .await
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

async fn resolve_or_create_environment(
  api: &client::ApiClient,
  project_ref: &str,
  name: &str,
) -> Result<String> {
  let path = environment_list_path(project_ref);
  let environments = api.request(Method::GET, &path, None).await?;
  if let Some(environment) = output::array(&environments)
    .iter()
    .find(|environment| output::string(environment, "name").eq_ignore_ascii_case(name.trim()))
  {
    return Ok(output::string(environment, "id"));
  }
  let create_path = api_paths::projects::environments(&encode_path_segment(project_ref));
  let created = api
    .request(
      Method::POST,
      &create_path,
      Some(json!({"name":name.trim()})),
    )
    .await?;
  let id = output::string(&created, "id");
  if id == "-" {
    bail!("environment creation response did not contain an ID");
  }
  Ok(id)
}

fn environment_list_path(project_ref: &str) -> String {
  api_paths::environments::list(Some(&encode_path_segment(project_ref)))
}

async fn resolve_folder_reference(
  api: &client::ApiClient,
  project_ref: &str,
  reference: &str,
) -> Result<String> {
  let tree = load_tree(api, project_ref).await?;
  let entries = output::array(&tree);
  let mut folders = HashMap::<String, (String, Option<String>, bool)>::new();
  for entry in entries {
    let folder = entry.get("folder").unwrap_or(entry);
    let id = output::string(folder, "id");
    if id != "-" {
      folders.insert(
        id,
        (
          output::string(folder, "name"),
          folder
            .get("parentId")
            .and_then(Value::as_str)
            .map(str::to_owned),
          folder
            .get("isRoot")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ),
      );
    }
  }
  for id in folders.keys() {
    if id == reference || folder_path(id, &folders)? == reference {
      return Ok(id.clone());
    }
  }
  bail!(
    "Vault folder `{reference}` was not found. Use `dopbase files <PROJECT_REF> tree` to list paths and IDs."
  )
}

async fn resolve_file_reference(
  api: &client::ApiClient,
  project_ref: &str,
  reference: &str,
) -> Result<String> {
  let tree = load_tree(api, project_ref).await?;
  let entries = output::array(&tree);
  let mut folders = HashMap::<String, (String, Option<String>, bool)>::new();
  for entry in entries {
    let folder = entry.get("folder").unwrap_or(entry);
    let id = output::string(folder, "id");
    if id != "-" {
      folders.insert(
        id,
        (
          output::string(folder, "name"),
          folder
            .get("parentId")
            .and_then(Value::as_str)
            .map(str::to_owned),
          folder
            .get("isRoot")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ),
      );
    }
  }
  for entry in entries {
    let folder = entry.get("folder").unwrap_or(entry);
    let folder_id = output::string(folder, "id");
    let folder_path = folder_path(&folder_id, &folders)?;
    for file in output::array(entry.get("files").unwrap_or(&Value::Null)) {
      let id = output::string(file, "id");
      let path = format!("{folder_path}/{}", output::string(file, "name"));
      if id == reference || path == reference {
        return Ok(id);
      }
    }
  }
  bail!(
    "Vault file `{reference}` was not found. Use `dopbase files <PROJECT_REF> tree` to list paths and IDs."
  )
}

fn folder_path(
  id: &str,
  folders: &HashMap<String, (String, Option<String>, bool)>,
) -> Result<String> {
  let mut path = Vec::new();
  let mut current = Some(id.to_owned());
  let mut visited = std::collections::HashSet::new();
  while let Some(folder_id) = current {
    if !visited.insert(folder_id.clone()) {
      bail!("Vault folder hierarchy contains a cycle");
    }
    let (name, parent, is_root) = folders
      .get(&folder_id)
      .context("Vault folder response omitted a referenced parent")?;
    if !is_root {
      path.push(name.as_str());
    }
    current = parent.clone();
  }
  path.reverse();
  Ok(path.join("/"))
}

async fn folder_command(
  api: &client::ApiClient,
  project_ref: &str,
  command: FolderCommand,
  json_output: bool,
) -> Result<()> {
  match command {
    FolderCommand::Create { name, parent } => {
      let parent = match parent {
        Some(reference) => Some(resolve_folder_reference(api, project_ref, &reference).await?),
        None => None,
      };
      let result = api
        .request(
          Method::POST,
          &api_paths::vault::folders(&encode_path_segment(project_ref)),
          Some(json!({"name":name,"parentId":parent})),
        )
        .await?;
      print_result(
        &result,
        json_output,
        &format!("Created Vault folder {}.", output::string(&result, "name")),
      )?;
    }
    FolderCommand::Move {
      id: reference,
      parent,
      root,
      name,
    } => {
      let id = resolve_folder_reference(api, project_ref, &reference).await?;
      let existing = api
        .request(
          Method::GET,
          &api_paths::vault::folder(&encode_path_segment(project_ref), &id),
          None,
        )
        .await?;
      let name = name.unwrap_or_else(|| output::string(&existing, "name"));
      let parent_id = if root {
        None
      } else {
        match parent {
          Some(reference) => Some(resolve_folder_reference(api, project_ref, &reference).await?),
          None => existing
            .get("parentId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        }
      };
      let result = api
        .request(
          Method::PUT,
          &api_paths::vault::folder(&encode_path_segment(project_ref), &id),
          Some(json!({"name":name,"parentId":parent_id})),
        )
        .await?;
      print_result(
        &result,
        json_output,
        &format!("Updated Vault folder {}.", output::string(&result, "name")),
      )?;
    }
    FolderCommand::SetEnvironment {
      id: reference,
      environment,
      clear,
    } => {
      let id = resolve_folder_reference(api, project_ref, &reference).await?;
      let environment_id = if clear {
        None
      } else {
        match environment {
          Some(name) => Some(resolve_or_create_environment(api, project_ref, &name).await?),
          None => None,
        }
      };
      let result = api
        .request(
          Method::PUT,
          &api_paths::vault::folder_environment(&encode_path_segment(project_ref), &id),
          Some(json!({"environmentId":environment_id})),
        )
        .await?;
      print_result(
        &result,
        json_output,
        if clear {
          "Cleared the Vault folder environment tag."
        } else {
          "Assigned the Vault folder environment tag."
        },
      )?;
    }
    FolderCommand::Delete { id: reference, yes } => {
      let id = resolve_folder_reference(api, project_ref, &reference).await?;
      prompt::confirm(&format!("Delete empty Vault folder {id}?"), yes)?;
      let result = api
        .request(
          Method::DELETE,
          &api_paths::vault::folder(&encode_path_segment(project_ref), &id),
          None,
        )
        .await?;
      print_result(&result, json_output, &format!("Deleted Vault folder {id}."))?;
    }
  }
  Ok(())
}

async fn file_command(
  api: &client::ApiClient,
  project_ref: &str,
  command: FileCommand,
  json_output: bool,
) -> Result<()> {
  match command {
    FileCommand::List {
      folder_id: reference,
    } => {
      let folder_id = resolve_folder_reference(api, project_ref, &reference).await?;
      let data = api
        .request(
          Method::GET,
          &api_paths::vault::folder_files(&encode_path_segment(project_ref), &folder_id),
          None,
        )
        .await?;
      if json_output {
        output::print_json(&data)?;
      } else {
        let rows = output::array(&data)
          .iter()
          .map(|file| {
            vec![
              output::string(file, "name"),
              output::string(file, "kind"),
              file
                .get("version")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                .to_string(),
              output::string(file, "id"),
              output::timestamp(file, "updatedAt"),
            ]
          })
          .collect::<Vec<_>>();
        output::print_table(
          &["NAME", "TYPE", "VERSION", "ID", "UPDATED"],
          &rows,
          "No files in this folder.",
          &format!("{} file(s)", rows.len()),
        );
      }
    }
    FileCommand::Create {
      folder_id: reference,
      name,
      kind,
      input,
      stdin,
      environment,
    } => {
      let folder_id = resolve_folder_reference(api, project_ref, &reference).await?;
      let (content, encoding) = read_input(input.as_deref(), stdin)?;
      let environment_id = match environment {
        Some(name) if !name.trim().is_empty() => {
          Some(resolve_or_create_environment(api, project_ref, &name).await?)
        }
        _ => None,
      };
      let result = api.request(Method::POST, &api_paths::vault::folder_files(&encode_path_segment(project_ref), &folder_id), Some(json!({"name":name,"kind":kind.api_value(),"content":content.as_str(),"encoding":encoding,"environmentId":environment_id}))).await?;
      print_result(
        &result,
        json_output,
        &format!(
          "Created encrypted Vault file {}.",
          output::string(&result, "name")
        ),
      )?;
    }
    FileCommand::Move {
      file_id: file_reference,
      to,
    } => {
      let file_id = resolve_file_reference(api, project_ref, &file_reference).await?;
      let folder_id = resolve_folder_reference(api, project_ref, &to).await?;
      let result = api
        .request(
          Method::POST,
          &api_paths::vault::file_move(&encode_path_segment(project_ref), &file_id),
          Some(json!({"folderId":folder_id})),
        )
        .await?;
      print_result(
        &result,
        json_output,
        &format!(
          "Moved Vault file {}; its ID and version history are unchanged.",
          output::string(&result, "id")
        ),
      )?;
    }
    FileCommand::SetEnvironment {
      file_id: reference,
      environment,
      clear,
    } => {
      let file_id = resolve_file_reference(api, project_ref, &reference).await?;
      let environment_id = if clear {
        None
      } else {
        match environment {
          Some(name) => Some(resolve_or_create_environment(api, project_ref, &name).await?),
          None => None,
        }
      };
      let result = api
        .request(
          Method::PUT,
          &api_paths::vault::file_environment(&encode_path_segment(project_ref), &file_id),
          Some(json!({"environmentId":environment_id})),
        )
        .await?;
      print_result(
        &result,
        json_output,
        if clear {
          "Cleared the Vault file environment tag."
        } else {
          "Assigned the Vault file environment tag."
        },
      )?;
    }
    FileCommand::Show { file_id: reference } => {
      let file_id = resolve_file_reference(api, project_ref, &reference).await?;
      let result = api
        .request(
          Method::GET,
          &api_paths::vault::file(&encode_path_segment(project_ref), &file_id),
          None,
        )
        .await?;
      if json_output {
        output::print_json(&result)?;
      } else {
        output::print_fields(&[
          ("Name:", output::string(&result, "name")),
          ("Type:", output::string(&result, "kind")),
          ("Folder ID:", output::string(&result, "folderId")),
          (
            "Version:",
            result
              .get("version")
              .and_then(Value::as_i64)
              .unwrap_or_default()
              .to_string(),
          ),
          ("Encoding:", output::string(&result, "encoding")),
          ("Updated:", output::timestamp(&result, "updatedAt")),
        ]);
      }
    }
    FileCommand::Reveal { file_id: reference } => {
      let file_id = resolve_file_reference(api, project_ref, &reference).await?;
      let mut result = api
        .request(
          Method::POST,
          &api_paths::vault::reveal_file(&encode_path_segment(project_ref), &file_id),
          None,
        )
        .await?;
      if json_output {
        output::print_json(&result)?;
      } else {
        let encoding = output::string(&result, "encoding");
        let encoded = Zeroizing::new(
          result
            .as_object_mut()
            .and_then(|object| object.remove("content"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .context("server response did not contain file content")?,
        );
        let bytes = if encoding == "base64" {
          Zeroizing::new(STANDARD.decode(&*encoded)?)
        } else {
          Zeroizing::new(encoded.as_bytes().to_vec())
        };
        let mut stdout = io::stdout().lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
      }
    }
    FileCommand::Update {
      file_id: reference,
      input,
      stdin,
    } => {
      let file_id = resolve_file_reference(api, project_ref, &reference).await?;
      let (content, encoding) = read_input(input.as_deref(), stdin)?;
      let result = api
        .request(
          Method::PUT,
          &api_paths::vault::file(&encode_path_segment(project_ref), &file_id),
          Some(json!({"content":content.as_str(),"encoding":encoding})),
        )
        .await?;
      print_result(
        &result,
        json_output,
        &format!(
          "Saved a new version of Vault file {}.",
          output::string(&result, "name")
        ),
      )?;
    }
    FileCommand::Versions { file_id: reference } => {
      let file_id = resolve_file_reference(api, project_ref, &reference).await?;
      let data = api
        .request(
          Method::GET,
          &api_paths::vault::file_versions(&encode_path_segment(project_ref), &file_id),
          None,
        )
        .await?;
      if json_output {
        output::print_json(&data)?;
      } else {
        let rows = output::array(&data)
          .iter()
          .map(|version| {
            vec![
              version
                .get("version")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                .to_string(),
              output::timestamp(version, "createdAt"),
              output::timestamp(version, "archivedAt"),
              output::string(version, "encoding"),
            ]
          })
          .collect::<Vec<_>>();
        output::print_table(
          &["VERSION", "CREATED", "ARCHIVED", "ENCODING"],
          &rows,
          "No retained versions.",
          &format!("{} retained version(s)", rows.len()),
        );
      }
    }
    FileCommand::Rollback {
      file_id: reference,
      version,
      yes,
    } => {
      let file_id = resolve_file_reference(api, project_ref, &reference).await?;
      prompt::confirm(
        &format!(
          "Restore Vault file {file_id} from version {version}? This creates a new current version."
        ),
        yes,
      )?;
      let result = api
        .request(
          Method::POST,
          &api_paths::vault::rollback_file(&encode_path_segment(project_ref), &file_id, version),
          None,
        )
        .await?;
      print_result(
        &result,
        json_output,
        &format!(
          "Restored Vault file from version {version}; new version {}.",
          result
            .get("version")
            .and_then(Value::as_i64)
            .unwrap_or_default()
        ),
      )?;
    }
    FileCommand::Delete {
      file_id: reference,
      yes,
    } => {
      let file_id = resolve_file_reference(api, project_ref, &reference).await?;
      prompt::confirm(
        &format!("Delete Vault file {file_id} and all retained versions?"),
        yes,
      )?;
      let result = api
        .request(
          Method::DELETE,
          &api_paths::vault::file(&encode_path_segment(project_ref), &file_id),
          None,
        )
        .await?;
      print_result(
        &result,
        json_output,
        &format!("Deleted Vault file {file_id}."),
      )?;
    }
  }
  Ok(())
}

fn read_input(
  path: Option<&Path>,
  stdin: bool,
) -> Result<(Zeroizing<String>, &'static str)> {
  if path.is_some() == stdin {
    bail!("provide exactly one input source: --input <FILE> or --stdin");
  }
  let mut bytes = Zeroizing::new(Vec::new());
  if let Some(path) = path {
    let file = fs::File::open(path)
      .with_context(|| format!("could not inspect input file {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
      bail!("input must be a regular file");
    }
    if metadata.len() > MAX_FILE_BYTES {
      bail!("Vault files are limited to 1 MiB");
    }
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
      bail!("Vault files are limited to 1 MiB");
    }
  } else {
    io::stdin()
      .take(MAX_FILE_BYTES + 1)
      .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
      bail!("Vault files are limited to 1 MiB");
    }
  }
  if bytes.contains(&0) {
    return Ok((Zeroizing::new(STANDARD.encode(&*bytes)), "base64"));
  }
  if let Ok(text) = std::str::from_utf8(&bytes) {
    Ok((Zeroizing::new(text.to_owned()), "utf-8"))
  } else {
    Ok((Zeroizing::new(STANDARD.encode(&*bytes)), "base64"))
  }
}

fn print_result(
  result: &Value,
  json_output: bool,
  message: &str,
) -> Result<()> {
  if json_output {
    output::print_json(result)?;
  } else {
    output::print_success(message);
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn encodes_text_and_binary_vault_inputs_with_explicit_encoding() {
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), b"KUBECONFIG=example\n").unwrap();
    let (text, encoding) = read_input(Some(file.path()), false).unwrap();
    assert_eq!(&*text, "KUBECONFIG=example\n");
    assert_eq!(encoding, "utf-8");

    fs::write(file.path(), [0_u8, 1, 2]).unwrap();
    let (binary, encoding) = read_input(Some(file.path()), false).unwrap();
    assert_eq!(&*binary, "AAEC");
    assert_eq!(encoding, "base64");
  }

  #[test]
  fn resolves_nested_folder_paths_and_rejects_cycles() {
    let folders = HashMap::from([
      ("root".into(), ("Project root".into(), None, true)),
      (
        "parent".into(),
        ("production".into(), Some("root".into()), false),
      ),
      (
        "child".into(),
        ("cluster".into(), Some("parent".into()), false),
      ),
    ]);
    assert_eq!(
      folder_path("child", &folders).unwrap(),
      "production/cluster"
    );
    assert_eq!(folder_path("root", &folders).unwrap(), "");

    let cycle = HashMap::from([
      ("a".into(), ("a".into(), Some("b".into()), false)),
      ("b".into(), ("b".into(), Some("a".into()), false)),
    ]);
    assert!(folder_path("a", &cycle).is_err());
  }

  #[test]
  fn environment_lookup_uses_the_list_endpoint() {
    assert_eq!(
      environment_list_path("AppFarm"),
      format!("{}v1/environments?project=AppFarm", api_paths::PREFIX)
    );
  }
}

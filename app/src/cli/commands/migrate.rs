use crate::{
  cli::{client, output, prompt},
  constants::api,
  legacy_vault::{self, LegacyEntry},
  modules::vault::validation,
};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
  collections::{HashMap, HashSet},
  fs::OpenOptions,
  io::Write,
  path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Subcommand, Debug)]
pub enum MigrateCommand {
  /// Import a Local Vault LVLT0001 file into encrypted Dopbase Vault storage.
  #[command(after_help = HELP)]
  LocalVault(LocalVaultArgs),
}

pub const HELP: &str = "\
Examples:
  dopbase migrate local-vault --folder \"Imported vault\" --dry-run
  dopbase migrate local-vault --folder \"Imported vault\" --backup ~/local-vault-backup.vault

The old password is prompted without echo. The source file is never modified.
Actual imports require a new verified encrypted backup; --dry-run writes nothing.
The import is applied atomically: a failure writes nothing to the project.";

#[derive(Args, Debug)]
pub struct LocalVaultArgs {
  /// Existing project name or ID that receives the imported files.
  #[arg(long, value_name = "PROJECT_REF")]
  project: String,
  /// Legacy vault file (defaults to ~/.local/share/local-vault/secrets.vault).
  #[arg(long, value_name = "PATH")]
  file: Option<PathBuf>,
  /// New top-level folder to contain the imported hierarchy.
  #[arg(long, value_name = "NAME")]
  folder: String,
  /// Create a new, verified copy of the encrypted source before importing.
  #[arg(long, value_name = "PATH", required_unless_present = "dry_run")]
  backup: Option<PathBuf>,
  /// Validate and summarize without creating folders or files.
  #[arg(long, conflicts_with = "backup")]
  dry_run: bool,
  /// Skip the final import confirmation (still requires the old vault password).
  #[arg(long)]
  yes: bool,
}

pub async fn execute(
  command: MigrateCommand,
  server: &crate::cli::local_config::ResolvedServer,
  json_output: bool,
) -> Result<i32> {
  match command {
    MigrateCommand::LocalVault(args) => migrate_local_vault(server, args, json_output).await?,
  }
  Ok(0)
}

async fn migrate_local_vault(
  server: &crate::cli::local_config::ResolvedServer,
  args: LocalVaultArgs,
  json_output: bool,
) -> Result<()> {
  let requested_source = args
    .file
    .map(expand_home)
    .unwrap_or_else(default_vault_path);
  let encrypted = legacy_vault::read_file(&requested_source)?;
  let source = requested_source
    .canonicalize()
    .context("could not resolve the Local Vault file")?;
  let mut password = Zeroizing::new(prompt::password(
    "Old Local Vault master password",
    false,
    client::CliCancelled::LocalVaultPassword,
  )?);
  let entries = legacy_vault::read_entries(&encrypted, &password)?;
  password.zeroize();
  let hierarchy = validate_import(&entries, &args.folder)?;
  let revision_count: usize = entries.iter().map(|entry| entry.versions.len()).sum();
  let root_name = args.folder.trim();

  if args.dry_run {
    let summary = json!({
      "dryRun": true,
      "source": source,
      "entries": entries.len(),
      "versions": revision_count,
      "folders": hierarchy.len(),
      "destination": root_name,
      "agentAccess": "not imported",
    });
    if json_output {
      output::print_json(&summary)?;
    } else {
      output::print_text("Dry run complete. No changes were applied.");
      output::print_fields(&[
        ("Entries:", entries.len().to_string()),
        ("Value revisions:", revision_count.to_string()),
        ("Nested folders:", hierarchy.len().to_string()),
        ("Destination:", root_name.to_owned()),
        ("Agent access:", "not imported".into()),
      ]);
    }
    return Ok(());
  }

  let api_client = client::human_client(server).await?;
  let existing_folders = api_client
    .request(Method::GET, &api::vault::folders(&args.project), None)
    .await?;
  if destination_exists(&existing_folders, root_name) {
    bail!("{}", duplicate_folder_message(&args.project, root_name));
  }

  prompt::confirm(
    &format!(
      "Import {} entries and {} value revisions into project {:?}, folder {:?}?",
      entries.len(),
      revision_count,
      args.project,
      root_name
    ),
    args.yes,
  )?;

  let backup = args
    .backup
    .context("--backup is required unless --dry-run is used")?;
  let backup = expand_home(backup);
  create_verified_backup(&backup, &encrypted)?;

  let payload = import_payload(root_name, &entries)?;
  let data = match api_client
    .request(
      Method::POST,
      &api::vault::import(&args.project),
      Some(payload),
    )
    .await
  {
    Ok(data) => data,
    Err(error) if client::is_conflict_error(&error) => {
      bail!("{}", duplicate_folder_message(&args.project, root_name))
    }
    Err(error) => bail!(
      "Local Vault import failed; nothing was written to project {:?} and the source file plus its encrypted backup at {} are intact: {error:#}",
      args.project,
      backup.display()
    ),
  };
  let folder_id = data
    .get("folderId")
    .and_then(Value::as_str)
    .context("Dopbase did not return the imported folder id")?;
  let (folders, files, versions) =
    imported_counts(&data, (hierarchy.len() + 1, entries.len(), revision_count));

  let summary = json!({
    "dryRun": false,
    "source": source,
    "backup": backup,
    "folderId": folder_id,
    "entries": entries.len(),
    "folders": folders,
    "files": files,
    "versions": versions,
    "destination": root_name,
    "agentAccess": "not imported",
  });
  if json_output {
    output::print_json(&summary)?;
  } else {
    output::print_success("Local Vault data imported into Dopbase Vault.");
    output::print_fields(&[
      ("Entries:", entries.len().to_string()),
      ("Value revisions:", versions.to_string()),
      ("Folders created:", folders.to_string()),
      ("Files created:", files.to_string()),
      ("Destination:", root_name.to_owned()),
      ("Encrypted backup:", backup.display().to_string()),
      ("Agent access:", "not imported".into()),
    ]);
  }
  Ok(())
}

fn default_vault_path() -> PathBuf {
  std::env::var_os("HOME")
    .map(PathBuf::from)
    .unwrap_or_else(std::env::temp_dir)
    .join(".local/share/local-vault/secrets.vault")
}

fn expand_home(path: PathBuf) -> PathBuf {
  let value = path.to_string_lossy();
  if (value == "~" || value.starts_with("~/"))
    && let Some(home) = std::env::var_os("HOME")
  {
    return PathBuf::from(home).join(value.trim_start_matches("~/"));
  }
  path
}

/// Reject an existing top-level folder whose name matches `name`.
///
/// The project root itself is not a valid destination name, so only children
/// of that root are compared. `GET /files/folders` normally omits the root
/// folder, which makes every top-level folder reference a `parentId` that is
/// absent from the response; when the response does include the root
/// (`isRoot: true`), its id is used instead. A response that carries neither
/// falls through to the server's `VAULT_NAME_CONFLICT` guard.
fn destination_exists(
  folders: &Value,
  name: &str,
) -> bool {
  let Some(folders) = folders.as_array() else {
    return false;
  };
  let ids: HashSet<&str> = folders
    .iter()
    .filter_map(|folder| folder.get("id").and_then(Value::as_str))
    .collect();
  let roots: HashSet<&str> = folders
    .iter()
    .filter(|folder| folder.get("isRoot").and_then(Value::as_bool) == Some(true))
    .filter_map(|folder| folder.get("id").and_then(Value::as_str))
    .collect();
  let name = name.trim();
  folders.iter().any(|folder| {
    if folder.get("isRoot").and_then(Value::as_bool) == Some(true) {
      return false;
    }
    let Some(parent) = folder.get("parentId").and_then(Value::as_str) else {
      return false;
    };
    let top_level = if roots.is_empty() {
      !ids.contains(parent)
    } else {
      roots.contains(parent)
    };
    top_level
      && folder
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|existing| existing.eq_ignore_ascii_case(name))
  })
}

fn duplicate_folder_message(
  project_ref: &str,
  root_name: &str,
) -> String {
  format!(
    "a top-level folder named {root_name:?} already exists in project {project_ref:?}; choose a new --folder name"
  )
}

fn validate_import(
  entries: &[LegacyEntry],
  root_name: &str,
) -> Result<HashMap<String, Vec<String>>> {
  validate_folder_name(root_name)?;
  if entries.is_empty() {
    bail!("Local Vault contains no entries to import");
  }
  let mut hierarchy = HashMap::<String, Vec<String>>::new();
  let mut file_paths = HashSet::new();
  for entry in entries {
    validate_file_name(&entry.name)?;
    let segments = folder_segments(&entry.folder)?;
    for depth in 1..=segments.len() {
      let path = segments[..depth].join("/");
      hierarchy.insert(path, segments[..depth].to_vec());
    }
    let identity = format!(
      "{}/{}",
      segments.join("/").to_lowercase(),
      entry.name.to_lowercase()
    );
    if !file_paths.insert(identity) {
      bail!(
        "Local Vault contains duplicate file names in the same folder: {:?}",
        entry.name
      );
    }
    if !matches!(
      entry.kind.as_str(),
      "secret" | "ssh" | "kubeconfig" | "env" | "api" | "file"
    ) {
      bail!(
        "entry {:?} uses an unsupported type {:?}",
        entry.name,
        entry.kind
      );
    }
    for version in &entry.versions {
      if version.content.len() > 1024 * 1024 || version.content.contains('\0') {
        bail!(
          "entry {:?} contains content the new Vault cannot store",
          entry.name
        );
      }
    }
  }
  Ok(hierarchy)
}

fn folder_segments(folder: &str) -> Result<Vec<String>> {
  if folder.chars().count() > 160 {
    bail!("a Local Vault folder path exceeds 160 characters");
  }
  let mut segments = Vec::new();
  for segment in folder
    .split(['/', '\\'])
    .map(str::trim)
    .filter(|part| !part.is_empty())
  {
    validate_folder_name(segment)?;
    segments.push(segment.to_owned());
    if segments.len() > 32 {
      bail!("a Local Vault folder path exceeds 32 levels");
    }
  }
  Ok(segments)
}

fn validate_folder_name(name: &str) -> Result<()> {
  validation::valid_name(name)
    .map(|_| ())
    .map_err(|reason| anyhow::anyhow!("folder names must be valid: {reason}"))
}

fn validate_file_name(name: &str) -> Result<()> {
  validation::valid_name(name)
    .map(|_| ())
    .map_err(|reason| anyhow::anyhow!("file names must be valid: {reason}"))
}

fn create_verified_backup(
  path: &Path,
  encrypted: &[u8],
) -> Result<()> {
  let mut options = OpenOptions::new();
  options.write(true).create_new(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options
      .mode(0o600)
      .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
  }
  let mut file = options.open(path).with_context(|| {
    format!(
      "could not create backup {} without overwriting",
      path.display()
    )
  })?;
  if let Err(error) = file.write_all(encrypted).and_then(|()| file.sync_all()) {
    let _ = std::fs::remove_file(path);
    return Err(error).context("could not write encrypted Local Vault backup");
  }
  drop(file);
  let written = match std::fs::read(path) {
    Ok(written) => written,
    Err(error) => {
      let _ = std::fs::remove_file(path);
      return Err(error).context("could not verify encrypted Local Vault backup");
    }
  };
  if Sha256::digest(&written) != Sha256::digest(encrypted) {
    let _ = std::fs::remove_file(path);
    bail!("encrypted Local Vault backup verification failed");
  }
  Ok(())
}

/// Build the single atomic `POST /projects/{project}/files/import` body.
///
/// Entries keep the Local Vault hierarchy as `/`-separated folder paths and
/// every value revision in ascending order. The mapping from legacy kinds to
/// the target `VaultFileKind` is unchanged from the per-call importer.
fn import_payload(
  root_name: &str,
  entries: &[LegacyEntry],
) -> Result<Value> {
  let mut payload_entries = Vec::with_capacity(entries.len());
  for entry in entries {
    let kind = match entry.kind.as_str() {
      "ssh" => "sshPrivateKey",
      "kubeconfig" => "kubeconfig",
      "env" => "env",
      "file" => "text",
      // The target model treats API records as secret documents. Legacy
      // agent_allowed flags are deliberately not transferred.
      "secret" | "api" => "secret",
      _ => bail!("unsupported legacy type {:?}", entry.kind),
    };
    if entry.versions.is_empty() {
      bail!("entry {:?} has no revisions to import", entry.name);
    }
    let versions = entry
      .versions
      .iter()
      .map(|version| json!({"encoding": version.encoding, "content": version.content.as_str()}))
      .collect::<Vec<_>>();
    payload_entries.push(json!({
      "name": entry.name,
      "folder": folder_segments(&entry.folder)?.join("/"),
      "kind": kind,
      "versions": versions,
    }));
  }
  Ok(json!({"folder": root_name.trim(), "entries": payload_entries}))
}

/// Read the import counts from the response, falling back to the locally
/// known numbers when the server omits a field.
fn imported_counts(
  data: &Value,
  fallback: (usize, usize, usize),
) -> (usize, usize, usize) {
  let count = |field: &str, fallback: usize| {
    data
      .get(field)
      .and_then(Value::as_u64)
      .and_then(|value| usize::try_from(value).ok())
      .unwrap_or(fallback)
  };
  (
    count("folders", fallback.0),
    count("files", fallback.1),
    count("versions", fallback.2),
  )
}

#[cfg(test)]
mod tests {
  use super::{
    destination_exists, folder_segments, import_payload, imported_counts, validate_file_name,
    validate_import,
  };
  use crate::{
    legacy_vault::{LegacyEntry, LegacyVersion},
    modules::vault::validation,
  };
  use serde_json::{Value, json};
  use zeroize::Zeroizing;

  fn entry(
    name: &str,
    folder: &str,
    kind: &str,
  ) -> LegacyEntry {
    LegacyEntry {
      name: name.into(),
      folder: folder.into(),
      kind: kind.into(),
      versions: vec![LegacyVersion {
        version: 1,
        encoding: "utf-8".into(),
        content: Zeroizing::new("value".to_owned()),
      }],
    }
  }

  fn rejection(
    entries: &[LegacyEntry],
    root: &str,
  ) -> String {
    let error = validate_import(entries, root).expect_err("import should have been rejected");
    format!("{error:#}")
  }

  #[test]
  fn accepts_a_nested_hierarchy_and_returns_every_parent_folder() {
    let entries = [
      entry("deploy.sh", "Ops/Prod", "ssh"),
      entry("notes.txt", "Ops", "file"),
      entry("token", "Dev/Sub/Deeper", "api"),
    ];
    let mut hierarchy = validate_import(&entries, "Imported vault").unwrap();
    let mut paths: Vec<_> = hierarchy.keys().cloned().collect();
    paths.sort();
    assert_eq!(
      paths,
      ["Dev", "Dev/Sub", "Dev/Sub/Deeper", "Ops", "Ops/Prod"]
    );
    assert_eq!(hierarchy.remove("Ops/Prod").unwrap(), ["Ops", "Prod"]);
  }

  #[test]
  fn rejects_duplicate_file_identities_case_insensitively() {
    let entries = [
      entry("Deploy.sh", "Ops/Prod", "ssh"),
      entry("deploy.sh", "ops/prod", "ssh"),
    ];
    assert!(
      rejection(&entries, "Imported vault").contains("duplicate file names in the same folder"),
      "same folder and name modulo case must collide"
    );

    let same_folder = [
      entry("Deploy.sh", "Ops", "ssh"),
      entry("DEPLOY.SH", "Ops", "file"),
    ];
    assert!(rejection(&same_folder, "Imported vault").contains("duplicate file names"));

    let distinct = [
      entry("Deploy.sh", "Ops", "ssh"),
      entry("deploy.sh", "Dev", "ssh"),
    ];
    assert!(
      validate_import(&distinct, "Imported vault").is_ok(),
      "identical names in different folders are legal"
    );
  }

  #[test]
  fn rejects_path_separators_in_folder_names() {
    assert!(
      rejection(&[entry("a", "Ops", "secret")], "Imported/vault").contains("path separators"),
      "the destination folder must not contain a separator"
    );
    assert!(
      rejection(&[entry("a", "Ops", "secret")], "Imported\\vault").contains("path separators")
    );
    assert_eq!(
      folder_segments("Ops\\Prod/Cluster").unwrap(),
      ["Ops", "Prod", "Cluster"],
      "entry folder paths are split into segments instead of rejected"
    );
  }

  #[test]
  fn rejects_dot_and_dot_dot_folder_segments() {
    assert!(rejection(&[entry("a", ".", "secret")], "Imported").contains("folder names must be"));
    assert!(
      rejection(&[entry("a", "Ops/..", "secret")], "Imported").contains("folder names must be")
    );
    assert!(
      rejection(&[entry("a", "Ops/./Prod", "secret")], "Imported").contains("folder names must be")
    );
    assert!(rejection(&[entry("a", "Ops", "secret")], "..").contains("folder names must be"));
  }

  #[test]
  fn rejects_folder_paths_deeper_than_32_levels() {
    let deep = vec!["a"; 33].join("/");
    assert!(deep.chars().count() < 160, "depth must trip before length");
    assert!(
      rejection(&[entry("a", &deep, "secret")], "Imported").contains("exceeds 32 levels"),
      "33 segments must be rejected"
    );
    let allowed = vec!["a"; 32].join("/");
    assert!(validate_import(&[entry("a", &allowed, "secret")], "Imported").is_ok());
  }

  #[test]
  fn rejects_folder_paths_longer_than_160_characters() {
    let long = format!("{}/{}", "a".repeat(80), "b".repeat(80));
    assert_eq!(long.chars().count(), 161);
    assert!(
      rejection(&[entry("a", &long, "secret")], "Imported").contains("exceeds 160 characters")
    );
    assert!(rejection(&[entry("a", "Ops", "secret")], &"n".repeat(129)).contains("folder names"));
  }

  #[test]
  fn rejects_unsupported_entry_kinds() {
    for kind in ["agent", "note", "", "Secret"] {
      let error = rejection(&[entry("a", "Ops", kind)], "Imported");
      assert!(
        error.contains("unsupported type"),
        "kind {kind:?} must be rejected: {error}"
      );
    }
    for kind in ["secret", "ssh", "kubeconfig", "env", "api", "file"] {
      assert!(
        validate_import(&[entry("a", "Ops", kind)], "Imported").is_ok(),
        "kind {kind:?} must be supported"
      );
    }
  }

  #[test]
  fn rejects_invalid_file_names() {
    for name in ["", "   ", "nul\0name"] {
      let error = rejection(&[entry(name, "Ops", "secret")], "Imported");
      assert!(
        error.contains("file names must be"),
        "name {name:?} must be rejected: {error}"
      );
    }
    let long = "n".repeat(129);
    assert!(rejection(&[entry(&long, "Ops", "secret")], "Imported").contains("file names must be"));
  }

  #[test]
  fn rejects_an_empty_vault_and_unsupported_content() {
    assert!(rejection(&[], "Imported").contains("no entries to import"));

    let mut oversized = entry("a", "Ops", "secret");
    oversized.versions[0].content = Zeroizing::new("a".repeat(1024 * 1024 + 1));
    assert!(rejection(&[oversized], "Imported").contains("cannot store"));

    let mut nul = entry("a", "Ops", "secret");
    nul.versions[0].content = Zeroizing::new("before\0after".to_owned());
    assert!(rejection(&[nul], "Imported").contains("cannot store"));
  }

  #[test]
  fn rejects_dot_and_dot_dot_file_names() {
    for name in [".", "..", "Ops/Prod", "Ops\\Prod", "nul\0name"] {
      let error = rejection(&[entry(name, "Ops", "secret")], "Imported");
      assert!(
        error.contains("file names must be"),
        "name {name:?} must be rejected before any write: {error}"
      );
    }
    assert!(
      validate_import(&[entry("..", "Ops", "secret")], "Imported").is_err(),
      "dry-run validation must reject the same names the server rejects"
    );
  }

  #[test]
  fn file_name_validation_is_the_shared_vault_rule() {
    let long = "n".repeat(129);
    let longest = "n".repeat(128);
    for name in [
      "",
      "  ",
      ".",
      "..",
      "a/b",
      "a\\b",
      "nul\0name",
      "ok.txt",
      &longest,
      &long,
    ] {
      assert_eq!(
        validate_file_name(name).is_err(),
        validation::valid_name(name).is_err(),
        "importer and server must agree on {name:?}"
      );
    }
    assert!(validate_file_name("ok.txt").is_ok());
  }

  #[test]
  fn rejects_an_existing_top_level_folder_case_insensitively() {
    let folders = json!([
      {"id": "root", "isRoot": true, "parentId": null, "name": ""},
      {"id": "f1", "isRoot": false, "parentId": "root", "name": "Imported Vault"},
      {"id": "f2", "isRoot": false, "parentId": "f1", "name": "Ops"},
    ]);
    assert!(destination_exists(&folders, "Imported Vault"));
    assert!(destination_exists(&folders, "imported vault"));
    assert!(destination_exists(&folders, "  IMPORTED VAULT  "));
    assert!(!destination_exists(&folders, "Imported"));
  }

  #[test]
  fn allows_the_same_name_nested_deeper() {
    let folders = json!([
      {"id": "root", "isRoot": true, "parentId": null, "name": ""},
      {"id": "f1", "isRoot": false, "parentId": "root", "name": "Ops"},
      {"id": "f2", "isRoot": false, "parentId": "f1", "name": "Imported Vault"},
    ]);
    assert!(
      !destination_exists(&folders, "Imported Vault"),
      "only children of the project root can collide"
    );
  }

  #[test]
  fn allows_the_same_name_in_another_project() {
    assert!(
      !destination_exists(&json!([]), "Imported Vault"),
      "another project's folders are not part of this project's response"
    );
    let other_tree = json!([
      {"id": "elsewhere", "isRoot": false, "parentId": null, "name": "Imported Vault"},
    ]);
    assert!(
      !destination_exists(&other_tree, "Imported Vault"),
      "a folder outside the resolved root must not block the import"
    );
  }

  #[test]
  fn detects_top_level_folders_when_the_server_omits_the_root() {
    // GET /files/folders hides the project root, so a top-level folder points
    // at a parent id that is absent from the response.
    let folders = json!([
      {"id": "f1", "isRoot": false, "parentId": "unlisted-root", "name": "Imported Vault"},
      {"id": "f2", "isRoot": false, "parentId": "f1", "name": "Imported Vault"},
    ]);
    assert!(destination_exists(&folders, "imported vault"));
  }

  #[test]
  fn falls_through_when_the_response_has_no_root() {
    assert!(!destination_exists(&json!([]), "Imported Vault"));
    assert!(!destination_exists(
      &json!({"unexpected": true}),
      "Imported Vault"
    ));
    let nested_only = json!([
      {"id": "a", "parentId": null, "name": "Ops"},
      {"id": "b", "parentId": "a", "name": "Imported Vault"},
    ]);
    assert!(
      !destination_exists(&nested_only, "Imported Vault"),
      "without a root hint the server conflict stays the guard"
    );
  }

  #[test]
  fn builds_one_atomic_import_payload() {
    let mut multi = entry("deploy.sh", "Ops\\Prod", "ssh");
    multi.versions = vec![
      LegacyVersion {
        version: 1,
        encoding: "utf-8".into(),
        content: Zeroizing::new("old".to_owned()),
      },
      LegacyVersion {
        version: 2,
        encoding: "base64".into(),
        content: Zeroizing::new("bmV3".to_owned()),
      },
    ];
    let entries = [
      multi,
      entry("notes.txt", "Ops", "file"),
      entry("token", "", "api"),
      entry("db.env", "Ops/Prod", "env"),
    ];
    let payload = import_payload("  Imported vault  ", &entries).unwrap();
    assert_eq!(
      payload,
      json!({
        "folder": "Imported vault",
        "entries": [
          {
            "name": "deploy.sh",
            "folder": "Ops/Prod",
            "kind": "sshPrivateKey",
            "versions": [
              {"encoding": "utf-8", "content": "old"},
              {"encoding": "base64", "content": "bmV3"},
            ],
          },
          {
            "name": "notes.txt",
            "folder": "Ops",
            "kind": "text",
            "versions": [{"encoding": "utf-8", "content": "value"}],
          },
          {
            "name": "token",
            "folder": "",
            "kind": "secret",
            "versions": [{"encoding": "utf-8", "content": "value"}],
          },
          {
            "name": "db.env",
            "folder": "Ops/Prod",
            "kind": "env",
            "versions": [{"encoding": "utf-8", "content": "value"}],
          },
        ],
      })
    );
  }

  #[test]
  fn maps_every_supported_legacy_kind() {
    for (legacy, expected) in [
      ("ssh", "sshPrivateKey"),
      ("kubeconfig", "kubeconfig"),
      ("env", "env"),
      ("file", "text"),
      ("secret", "secret"),
      ("api", "secret"),
    ] {
      let payload = import_payload("Imported", &[entry("a", "Ops", legacy)]).unwrap();
      assert_eq!(payload["entries"][0]["kind"], json!(expected), "{legacy}");
    }
  }

  #[test]
  fn rejects_payload_entries_without_revisions() {
    let mut empty = entry("a", "Ops", "secret");
    empty.versions.clear();
    let error = import_payload("Imported", &[empty]).expect_err("no revisions must be rejected");
    assert!(format!("{error:#}").contains("no revisions"), "{error:#}");
  }

  #[test]
  fn reads_import_counts_and_falls_back_when_missing() {
    let data = json!({"folderId": "f1", "folders": 3, "files": 4, "versions": 7});
    assert_eq!(imported_counts(&data, (9, 9, 9)), (3, 4, 7));

    let partial = json!({"folderId": "f1", "files": 4});
    assert_eq!(
      imported_counts(&partial, (3, 4, 5)),
      (3, 4, 5),
      "absent fields fall back to the locally known numbers"
    );

    let invalid: Value = json!({"folders": "many"});
    assert_eq!(imported_counts(&invalid, (1, 2, 3)), (1, 2, 3));
  }
}

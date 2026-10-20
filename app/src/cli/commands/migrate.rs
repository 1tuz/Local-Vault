use crate::{
  cli::{
    client::{self, ApiClient},
    output, prompt,
  },
  constants::api,
  legacy_vault::{self, LegacyEntry},
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
Actual imports require a new verified encrypted backup; --dry-run writes nothing.";

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
  if root_folder_exists(&existing_folders, root_name) {
    bail!(
      "a top-level folder named {root_name:?} already exists in project {:?}; choose a new --folder name",
      args.project
    );
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

  import_entries(&api_client, &args.project, root_name, &entries)
    .await
    .with_context(|| {
      format!(
        "Local Vault import failed; the original was preserved and its encrypted backup is at {}",
        backup.display()
      )
    })?;

  let summary = json!({
    "dryRun": false,
    "source": source,
    "backup": backup,
    "entries": entries.len(),
    "versions": revision_count,
    "destination": root_name,
    "agentAccess": "not imported",
  });
  if json_output {
    output::print_json(&summary)?;
  } else {
    output::print_success("Local Vault data imported into Dopbase Vault.");
    output::print_fields(&[
      ("Entries:", entries.len().to_string()),
      ("Value revisions:", revision_count.to_string()),
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

fn root_folder_exists(
  folders: &Value,
  name: &str,
) -> bool {
  folders.as_array().is_some_and(|folders| {
    folders.iter().any(|folder| {
      folder.get("parentId").is_none_or(Value::is_null)
        && folder
          .get("name")
          .and_then(Value::as_str)
          .is_some_and(|existing| existing.eq_ignore_ascii_case(name.trim()))
    })
  })
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
  let name = name.trim();
  if name.is_empty()
    || name.len() > 128
    || name == "."
    || name == ".."
    || name.contains('\0')
    || name.contains('/')
    || name.contains('\\')
  {
    bail!("folder names must be 1–128 bytes and cannot contain path separators");
  }
  Ok(())
}

fn validate_file_name(name: &str) -> Result<()> {
  if name.trim().is_empty() || name.trim().len() > 128 || name.contains('\0') {
    bail!("file names must be 1–128 bytes");
  }
  Ok(())
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

async fn import_entries(
  api_client: &ApiClient,
  project_ref: &str,
  root_name: &str,
  entries: &[LegacyEntry],
) -> Result<()> {
  let mut created_folders = Vec::new();
  let mut created_files = Vec::new();
  let result = async {
    let root = create_folder(api_client, project_ref, root_name, None).await?;
    created_folders.push(root.clone());
    let mut folder_ids = HashMap::<String, String>::new();
    for entry in entries {
      let segments = folder_segments(&entry.folder)?;
      let mut parent_id = root.clone();
      let mut path_parts = Vec::new();
      for segment in segments {
        path_parts.push(segment.clone());
        let path = path_parts.join("/");
        if let Some(id) = folder_ids.get(&path) {
          parent_id.clone_from(id);
        } else {
          let id = create_folder(api_client, project_ref, &segment, Some(&parent_id)).await?;
          created_folders.push(id.clone());
          folder_ids.insert(path, id.clone());
          parent_id = id;
        }
      }
      let first = entry.versions.first().context("entry has no revisions")?;
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
      let created = api_client
        .request(
          Method::POST,
          &api::vault::folder_files(project_ref, &parent_id),
          Some(json!({"name":entry.name,"kind":kind,"encoding":first.encoding,"content":first.content.as_str()})),
        )
        .await
        .with_context(|| format!("could not import file {:?}", entry.name))?;
      let file_id = created
        .get("id")
        .and_then(Value::as_str)
        .context("Dopbase did not return an imported file id")?
        .to_owned();
      created_files.push(file_id.clone());
      for version in entry.versions.iter().skip(1) {
        api_client
          .request(
            Method::PUT,
            &api::vault::file(project_ref, &file_id),
            Some(json!({"content":version.content.as_str(),"encoding":version.encoding})),
          )
          .await
          .with_context(|| {
            format!(
              "could not import revision {} of {:?}",
              version.version, entry.name
            )
          })?;
      }
    }
    Ok::<(), anyhow::Error>(())
  }
  .await;
  if let Err(error) = result {
    let cleanup_errors =
      rollback_created(api_client, project_ref, &created_files, &created_folders).await;
    if cleanup_errors.is_empty() {
      return Err(error).context("partial import was rolled back");
    }
    bail!(
      "{error:#}; automatic rollback was incomplete: {}",
      cleanup_errors.join("; ")
    );
  }
  Ok(())
}

async fn create_folder(
  api_client: &ApiClient,
  project_ref: &str,
  name: &str,
  parent_id: Option<&str>,
) -> Result<String> {
  let response = api_client
    .request(
      Method::POST,
      &api::vault::folders(project_ref),
      Some(json!({"name":name,"parentId":parent_id})),
    )
    .await?;
  response
    .get("id")
    .and_then(Value::as_str)
    .map(str::to_owned)
    .context("Dopbase did not return a created folder id")
}

async fn rollback_created(
  api_client: &ApiClient,
  project_ref: &str,
  files: &[String],
  folders: &[String],
) -> Vec<String> {
  let mut errors = Vec::new();
  for id in files.iter().rev() {
    if let Err(error) = api_client
      .request(Method::DELETE, &api::vault::file(project_ref, id), None)
      .await
    {
      errors.push(format!("file {id}: {error}"));
    }
  }
  for id in folders.iter().rev() {
    if let Err(error) = api_client
      .request(Method::DELETE, &api::vault::folder(project_ref, id), None)
      .await
    {
      errors.push(format!("folder {id}: {error}"));
    }
  }
  errors
}

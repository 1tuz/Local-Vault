use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum VaultCommand {
  /// Show folders and files as a path tree.
  #[command(after_help = TREE_HELP)]
  Tree,
  /// Manage folders.
  #[command(after_help = FOLDER_HELP)]
  Folder {
    #[command(subcommand)]
    command: FolderCommand,
  },
  /// Manage encrypted typed files.
  #[command(after_help = FILE_HELP)]
  File {
    #[command(subcommand)]
    command: FileCommand,
  },
}

#[derive(Subcommand, Debug)]
pub enum FolderCommand {
  /// Create a folder. Parent accepts a path or ID; omit it for a top-level folder.
  #[command(after_help = FOLDER_CREATE_HELP)]
  Create {
    /// Folder name, without path separators.
    name: String,
    /// Parent folder path or ID; omit for a top-level folder.
    #[arg(long, help = "Parent folder path or ID; omit for a top-level folder.")]
    parent: Option<String>,
  },
  /// Move a folder to a parent folder or the root; optionally rename it.
  #[command(after_help = FOLDER_MOVE_HELP)]
  Move {
    /// Current folder path or ID.
    id: String,
    /// Destination parent folder path or ID.
    #[arg(
      long,
      help = "Destination parent folder path or ID.",
      conflicts_with = "root"
    )]
    parent: Option<String>,
    /// Move to the top level (the default is to keep the current parent).
    #[arg(long, help = "Move to the top-level Vault folder.")]
    root: bool,
    /// New folder name; omitted to keep its current name.
    #[arg(long)]
    name: Option<String>,
  },
  /// Assign or clear the environment tag inherited by Vault files in this folder.
  #[command(after_help = FOLDER_ENVIRONMENT_HELP)]
  SetEnvironment {
    /// Folder path or ID.
    id: String,
    /// Environment name. Created if it does not exist in the project.
    #[arg(
      long,
      value_name = "NAME",
      conflicts_with = "clear",
      required_unless_present = "clear"
    )]
    environment: Option<String>,
    /// Remove the folder's environment tag.
    #[arg(long)]
    clear: bool,
  },
  /// Delete an empty folder.
  #[command(after_help = FOLDER_DELETE_HELP)]
  Delete {
    /// Folder path or ID.
    id: String,
    /// Skip the confirmation prompt.
    #[arg(long)]
    yes: bool,
  },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum VaultFileKind {
  Secret,
  Env,
  Kubeconfig,
  SshPrivateKey,
  Certificate,
  Text,
}

impl VaultFileKind {
  pub(super) fn api_value(self) -> &'static str {
    match self {
      Self::Secret => "secret",
      Self::Env => "env",
      Self::Kubeconfig => "kubeconfig",
      Self::SshPrivateKey => "sshPrivateKey",
      Self::Certificate => "certificate",
      Self::Text => "text",
    }
  }
}

#[derive(Subcommand, Debug)]
pub enum FileCommand {
  /// List file metadata in a folder.
  #[command(after_help = FILE_LIST_HELP)]
  List {
    /// Folder path or ID.
    folder_id: String,
  },
  /// Create a typed file from a path or standard input.
  #[command(after_help = FILE_CREATE_HELP)]
  Create {
    /// Folder path or ID.
    folder_id: String,
    /// File name, without path separators.
    name: String,
    /// Stored content type.
    #[arg(long, value_enum)]
    kind: VaultFileKind,
    /// Read bytes from a regular file (binary files are Base64 encoded).
    #[arg(long, conflicts_with = "stdin")]
    input: Option<PathBuf>,
    /// Read bytes from standard input.
    #[arg(long)]
    stdin: bool,
    /// Attach to an existing project environment by name, or create it if missing.
    #[arg(long, value_name = "NAME")]
    environment: Option<String>,
  },
  /// Move a file into another folder without changing its ID or versions.
  #[command(after_help = FILE_MOVE_HELP)]
  Move {
    /// File path or ID.
    file_id: String,
    /// Destination folder path or ID.
    #[arg(long, value_name = "FOLDER")]
    to: String,
  },
  /// Assign or clear a typed file's environment tag.
  #[command(after_help = FILE_ENVIRONMENT_HELP)]
  SetEnvironment {
    /// File path or ID.
    file_id: String,
    /// Environment name. Created if it does not exist in the project.
    #[arg(
      long,
      value_name = "NAME",
      conflicts_with = "clear",
      required_unless_present = "clear"
    )]
    environment: Option<String>,
    /// Remove the file's environment tag.
    #[arg(long)]
    clear: bool,
  },
  /// Show file metadata only.
  #[command(after_help = FILE_SHOW_HELP)]
  Show {
    /// File path or ID.
    file_id: String,
  },
  /// Reveal file bytes using the authenticated human session.
  #[command(after_help = FILE_REVEAL_HELP)]
  Reveal {
    /// File path or ID.
    file_id: String,
  },
  /// Replace file content from a path or standard input, creating a new version.
  #[command(after_help = FILE_UPDATE_HELP)]
  Update {
    /// File path or ID.
    file_id: String,
    /// Read bytes from a regular file (binary files are Base64 encoded).
    #[arg(long, conflicts_with = "stdin")]
    input: Option<PathBuf>,
    /// Read bytes from standard input.
    #[arg(long)]
    stdin: bool,
  },
  /// List retained file version metadata without revealing content.
  #[command(after_help = FILE_VERSIONS_HELP)]
  Versions {
    /// File path or ID.
    file_id: String,
  },
  /// Restore a prior version as a new current version.
  #[command(after_help = FILE_ROLLBACK_HELP)]
  Rollback {
    /// File path or ID.
    file_id: String,
    /// Version number to restore.
    version: i64,
    /// Skip the confirmation prompt.
    #[arg(long)]
    yes: bool,
  },
  /// Delete a file and its retained versions.
  #[command(after_help = FILE_DELETE_HELP)]
  Delete {
    /// File path or ID.
    file_id: String,
    /// Skip the confirmation prompt.
    #[arg(long)]
    yes: bool,
  },
}

pub(crate) const HELP: &str = "\
Examples:
  dopbase files AppFarm tree
  dopbase files AppFarm folder create production
  dopbase files AppFarm folder create cluster --parent production
  dopbase files AppFarm file list production/cluster
  dopbase files AppFarm file create production/cluster kubeconfig --kind kubeconfig --input ./config
  dopbase files AppFarm file reveal production/cluster/kubeconfig
  dopbase files AppFarm file versions production/cluster/kubeconfig
  dopbase files AppFarm file rollback production/cluster/kubeconfig 2

File content is encrypted by the server. `reveal` requires an authenticated
project-manager session. AI-agent tokens can list metadata only and cannot reveal,
create, update, roll back, or delete Vault data.
";

const FOLDER_HELP: &str = "\
Examples:
  dopbase files AppFarm folder create production
  dopbase files AppFarm folder move production/cluster --parent staging
";
const FILE_HELP: &str = "\
Examples:
  dopbase files AppFarm file list production/cluster
  dopbase files AppFarm file versions production/cluster/kubeconfig
";

const TREE_HELP: &str = "\
Examples:
  dopbase files AppFarm tree
  dopbase files AppFarm tree --json
";
const FOLDER_CREATE_HELP: &str = "\
Examples:
  dopbase files AppFarm folder create production
  dopbase files AppFarm folder create cluster --parent production
";
const FOLDER_MOVE_HELP: &str = "\
Examples:
  dopbase files AppFarm folder move production/cluster --parent staging
  dopbase files AppFarm folder move production --root --name prod
";
const FOLDER_ENVIRONMENT_HELP: &str = "\
Examples:
  dopbase files AppFarm folder set-environment production/cluster --environment production
  dopbase files AppFarm folder set-environment production/cluster --clear

The tag applies to metadata and is inherited by files under this folder.
";
const FOLDER_DELETE_HELP: &str = "\
Examples:
  dopbase files AppFarm folder delete production/empty --yes

Only empty folders can be deleted.
";
const FILE_LIST_HELP: &str = "\
Examples:
  dopbase files AppFarm file list production/cluster
";
const FILE_CREATE_HELP: &str = "\
Examples:
  dopbase files AppFarm file create production/cluster kubeconfig --kind kubeconfig --input ./config
  printf '%s' \"$KUBECONFIG\" | dopbase files AppFarm file create production env --kind env --stdin
  dopbase files AppFarm file create production API_KEY --kind secret --stdin --environment 'Release Candidate'

Provide exactly one of --input or --stdin.
";
const FILE_MOVE_HELP: &str = "\
Examples:
  dopbase files AppFarm file move production/cluster/kubeconfig --to staging/cluster
  dopbase files AppFarm file move 01J... --to staging/cluster

Moving a file preserves its stable ID, content, and version history.
";
const FILE_ENVIRONMENT_HELP: &str = "\
Examples:
  dopbase files AppFarm file set-environment production/cluster/kubeconfig --environment production
  dopbase files AppFarm file set-environment production/cluster/kubeconfig --clear
";
const FILE_SHOW_HELP: &str = "\
Examples:
  dopbase files AppFarm file show production/cluster/kubeconfig
";
const FILE_REVEAL_HELP: &str = "\
Examples:
  dopbase files AppFarm file reveal production/cluster/kubeconfig > config

Requires an authenticated project-manager session. Binary files are written to stdout as raw bytes.
";
const FILE_UPDATE_HELP: &str = "\
Examples:
  dopbase files AppFarm file update production/cluster/kubeconfig --input ./new-config
  cat config | dopbase files AppFarm file update production/cluster/kubeconfig --stdin

Provide exactly one of --input or --stdin. Each update creates a new version.
";
const FILE_VERSIONS_HELP: &str = "\
Examples:
  dopbase files AppFarm file versions production/cluster/kubeconfig
";
const FILE_ROLLBACK_HELP: &str = "\
Examples:
  dopbase files AppFarm file rollback production/cluster/kubeconfig 2
  dopbase files AppFarm file rollback production/cluster/kubeconfig 2 --yes

Restoring creates a new current version; it does not erase newer history.
";
const FILE_DELETE_HELP: &str = "\
Examples:
  dopbase files AppFarm file delete production/cluster/kubeconfig
  dopbase files AppFarm file delete production/cluster/kubeconfig --yes

Deleting a file removes its retained versions.
";

CREATE TABLE vault_folders (
  id TEXT PRIMARY KEY,
  parent_id TEXT REFERENCES vault_folders(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX vault_folders_sibling_name_idx
  ON vault_folders(COALESCE(parent_id, ''), name COLLATE NOCASE);

CREATE TABLE vault_files (
  id TEXT PRIMARY KEY,
  folder_id TEXT NOT NULL REFERENCES vault_folders(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('secret','env','kubeconfig','sshPrivateKey','certificate','text')),
  version INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  value_nonce BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  key_nonce BLOB NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(folder_id, name COLLATE NOCASE)
);

CREATE INDEX vault_files_folder_idx ON vault_files(folder_id, name COLLATE NOCASE);

CREATE TABLE vault_file_versions (
  file_id TEXT NOT NULL REFERENCES vault_files(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  value_nonce BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  key_nonce BLOB NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT NOT NULL,
  PRIMARY KEY(file_id, version)
);

ALTER TABLE vault_folders
  ADD COLUMN environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL;

ALTER TABLE vault_folders
  ADD COLUMN is_root INTEGER NOT NULL DEFAULT 0 CHECK (is_root IN (0, 1));

DROP INDEX vault_folders_sibling_name_idx;

CREATE UNIQUE INDEX vault_folders_sibling_name_idx
  ON vault_folders(project_id, COALESCE(parent_id, ''), name COLLATE NOCASE);

CREATE UNIQUE INDEX vault_folders_project_root_idx
  ON vault_folders(project_id) WHERE is_root = 1;

CREATE INDEX vault_folders_environment_idx
  ON vault_folders(environment_id);

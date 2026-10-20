DROP INDEX IF EXISTS vault_folders_environment_idx;
DROP INDEX IF EXISTS vault_folders_project_root_idx;
DROP INDEX IF EXISTS vault_folders_sibling_name_idx;

ALTER TABLE vault_folders DROP COLUMN is_root;
ALTER TABLE vault_folders DROP COLUMN environment_id;

CREATE UNIQUE INDEX vault_folders_sibling_name_idx
  ON vault_folders(COALESCE(parent_id, ''), name COLLATE NOCASE);

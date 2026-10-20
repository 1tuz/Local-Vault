DROP INDEX IF EXISTS vault_folders_project_parent_idx;
UPDATE vault_folders SET project_id = NULL WHERE project_id = 'prj_legacy_files_migration';
DELETE FROM projects WHERE id = 'prj_legacy_files_migration';
ALTER TABLE vault_folders DROP COLUMN project_id;

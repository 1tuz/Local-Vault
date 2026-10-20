DROP INDEX IF EXISTS vault_files_environment_idx;

ALTER TABLE vault_files DROP COLUMN environment_id;

ALTER TABLE vault_files
  ADD COLUMN environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL;

CREATE INDEX vault_files_environment_idx ON vault_files(environment_id);

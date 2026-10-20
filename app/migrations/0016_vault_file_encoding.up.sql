ALTER TABLE vault_files
  ADD COLUMN encoding TEXT NOT NULL DEFAULT 'utf-8'
  CHECK (encoding IN ('utf-8', 'base64'));

ALTER TABLE vault_file_versions
  ADD COLUMN encoding TEXT NOT NULL DEFAULT 'utf-8'
  CHECK (encoding IN ('utf-8', 'base64'));

ALTER TABLE vault_folders
  ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE CASCADE;

CREATE INDEX vault_folders_project_parent_idx
  ON vault_folders(project_id, parent_id, name COLLATE NOCASE);

-- Keep any files created by the earlier standalone tree. Move them under a
-- generated project so the new project-scoped file browser can still find them.
WITH RECURSIVE candidates(n, name) AS (
  VALUES (1, 'personal-files')
  UNION ALL
  SELECT n + 1, 'personal-files-' || (n + 1)
  FROM candidates
  WHERE n < 999
), available AS (
  SELECT name
  FROM candidates
  WHERE NOT EXISTS (
    SELECT 1 FROM projects WHERE projects.name = candidates.name COLLATE NOCASE
  )
  ORDER BY n
  LIMIT 1
)
INSERT INTO projects(id, name, created_at, updated_at)
SELECT 'prj_legacy_files_migration', name, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM available
WHERE EXISTS (SELECT 1 FROM vault_folders)
  AND NOT EXISTS (
    SELECT 1 FROM projects WHERE id = 'prj_legacy_files_migration'
  );

UPDATE vault_folders
SET project_id = 'prj_legacy_files_migration'
WHERE project_id IS NULL
  AND EXISTS (SELECT 1 FROM projects WHERE id = 'prj_legacy_files_migration');

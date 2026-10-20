DROP INDEX IF EXISTS agent_tokens_project_idx;

ALTER TABLE agent_tokens DROP COLUMN project_id;

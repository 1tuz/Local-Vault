DROP INDEX IF EXISTS agent_tokens_environment_idx;
ALTER TABLE agent_tokens DROP COLUMN environment_id;

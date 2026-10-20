ALTER TABLE agent_tokens
ADD COLUMN environment_id TEXT REFERENCES environments(id) ON DELETE CASCADE;

CREATE INDEX agent_tokens_environment_idx ON agent_tokens(environment_id);

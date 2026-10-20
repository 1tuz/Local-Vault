ALTER TABLE agent_tokens
ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE CASCADE;

CREATE INDEX agent_tokens_project_idx ON agent_tokens(project_id);

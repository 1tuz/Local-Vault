Migrations are embedded into the `dopbase` binary with `sqlx::migrate!()` and
run transactionally before the HTTP listener starts.

Each table and feature uses its own reversible pair with the same numeric
version. The current pre-release schema is assembled in this order:

```text
0001_instance_metadata.up.sql
0002_admins.up.sql
0003_sessions.up.sql
0004_projects.up.sql
0005_environments.up.sql
0006_secrets.up.sql
0007_runner_tokens.up.sql
0008_audit_events.up.sql
0009_environment_env_layout.up.sql
0010_session_retention.up.sql
0011_service_accounts.up.sql
0012_agent_tokens.up.sql
0013_runner_token_expiry.up.sql
0014_secret_versions.up.sql
0015_vault_files.up.sql
0016_vault_file_encoding.up.sql
0017_agent_token_environment_scope.up.sql
0018_project_files.up.sql
0019_agent_token_project_scope.up.sql
0020_vault_file_environment.up.sql
0021_vault_environment_tags.up.sql
```

The up file applies the change. The down file removes only that version's
change and must be safe when versions are reverted in reverse order. Version
0013 adds a nullable runner-token expiry column; existing tokens keep no
expiry. Version 0017 adds an optional environment scope to agent tokens; existing
tokens remain metadata-only. Runtime startup applies up migrations only. Rollback
is a maintenance and test operation, not a public Dopbase CLI command.
Version 0019 adds an optional project scope to agent tokens; existing tokens keep
their prior global or environment scope.
Version 0020 adds an optional environment label to typed project files. A null
environment means the file is shared across environments; deleting an
environment clears the label without deleting the file.
Version 0021 adds optional environment labels to folders and marks each
project's virtual root folder.

The database test suite applies all migrations, rolls back to version zero,
and reapplies them. Never edit a migration after release. Add a new numbered
pair instead.

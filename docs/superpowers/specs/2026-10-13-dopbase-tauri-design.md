# Dopbase in Tauri: Architecture Design

## Goal

Use the clean upstream Dopbase product as the functional and security baseline while shipping it as a Tauri desktop application. Restore the upstream Admin UI, Rust API, auth/roles, encryption, versions, backups, CLI, import/export, and runtime secret injection. Add Vault-like folders and file-like typed secret collections. Keep human reveal/copy controls. AI/MCP access must never reveal secret values or mutate stored data.

## Architecture

- Keep upstream Rust application as the domain, persistence, crypto, and REST API implementation.
- Keep the Vue Admin UI and its existing HTTP service layer.
- Add a Tauri desktop host that starts the upstream API bound only to loopback and opens the Admin UI in a Tauri WebView. Desktop lifetime owns the API; use the upstream default/configured port so CLI and MCP can connect to the desktop instance. The API must not become a public network service.
- Preserve the upstream standalone CLI/server mode. CLI, Admin UI, and MCP must use the same upstream API and authorization rules rather than duplicate database or crypto access.
- Add MCP as a stdio adapter using a dedicated AI-agent credential. Expose metadata-only tools. Do not expose reveal, export, runtime injection, secret writes, rollback, or administrative mutations through MCP.

## Data model

Keep the existing project → environment → versioned secret model unchanged.
Environments also act as project-local tags for Vault files and folders. Add a
project-scoped Vault tree through additive migrations:

`Vault → Folder tree → Typed secret files`

- Vault folders belong to one project and may inherit or override an environment tag. A file without a direct tag inherits the nearest tagged folder; untagged files remain shared. Secret values remain stored in their existing environment records.
- A file-like secret set groups entries and presents them as one `.env`, kubeconfig, SSH key, API credential, certificate, or generic secret document.
- Each file is an encrypted document with its own version history and rollback. Existing environment secrets retain their upstream per-secret history.
- Store type, path, name, and non-secret labels as metadata. Encrypt every secret payload using the upstream envelope-encryption implementation.
- Keep the existing environment import/export and CLI workflows. Add Vault operations alongside them without changing behavior for existing data.

## Security and migration

- AI identities can read project/environment/folder/file names, secret keys, types, and version metadata only; they cannot read values or write data.
- Human reveal/copy actions remain in the authenticated UI, require an active session and CSRF protection, and are recorded in the audit log. Bulk exports retain recent-password confirmation.
- Keep the old `LVLT0001` vault intact. Any data migration must be explicit, create a recoverable backup, require the old master password, and write into the upstream encrypted store; never silently overwrite either store.
- Do not expose the desktop API beyond loopback. Preserve upstream request auth, CSRF protection, and browser-origin checks. The desktop uses the same configured port and data directory as the CLI server; only one process can own that server at a time.

## Delivery phases

1. Establish an upstream baseline in the workspace and package it in Tauri without losing existing product features.
2. Add folder/file/type model through additive migrations and shared API/CLI operations.
3. Add metadata-only MCP tools and permission checks.
4. Port the prototype's reveal/copy controls and provide an explicit data migration path.
5. Verify build, server binding, UI launch, CLI/MCP auth boundaries, and backup/restore behavior.

## Acceptance criteria

- Desktop launches the full upstream Admin UI inside Tauri and the backend binds only to loopback.
- Existing upstream project/environment/secret/auth/token/backup/audit/import/export/CLI workflows remain available; project environments are presented as tags in the desktop UI.
- Folder nesting and file-like typed secret sets work in the UI/API, with upstream encryption and per-file rollback; existing environment secrets retain their own rollback.
- AI/MCP cannot obtain a secret value by any exposed tool or alternate route.
- Human users retain explicit show/hide and copy controls.
- Existing databases remain readable; schema changes are additive, and old Local Vault files are never silently discarded.

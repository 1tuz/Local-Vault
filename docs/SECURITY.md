# Security and operational boundaries

**Status: upstream Dopbase security model with a new Tauri host, vault-file API,
version history, and MCP adapter. No independent security audit has been
performed. Do not use real production credentials until the remaining checks
below are completed.**

## Implemented protections

- Secret and typed-file payloads use the upstream XChaCha20-Poly1305 envelope
  encryption, with per-value data keys and the instance master key.
- The desktop host binds the upstream API to loopback, owns its lifecycle, and
  loads the original Vue Admin UI in a Tauri WebView. The existing CLI and
  desktop use the same configured server port and `~/.dopbase` data directory.
- Existing authentication, roles, CSRF checks, audit records, encrypted
  backups, and CLI workflows remain in use. Browser and project-file reveal/copy
  use the active authenticated session; bulk secret export still requires recent
  password confirmation.
- Creating an AI-agent token requires an authenticated Admin browser session
  and CSRF token, but does not require recent password confirmation. The
  plaintext token is shown only once.
- Desktop browser sessions do not expire due to inactivity or age. The
  HttpOnly session cookie and CSRF token persist until logout, password change,
  or explicit session revocation. Password re-confirmation for bulk exports
  and other sensitive operations remains separate from session lifetime.
- Secret and typed-file revisions retain encrypted prior ciphertext. Restore
  writes a new version. Agents and CLI sessions may add values, write versions,
  and restore versions, but deletion is limited to browser Admin UI sessions
  with CSRF protection. The UI can delete archived versions; the current
  version remains until its secret/file is deleted in the UI.
- Backups contain the whole Vault tree, every file revision, and archived
  secret versions in addition to projects, environments, secrets, and accounts.
  Restore removes Vault folders leaf-first and restores the snapshot's folders,
  files, versions, and archived secret versions; factory reset removes the same
  rows explicitly.
- A master-key rekey, whether from uploading a backup with a different key or
  restoring with `masterKey`, re-wraps the data key of every encrypted row:
  environment secrets, archived secret versions, Vault files, and archived
  Vault file revisions. A row that cannot be unwrapped fails the whole
  operation, so no row is left under the previous key.
- Vault folders expose names, hierarchy, and project environment tags. Tags are
  metadata and inherit through folder ancestry. Typed file contents are
  encrypted;
  supported labels are secret, env, kubeconfig, SSH private key, certificate,
  and text.
- MCP uses stdio and requires an AI-agent token. Global tokens read metadata;
  project-scoped tokens can create folders and typed files, save and restore
  file versions, and move files in their project. MCP never reveals or exports
  file values and offers no delete tools. Global and one-project tokens may use
  MCP; environment-scoped tokens remain rejected.
- `dpe_` agent tokens are restricted to one existing environment. They may run
  a command with that environment's decrypted secrets, create or update secret
  versions, inspect version metadata, and restore an old value as a new
  version. They cannot use MCP, call the secret-reveal or export paths, delete
  secrets or versions, or administer projects, folders, accounts, or the
  instance. These checks are enforced by the API. The default `dpa_` token remains
  metadata-only.
- `dpp_` agent tokens are scoped to one existing project. They can list that
  project's metadata and create or version its secrets, environments, and typed
  files. They cannot reveal or export secrets, delete data, or administer other
  projects. `dopbase run` can use their secrets, but the token can call the
  scoped runtime endpoint directly, so it cannot guarantee the agent is unable
  to read values.
- Dopbase does not print secret values during `dopbase run`, but passes them to
  the launched process as environment variables. The same scoped token can
  call the runtime endpoint directly. An agent holding it can therefore read
  or print those values; environment injection cannot provide a “use without
  being able to read” guarantee.
- The original UI retains copy/reveal for environment secrets. Vault files have
  reveal, edit, copy, hide, auto-hide, and version rollback controls.
- `dopbase migrate local-vault` reads the legacy `LVLT0001` file without
  modifying it, prompts for the old password without echo, and writes values
  through the Dopbase Vault API. Actual imports require a verified encrypted
  backup. The command ignores legacy agent-allow flags; MCP remains unable to
  reveal or delete values. Binary values stay base64 encoded and labeled. API entries map
  to generic secret files; legacy metadata and timestamps are not transferred.

## Limits and outstanding verification

- Plaintext exists in server memory during encryption/decryption and in the
  WebView while a human reveals or edits a value. Same-user malware can inspect
  local processes and loopback services; this is not an OS sandbox.
- The authenticated factory-reset API requires a root browser session. The
  separate offline `dopbase admin factory-reset` command operates directly on
  local files and does not use an agent token. A process with the same user's
  filesystem access can invoke local commands or modify files; scoped tokens
  are an API permission boundary, not a host sandbox.
- Folder and file names, types, version numbers, and timestamps are metadata and
  remain visible to authenticated AI-agent credentials where allowed.
- MCP modern discovery/tools-list and legacy initialize/tools-list were smoke-
  checked over stdio. An integration test uses a temporary `dpa_` token to
  confirm metadata/version/tree access works while reveal and writes return
  forbidden responses. This verifies the implemented role boundary, not an
  independent security audit.
- The production Vue UI built and type-checked; 213 UI tests passed, and a
  macOS `.app` bundle was created. The packaged executable returned a healthy
  response from an isolated temporary home. The Vault page's reveal/copy flow
  was not exercised interactively.
- The importer was not run against the user's vault. A synthetic offline
  `LVLT0001` dry-run passed with one encrypted entry, two retained revisions,
  nested folders, and UTF-8/Base64 encoding metadata. A full destination import
  and rollback were not exercised. Rust tests, UI tests, and strict clippy pass;
  Vault-page interaction and an independent security review remain outstanding.
- API transport is local HTTP because it binds to loopback. Remote deployments
  must continue to use HTTPS as documented by upstream Dopbase.

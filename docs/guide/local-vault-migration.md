# Migrate Local Vault data

The retired Tauri prototype stored data in a password-protected `LVLT0001`
file. Dopbase can import its current records and value revisions into the
encrypted Vault tree without changing that source file.

Preview the import first. Dry-run validates the old file and reports counts
without connecting to Dopbase or creating anything. The old vault password is
requested in a hidden prompt; it is never accepted on the command line or
echoed to the terminal:

```bash
dopbase migrate local-vault --folder "Imported vault" --dry-run
```

Then choose a new top-level folder and a new path for the encrypted backup:

```bash
dopbase migrate local-vault \
  --folder "Imported vault" \
  --backup "$HOME/local-vault-before-import.vault"
```

The backup path must not already exist. Dopbase creates it with owner-only
permissions and verifies its bytes before sending values to the server. Every
entry and folder name is checked against the Vault name rule before any write,
so dry-run and a real import reject the same names (including `.` and `..`).
Before writing, the CLI also rejects a destination folder that already exists
as a top-level folder of the project, compared case-insensitively.

The whole import is a single request to the server, and the server applies it
in one transaction. A failed import writes nothing, so no partial folder tree
or file remains, and the source file and the encrypted backup are never
modified. Deleting Vault folders and files remains an Admin UI operation, but a
failed import leaves nothing to delete. Resolve the reported problem and run
the import again.

The server enforces the import limits: at most 1000 entries, 1000 revisions per
entry, 1 MiB per revision, and 32 MiB in total. A folder path can have at most
160 characters and 32 levels. An import that exceeds a limit is rejected before
anything is written.

Legacy folder paths become nested folders. SSH, Kubernetes, environment, and
generic file entries retain their matching type; API entries become generic
secret files because Dopbase has no separate API credential file type. All
value revisions are imported in order. Base64 entries remain base64 text and
are labeled in the UI. Legacy metadata, audit timestamps, and `agent_allowed`
settings are not transferred. MCP remains metadata-only after import.

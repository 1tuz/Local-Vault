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
permissions and verifies its bytes before sending values to the server. An
existing destination folder is rejected. If an API request fails, the CLI
tries to remove the folders and files it created; it keeps the source and the
encrypted backup either way.

Legacy folder paths become nested folders. SSH, Kubernetes, environment, and
generic file entries retain their matching type; API entries become generic
secret files because Dopbase has no separate API credential file type. All
value revisions are imported in order. Base64 entries remain base64 text and
are labeled in the UI. Legacy metadata, audit timestamps, and `agent_allowed`
settings are not transferred. MCP remains metadata-only after import.

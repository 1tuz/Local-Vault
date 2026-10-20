CREATE TABLE secret_versions (
  environment_id TEXT NOT NULL,
  key TEXT NOT NULL,
  version INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  value_nonce BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  key_nonce BLOB NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  archived_at TEXT NOT NULL,
  PRIMARY KEY(environment_id, key, version),
  FOREIGN KEY(environment_id, key)
    REFERENCES secrets(environment_id, key) ON DELETE CASCADE
);

CREATE INDEX secret_versions_archived_at_idx
  ON secret_versions(environment_id, key, archived_at DESC);

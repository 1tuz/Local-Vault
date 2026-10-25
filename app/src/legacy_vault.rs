//! Read-only importer for the retired Local Vault `LVLT0001` container.
//!
//! This module never writes to the source vault. The decrypted SQLite image is
//! kept in zeroizing memory and imported values are re-encrypted by Dopbase.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::{io::Read, path::Path, ptr::NonNull};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"LVLT0001";
const MAX_VAULT_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 1000;
/// Matches `MAX_IMPORT_VERSIONS` in the Vault import service: the server
/// rejects a file with more revisions, so such an entry can never be imported.
const MAX_REVISIONS_PER_ENTRY: usize = 1000;

#[derive(Debug)]
pub struct LegacyEntry {
  pub name: String,
  pub folder: String,
  pub kind: String,
  pub versions: Vec<LegacyVersion>,
}

#[derive(Debug)]
pub struct LegacyVersion {
  pub version: i64,
  pub encoding: String,
  pub content: Zeroizing<String>,
}

impl Drop for LegacyEntry {
  fn drop(&mut self) {
    self.name.zeroize();
    self.folder.zeroize();
    self.kind.zeroize();
  }
}

/// Read a legacy vault without following a symlink and enforce its size limit.
pub fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
  let mut options = std::fs::OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
  }
  let file = options
    .open(path)
    .with_context(|| format!("could not open legacy vault {}", path.display()))?;
  let metadata = file
    .metadata()
    .context("could not inspect Local Vault file")?;
  if !metadata.is_file() {
    bail!("legacy vault path must be a regular file");
  }
  if metadata.len() > MAX_VAULT_BYTES as u64 {
    bail!("legacy vault exceeds the 32 MiB size limit");
  }
  let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
  file
    .take(MAX_VAULT_BYTES as u64 + 1)
    .read_to_end(&mut bytes)
    .with_context(|| format!("could not read legacy vault {}", path.display()))?;
  if bytes.len() > MAX_VAULT_BYTES {
    bail!("legacy vault exceeds the 32 MiB size limit");
  }
  Ok(bytes)
}

/// Decrypt, validate, and extract the stored values and revision history.
pub fn read_entries(
  bytes: &[u8],
  password: &str,
) -> Result<Vec<LegacyEntry>> {
  let plaintext = decrypt(bytes, password)?;
  let mut connection = Connection::open_in_memory().context("could not open import database")?;
  let allocation_size: i32 = plaintext
    .len()
    .try_into()
    .context("legacy vault database is too large")?;
  let allocation = unsafe { rusqlite::ffi::sqlite3_malloc(allocation_size).cast::<u8>() };
  let allocation = NonNull::new(allocation).context("could not allocate import database")?;
  unsafe {
    std::ptr::copy_nonoverlapping(plaintext.as_ptr(), allocation.as_ptr(), plaintext.len());
  }
  let database =
    unsafe { rusqlite::serialize::OwnedData::from_raw_nonnull(allocation, plaintext.len()) };
  connection
    .deserialize(rusqlite::DatabaseName::Main, database, true)
    .context("legacy vault database is invalid")?;
  let integrity: String = connection
    .query_row("PRAGMA integrity_check", [], |row| row.get(0))
    .context("could not verify legacy vault database")?;
  if integrity != "ok" {
    bail!("legacy vault database failed its integrity check");
  }

  let mut entries_statement = connection
    .prepare(
      "SELECT id,name,folder,kind,encoding,current_version FROM entries ORDER BY folder,name COLLATE NOCASE",
    )
    .context("legacy vault schema is unsupported")?;
  let rows = entries_statement
    .query_map([], |row| {
      Ok((
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, String>(2)?,
        row.get::<_, String>(3)?,
        row.get::<_, String>(4)?,
        row.get::<_, i64>(5)?,
      ))
    })
    .context("could not read legacy vault entries")?;
  let mut raw_entries = Vec::new();
  for row in rows {
    raw_entries.push(row.context("legacy vault entry is malformed")?);
    if raw_entries.len() > MAX_ENTRIES {
      bail!("legacy vault contains more than 1000 entries");
    }
  }
  drop(entries_statement);

  let mut result = Vec::with_capacity(raw_entries.len());
  for (id, name, folder, kind, encoding, current_version) in raw_entries {
    if current_version < 1 {
      bail!("entry {name:?} has an unsupported revision count");
    }
    if current_version as usize > MAX_REVISIONS_PER_ENTRY {
      bail!(
        "entry {name:?} has {current_version} revisions; Dopbase Vault stores at most {MAX_REVISIONS_PER_ENTRY} revisions per file"
      );
    }
    // One row past the limit is enough to reject the entry, so the query never
    // materialises an unbounded revision history.
    let mut versions_statement = connection
      .prepare(
        "SELECT version,content,snapshot FROM versions WHERE entry_id=?1 ORDER BY version LIMIT ?2",
      )
      .context("legacy vault revision schema is unsupported")?;
    let versions = versions_statement
      .query_map(params![id, MAX_REVISIONS_PER_ENTRY as i64 + 1], |row| {
        Ok((
          row.get::<_, i64>(0)?,
          row.get::<_, Vec<u8>>(1)?,
          row.get::<_, String>(2)?,
        ))
      })
      .context("could not read legacy vault revisions")?;
    let mut imported_versions = Vec::new();
    for version in versions {
      let (number, bytes, snapshot) = version.context("legacy vault revision is malformed")?;
      let snapshot: Value =
        serde_json::from_str(&snapshot).context("legacy vault revision metadata is malformed")?;
      let revision_encoding = snapshot
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or(&encoding);
      let bytes = Zeroizing::new(bytes);
      let value = match revision_encoding {
        "utf-8" => String::from_utf8(bytes.to_vec())
          .context("legacy entry is not valid UTF-8 and cannot be imported as text")?,
        "base64" => STANDARD.encode(bytes.as_slice()),
        _ => bail!("entry {name:?} uses an unsupported content encoding"),
      };
      if value.len() > 1024 * 1024 || value.contains('\0') {
        bail!("entry {name:?} contains content the new vault cannot store as text");
      }
      imported_versions.push(LegacyVersion {
        version: number,
        encoding: revision_encoding.to_owned(),
        content: Zeroizing::new(value),
      });
      if imported_versions.len() > MAX_REVISIONS_PER_ENTRY {
        bail!(
          "entry {name:?} has more than {MAX_REVISIONS_PER_ENTRY} revisions; Dopbase Vault stores at most {MAX_REVISIONS_PER_ENTRY} revisions per file"
        );
      }
    }
    if imported_versions.len() != current_version as usize
      || imported_versions
        .iter()
        .enumerate()
        .any(|(index, version)| version.version != index as i64 + 1)
    {
      bail!("entry {name:?} has missing or inconsistent revisions");
    }
    if imported_versions.is_empty() {
      bail!("entry {name:?} has no stored revisions");
    }
    result.push(LegacyEntry {
      name,
      folder,
      kind,
      versions: imported_versions,
    });
  }
  Ok(result)
}

fn decrypt(
  bytes: &[u8],
  password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
  if bytes.len() < 52 || bytes.len() > MAX_VAULT_BYTES || &bytes[..8] != MAGIC {
    bail!("unsupported or corrupt Local Vault format (expected LVLT0001)");
  }
  if password.is_empty() {
    bail!("Local Vault master password is required");
  }
  let salt = &bytes[8..24];
  let params = Params::new(65_536, 3, 2, Some(32))
    .map_err(|_| anyhow::anyhow!("invalid Argon2 parameters"))?;
  let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
  let mut key = Zeroizing::new([0_u8; 32]);
  argon
    .hash_password_into(password.as_bytes(), salt, key.as_mut())
    .map_err(|_| anyhow::anyhow!("could not derive Local Vault key"))?;
  let cipher = Aes256Gcm::new_from_slice(key.as_ref()).context("invalid Local Vault key")?;
  let mut aad = Vec::with_capacity(24);
  aad.extend_from_slice(MAGIC);
  aad.extend_from_slice(salt);
  let nonce = Nonce::from_slice(&bytes[24..36]);
  cipher
    .decrypt(
      nonce,
      Payload {
        msg: &bytes[36..],
        aad: &aad,
      },
    )
    .map(Zeroizing::new)
    .map_err(|_| anyhow::anyhow!("Local Vault password is incorrect or the file is damaged"))
}

#[cfg(test)]
mod tests {
  use super::{MAX_REVISIONS_PER_ENTRY, read_entries};
  use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
  };
  use argon2::{Algorithm, Argon2, Params, Version};
  use rusqlite::{Connection, DatabaseName, params};
  use std::sync::{
    LazyLock,
    atomic::{AtomicU64, Ordering},
  };

  const MAGIC: &[u8; 8] = b"LVLT0001";
  const SALT: [u8; 16] = *b"unit-test-salt-1";
  const PASSWORD: &str = "unit-test-master-password";
  const SCHEMA: &str = "
    CREATE TABLE entries (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      folder TEXT NOT NULL,
      kind TEXT NOT NULL,
      encoding TEXT NOT NULL,
      current_version INTEGER NOT NULL
    );
    CREATE TABLE versions (
      entry_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      content BLOB NOT NULL,
      snapshot TEXT NOT NULL
    );
  ";

  static KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let params = Params::new(65_536, 3, 2, Some(32)).unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon
      .hash_password_into(PASSWORD.as_bytes(), &SALT, &mut key)
      .unwrap();
    key
  });

  fn seal(plaintext: &[u8]) -> Vec<u8> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    let mut aad = Vec::with_capacity(24);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&SALT);
    let cipher = Aes256Gcm::new_from_slice(KEY.as_ref()).unwrap();
    let ciphertext = cipher
      .encrypt(
        Nonce::from_slice(&nonce),
        Payload {
          msg: plaintext,
          aad: &aad,
        },
      )
      .unwrap();
    let mut container = Vec::with_capacity(36 + ciphertext.len());
    container.extend_from_slice(MAGIC);
    container.extend_from_slice(&SALT);
    container.extend_from_slice(&nonce);
    container.extend_from_slice(&ciphertext);
    container
  }

  /// A sealed container whose single entry stores `rows` revisions while
  /// claiming `declared` of them.
  fn container(
    rows: i64,
    declared: i64,
  ) -> Vec<u8> {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(SCHEMA).unwrap();
    connection
      .execute(
        "INSERT INTO entries (id,name,folder,kind,encoding,current_version) VALUES (?1,?2,?3,?4,?5,?6)",
        params!["entry", "deploy.sh", "Ops", "secret", "utf-8", declared],
      )
      .unwrap();
    for version in 1..=rows {
      connection
        .execute(
          "INSERT INTO versions (entry_id,version,content,snapshot) VALUES (?1,?2,?3,?4)",
          params!["entry", version, b"value".to_vec(), "{}"],
        )
        .unwrap();
    }
    seal(&connection.serialize(DatabaseName::Main).unwrap())
  }

  #[test]
  fn accepts_the_server_limit_and_rejects_one_revision_more() {
    let entries = read_entries(
      &container(
        MAX_REVISIONS_PER_ENTRY as i64,
        MAX_REVISIONS_PER_ENTRY as i64,
      ),
      PASSWORD,
    )
    .expect("1000 revisions must be importable");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].versions.len(), MAX_REVISIONS_PER_ENTRY);

    let error = read_entries(
      &container(
        MAX_REVISIONS_PER_ENTRY as i64 + 1,
        MAX_REVISIONS_PER_ENTRY as i64 + 1,
      ),
      PASSWORD,
    )
    .expect_err("1001 revisions must be rejected");
    assert!(
      format!("{error:#}").contains("at most 1000"),
      "the declared revision count must be rejected before any read: {error:#}"
    );
  }

  #[test]
  fn rejects_rows_beyond_the_limit_even_when_the_count_lies() {
    // The entry claims 1000 revisions but stores 1001: the bounded query must
    // stop at one row past the limit and reject instead of reading everything.
    let error = read_entries(&container(1001, 1000), PASSWORD)
      .expect_err("an undeclared extra revision must be rejected");
    assert!(
      format!("{error:#}").contains("more than 1000"),
      "the row limit must reject before the whole history is materialised: {error:#}"
    );
  }
}

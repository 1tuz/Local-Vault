//! Read-only importer for the retired Local Vault `LVLT0001` container.
//!
//! This module never writes to the source vault. The decrypted SQLite image is
//! kept in zeroizing memory and imported values are re-encrypted by Dopbase.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::Connection;
use serde_json::Value;
use std::{io::Read, path::Path, ptr::NonNull};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"LVLT0001";
const MAX_VAULT_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 1000;

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
    if !(1..=10_000).contains(&current_version) {
      bail!("entry {name:?} has an unsupported revision count");
    }
    let mut versions_statement = connection
      .prepare("SELECT version,content,snapshot FROM versions WHERE entry_id=?1 ORDER BY version")
      .context("legacy vault revision schema is unsupported")?;
    let versions = versions_statement
      .query_map([id], |row| {
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

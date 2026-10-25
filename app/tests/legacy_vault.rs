//! Coverage for the read-only `LVLT0001` importer.
//!
//! Every container is built in-process: a synthetic SQLite image is created
//! with `rusqlite`, then sealed exactly like the retired Local Vault did
//! (Argon2id over a 16-byte salt, AES-256-GCM with `magic‖salt` as AAD).
//! No real vault file, password, or master key is involved.

use aes_gcm::{
  Aes256Gcm, KeyInit, Nonce,
  aead::{Aead, Payload},
};
use app::legacy_vault;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusqlite::{Connection, DatabaseName, params};
use std::sync::{
  LazyLock,
  atomic::{AtomicU64, Ordering},
};

const MAGIC: &[u8; 8] = b"LVLT0001";
const SALT: [u8; 16] = *b"fixture-salt-016";
const PASSWORD: &str = "synthetic-master-password";
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

struct Revision {
  version: i64,
  content: Vec<u8>,
  snapshot: String,
}

struct Entry {
  name: String,
  folder: String,
  kind: String,
  encoding: String,
  current_version: i64,
  revisions: Vec<Revision>,
}

fn entry(
  name: &str,
  folder: &str,
  kind: &str,
  encoding: &str,
) -> Entry {
  Entry {
    name: name.into(),
    folder: folder.into(),
    kind: kind.into(),
    encoding: encoding.into(),
    current_version: 0,
    revisions: Vec::new(),
  }
}

/// A text revision whose metadata falls back to the entry encoding.
fn text_revision(
  number: i64,
  content: &str,
) -> Revision {
  Revision {
    version: number,
    content: content.as_bytes().to_vec(),
    snapshot: "{}".into(),
  }
}

/// A revision whose metadata pins its own encoding.
fn encoded_revision(
  number: i64,
  content: &[u8],
  encoding: &str,
) -> Revision {
  Revision {
    version: number,
    content: content.to_vec(),
    snapshot: format!("{{\"encoding\":{}}}", serde_json::json!(encoding)),
  }
}

fn text_entry(
  name: &str,
  folder: &str,
  kind: &str,
  revisions: &[&str],
) -> Entry {
  let mut entry = entry(name, folder, kind, "utf-8");
  entry.revisions = revisions
    .iter()
    .enumerate()
    .map(|(index, content)| text_revision(index as i64 + 1, content))
    .collect();
  entry.current_version = entry.revisions.len() as i64;
  entry
}

fn base64_entry(
  name: &str,
  folder: &str,
  kind: &str,
  revisions: &[&[u8]],
) -> Entry {
  let mut entry = entry(name, folder, kind, "base64");
  entry.revisions = revisions
    .iter()
    .enumerate()
    .map(|(index, content)| encoded_revision(index as i64 + 1, content, "base64"))
    .collect();
  entry.current_version = entry.revisions.len() as i64;
  entry
}

/// Derived once per test binary; only AES-GCM runs per fixture.
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

fn database_image(entries: &[Entry]) -> Vec<u8> {
  let mut connection = Connection::open_in_memory().unwrap();
  connection.execute_batch(SCHEMA).unwrap();
  let transaction = connection.transaction().unwrap();
  for (index, entry) in entries.iter().enumerate() {
    let id = format!("entry-{index}");
    transaction
      .execute(
        "INSERT INTO entries (id,name,folder,kind,encoding,current_version) VALUES (?1,?2,?3,?4,?5,?6)",
        params![
          id,
          entry.name,
          entry.folder,
          entry.kind,
          entry.encoding,
          entry.current_version
        ],
      )
      .unwrap();
    for revision in &entry.revisions {
      transaction
        .execute(
          "INSERT INTO versions (entry_id,version,content,snapshot) VALUES (?1,?2,?3,?4)",
          params![id, revision.version, revision.content, revision.snapshot],
        )
        .unwrap();
    }
  }
  transaction.commit().unwrap();
  connection.serialize(DatabaseName::Main).unwrap().to_vec()
}

fn sealed_container(entries: &[Entry]) -> Vec<u8> {
  seal(&database_image(entries))
}

fn read(
  container: &[u8],
  password: &str,
) -> anyhow::Result<Vec<legacy_vault::LegacyEntry>> {
  legacy_vault::read_entries(container, password)
}

fn rejection(
  container: &[u8],
  password: &str,
) -> String {
  let error = read(container, password).expect_err("fixture should have been rejected");
  format!("{error:#}")
}

fn fixture() -> Vec<Entry> {
  let mut ssh = text_entry(
    "deploy.sh",
    "Ops/Prod",
    "ssh",
    &[
      "#!/bin/sh\necho first\n",
      "#!/bin/sh\necho second\n",
      "#!/bin/sh\necho third\n",
    ],
  );
  ssh.revisions[0].snapshot = "{}".into();
  ssh.revisions[2].snapshot = "{\"encoding\":\"utf-8\"}".into();

  vec![
    base64_entry(
      "Binary blob.bin",
      "Dev",
      "secret",
      &[&[0x00, 0xff, 0x10, 0x7f], &[0x01, 0x02]],
    ),
    text_entry("notes.txt", "Dev", "file", &["plain notes\n"]),
    text_entry("registry token", "Dev", "api", &["tok_first"]),
    text_entry("api.env", "Ops", "env", &["TOKEN=one\n"]),
    ssh,
    text_entry(
      "kube.yaml",
      "Ops/Prod/Cluster",
      "kubeconfig",
      &["apiVersion: v1\n"],
    ),
  ]
}

#[test]
fn reads_entries_folders_kinds_encodings_and_revisions() {
  let entries = read(&sealed_container(&fixture()), PASSWORD).unwrap();

  let names: Vec<_> = entries.iter().map(|entry| entry.name.as_str()).collect();
  assert_eq!(
    names,
    [
      "Binary blob.bin",
      "notes.txt",
      "registry token",
      "api.env",
      "deploy.sh",
      "kube.yaml",
    ],
    "entries must be ordered by folder then name"
  );
  let folders: Vec<_> = entries.iter().map(|entry| entry.folder.as_str()).collect();
  assert_eq!(
    folders,
    ["Dev", "Dev", "Dev", "Ops", "Ops/Prod", "Ops/Prod/Cluster"]
  );
  let kinds: Vec<_> = entries.iter().map(|entry| entry.kind.as_str()).collect();
  assert_eq!(kinds, ["secret", "file", "api", "env", "ssh", "kubeconfig"]);
  let encodings: Vec<_> = entries
    .iter()
    .map(|entry| entry.versions[0].encoding.as_str())
    .collect();
  assert_eq!(
    encodings,
    ["base64", "utf-8", "utf-8", "utf-8", "utf-8", "utf-8"]
  );

  let binary = &entries[0];
  assert_eq!(binary.versions.len(), 2);
  let numbers: Vec<_> = binary
    .versions
    .iter()
    .map(|version| version.version)
    .collect();
  assert_eq!(numbers, [1, 2]);
  assert_eq!(
    binary.versions[0].content.as_str(),
    STANDARD.encode([0x00, 0xff, 0x10, 0x7f])
  );
  assert_eq!(
    binary.versions[1].content.as_str(),
    STANDARD.encode([0x01, 0x02])
  );
  assert_eq!(
    STANDARD
      .decode(binary.versions[0].content.as_str())
      .unwrap(),
    [0x00, 0xff, 0x10, 0x7f],
    "base64 content must round-trip to the stored bytes"
  );
  assert!(
    binary
      .versions
      .iter()
      .all(|version| version.encoding == "base64")
  );

  assert_eq!(entries[1].versions.len(), 1);
  assert_eq!(entries[1].versions[0].content.as_str(), "plain notes\n");

  let ssh = &entries[4];
  assert_eq!(ssh.versions.len(), 3);
  let numbers: Vec<_> = ssh.versions.iter().map(|version| version.version).collect();
  assert_eq!(numbers, [1, 2, 3]);
  assert_eq!(ssh.versions[0].content.as_str(), "#!/bin/sh\necho first\n");
  assert_eq!(ssh.versions[1].content.as_str(), "#!/bin/sh\necho second\n");
  assert_eq!(ssh.versions[2].content.as_str(), "#!/bin/sh\necho third\n");
  assert!(
    ssh
      .versions
      .iter()
      .all(|version| version.encoding == "utf-8"),
    "revision metadata without encoding must inherit the entry encoding"
  );

  assert_eq!(entries[5].folder, "Ops/Prod/Cluster");
  assert_eq!(entries[5].versions[0].content.as_str(), "apiVersion: v1\n");
}

#[test]
fn rejects_a_wrong_password() {
  let container = sealed_container(&fixture());
  let error = rejection(&container, "not-the-password");
  assert!(
    error.contains("password is incorrect or the file is damaged"),
    "{error}"
  );
}

#[test]
fn rejects_a_bad_magic_and_a_short_file() {
  let mut container = sealed_container(&fixture());
  container[..8].copy_from_slice(b"LVLT0002");
  assert!(
    rejection(&container, PASSWORD).contains("unsupported or corrupt Local Vault format"),
    "bad magic must be rejected before key derivation"
  );

  let valid = sealed_container(&fixture());
  for bytes in [&valid[..0], &valid[..8], &valid[..51]] {
    let error = rejection(bytes, PASSWORD);
    assert!(
      error.contains("unsupported or corrupt Local Vault format"),
      "short files must be rejected: {error}"
    );
  }
}

#[test]
fn rejects_a_truncated_container() {
  let container = sealed_container(&fixture());
  let truncated = &container[..container.len() - 1];
  let error = rejection(truncated, PASSWORD);
  assert!(
    error.contains("password is incorrect or the file is damaged"),
    "truncated ciphertext must fail authentication: {error}"
  );
}

#[test]
fn rejects_an_invalid_sqlite_image() {
  let error = rejection(&seal(b"this is not a SQLite database image"), PASSWORD);
  assert!(
    error.contains("legacy vault database"),
    "a sealed non-SQLite payload must be rejected as a database: {error}"
  );
}

#[test]
fn rejects_a_revision_gap() {
  let mut missing = text_entry("gap", "Ops", "secret", &["one", "two"]);
  missing.current_version = 3;
  let error = rejection(&sealed_container(&[missing]), PASSWORD);
  assert!(
    error.contains("missing or inconsistent revisions"),
    "current_version must match the stored revision count: {error}"
  );

  let mut skipped = text_entry("skip", "Ops", "secret", &["one"]);
  skipped.revisions.push(text_revision(3, "three"));
  skipped.current_version = 2;
  let error = rejection(&sealed_container(&[skipped]), PASSWORD);
  assert!(
    error.contains("missing or inconsistent revisions"),
    "revision numbers must be contiguous: {error}"
  );

  let mut unsupported = text_entry("zero", "Ops", "secret", &["one"]);
  unsupported.current_version = 0;
  let error = rejection(&sealed_container(&[unsupported]), PASSWORD);
  assert!(
    error.contains("unsupported revision count"),
    "a non-positive current_version must be rejected: {error}"
  );
}

#[test]
fn rejects_an_unsupported_revision_encoding() {
  let mut entry = text_entry("utf16", "Ops", "secret", &["one"]);
  entry.revisions[0].snapshot = "{\"encoding\":\"utf-16\"}".into();
  let error = rejection(&sealed_container(&[entry]), PASSWORD);
  assert!(error.contains("unsupported content encoding"), "{error}");
}

#[test]
fn rejects_content_with_a_nul_byte() {
  let mut entry = text_entry("nul", "Ops", "secret", &["one"]);
  entry.revisions[0].content = b"before\0after".to_vec();
  let error = rejection(&sealed_container(&[entry]), PASSWORD);
  assert!(
    error.contains("cannot store as text"),
    "NUL content must be rejected before it reaches the API: {error}"
  );
}

#[test]
fn rejects_content_over_one_mebibyte() {
  let oversized = "a".repeat(1024 * 1024 + 1);
  let entry = text_entry("large", "Ops", "secret", &[oversized.as_str()]);
  let error = rejection(&sealed_container(&[entry]), PASSWORD);
  assert!(
    error.contains("cannot store as text"),
    "content above 1 MiB must be rejected: {error}"
  );
}

#[test]
fn rejects_more_than_one_thousand_entries() {
  let entries: Vec<_> = (0..1001)
    .map(|index| text_entry(&format!("entry-{index:04}"), "Ops", "secret", &["value"]))
    .collect();
  let error = rejection(&sealed_container(&entries), PASSWORD);
  assert!(error.contains("more than 1000 entries"), "{error}");
}

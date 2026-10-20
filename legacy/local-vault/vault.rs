use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fs2::FileExt;
use rand::TryRngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    path::PathBuf,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"LVLT0001";
const MAX_VAULT: u64 = 32 * 1024 * 1024;
const MAX_IMPORT: usize = 4 * 1024 * 1024;
const MAX_CONTENT: usize = 1024 * 1024;
const KINDS: &[&str] = &["secret", "ssh", "kubeconfig", "env", "api", "file"];

type Result<T> = std::result::Result<T, String>;

pub struct Vault {
    path: PathBuf,
    conn: Option<Connection>,
    salt: Option<[u8; 16]>,
    key: Option<Zeroizing<[u8; 32]>>,
    lock_file: Option<File>,
}

impl Vault {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            conn: None,
            salt: None,
            key: None,
            lock_file: None,
        }
    }

    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join(".local")
            .join("share")
            .join("local-vault")
            .join("secrets.vault")
    }

    pub fn exists(&self) -> bool {
        self.path.is_file()
    }
    pub fn unlocked(&self) -> bool {
        self.conn.is_some()
    }

    fn hold_lock(&mut self) -> Result<()> {
        let parent = self.path.parent().ok_or("Invalid vault path")?;
        fs::create_dir_all(parent).map_err(err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(err)?;
        }
        let lock_path = self.path.with_file_name(format!(
            "{}.lock",
            self.path.file_name().unwrap_or_default().to_string_lossy()
        ));
        if self.path.is_symlink() || lock_path.is_symlink() {
            return Err("Symlink vault paths are prohibited".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(lock_path).map_err(err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(err)?;
        }
        file.try_lock_exclusive()
            .map_err(|_| "Vault is opened by another process".to_string())?;
        self.lock_file = Some(file);
        Ok(())
    }

    fn release_lock(&mut self) {
        if let Some(file) = self.lock_file.take() {
            let _ = FileExt::unlock(&file);
        }
    }

    fn connect() -> Result<Connection> {
        let conn = Connection::open_in_memory().map_err(err)?;
        conn.execute_batch("PRAGMA foreign_keys=ON;
          CREATE TABLE entries (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, folder TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL, encoding TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}',
            agent_allowed INTEGER NOT NULL DEFAULT 0, current_version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
          );
          CREATE TABLE versions (
            entry_id TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
            version INTEGER NOT NULL, content BLOB NOT NULL, created_at TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '', snapshot TEXT NOT NULL,
            PRIMARY KEY(entry_id, version)
          );
          CREATE TABLE audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, entry_id TEXT, at TEXT NOT NULL
          );
          CREATE INDEX idx_version_history ON versions(entry_id, version);")
            .map_err(err)?;
        Ok(conn)
    }

    pub fn create(&mut self, password: &str) -> Result<()> {
        if password.chars().count() < 12 {
            return Err("Master password must have at least 12 characters".into());
        }
        if self.path.exists() {
            return Err("Vault already exists".into());
        }
        self.hold_lock()?;
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.try_fill_bytes(&mut salt).map_err(err)?;
        self.conn = match Self::connect() {
            Ok(conn) => Some(conn),
            Err(error) => {
                self.release_lock();
                return Err(error);
            }
        };
        self.salt = Some(salt);
        self.key = Some(Zeroizing::new(derive_key(password, &salt)?));
        if let Err(error) = self.persist(true) {
            self.lock();
            return Err(error);
        }
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        if self.unlocked() {
            return Err("Vault is already unlocked".into());
        }
        if !self.path.is_file() || self.path.is_symlink() {
            return Err("Vault does not exist or is not a regular file".into());
        }
        self.hold_lock()?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .read(true)
                .open(&self.path)
                .map_err(err)?;
            if file.metadata().map_err(err)?.len() > MAX_VAULT {
                return Err("Vault file is too large".into());
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(err)?;
            let (salt, key, plain) = decrypt(password, &bytes)?;
            let mut conn = Connection::open_in_memory().map_err(err)?;
            conn.deserialize_read_exact("main", Cursor::new(plain.as_slice()), plain.len(), false)
                .map_err(err)?;
            let integrity: String = conn
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .map_err(err)?;
            if integrity != "ok" {
                return Err("Vault database is corrupt".into());
            }
            conn.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get::<_, i64>(0))
                .map_err(|_| "Unsupported vault database".to_string())?;
            self.conn = Some(conn);
            self.salt = Some(salt);
            self.key = Some(Zeroizing::new(key));
            Ok(())
        })();
        if result.is_err() {
            self.lock();
        }
        result
    }

    pub fn lock(&mut self) {
        self.conn.take();
        self.salt.take();
        if let Some(mut key) = self.key.take() {
            key.zeroize();
        }
        self.release_lock();
    }

    pub fn list_entries(&self) -> Result<Vec<Value>> {
        let conn = self.db()?;
        let mut stmt = conn.prepare("SELECT id,name,folder,kind,encoding,agent_allowed,current_version,created_at,updated_at FROM entries ORDER BY folder,name COLLATE NOCASE").map_err(err)?;
        let rows = stmt.query_map([], |r| Ok(json!({
            "id":r.get::<_,String>(0)?, "name":r.get::<_,String>(1)?, "folder":r.get::<_,String>(2)?,
            "kind":r.get::<_,String>(3)?, "encoding":r.get::<_,String>(4)?, "agent_allowed":r.get::<_,bool>(5)?,
            "current_version":r.get::<_,i64>(6)?, "created_at":r.get::<_,String>(7)?, "updated_at":r.get::<_,String>(8)?
        }))).map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)
    }

    pub fn get_entry(&self, id: &str, version: Option<i64>) -> Result<Value> {
        let conn = self.db()?;
        let entry: Option<(String,String,String,String,i64,String)> = conn.query_row(
            "SELECT name,folder,kind,encoding,current_version,metadata FROM entries WHERE id=?1", [id],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))
        ).optional().map_err(err)?;
        let (name, folder, kind, encoding, current, metadata) = entry.ok_or("Entry not found")?;
        let v = version.unwrap_or(current);
        let revision: Option<(Vec<u8>, String, String)> = conn
            .query_row(
                "SELECT content,snapshot,created_at FROM versions WHERE entry_id=?1 AND version=?2",
                params![id, v],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(err)?;
        let (blob, snapshot, created_at) = revision.ok_or("Version not found")?;
        let snapshot: Value = serde_json::from_str(&snapshot).map_err(err)?;
        let content = if encoding == "base64" {
            STANDARD.encode(blob)
        } else {
            String::from_utf8(blob).map_err(err)?
        };
        let mut out = json!({"id":id,"name":name,"folder":folder,"kind":kind,"encoding":encoding,
            "current_version":current,"metadata":serde_json::from_str::<Value>(&metadata).map_err(err)?,
            "created_at":created_at,"selected_version":v,"content":content});
        if let Some(obj) = out.as_object_mut()
            && let Some(fields) = snapshot.as_object()
        {
            for (k, v) in fields {
                obj.insert(k.clone(), v.clone());
            }
        }
        Ok(out)
    }

    pub fn versions(&self, id: &str) -> Result<Vec<Value>> {
        let conn = self.db()?;
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM entries WHERE id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(err)?;
        if !exists {
            return Err("Entry not found".into());
        }
        let mut stmt = conn.prepare("SELECT version,created_at,note,length(content) FROM versions WHERE entry_id=?1 ORDER BY version DESC").map_err(err)?;
        let rows = stmt.query_map([id], |r| Ok(json!({"version":r.get::<_,i64>(0)?,"created_at":r.get::<_,String>(1)?,"note":r.get::<_,String>(2)?,"bytes":r.get::<_,i64>(3)?}))).map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)
    }

    pub fn put_entry(&mut self, input: Value, id: Option<&str>) -> Result<Value> {
        let entry = validate_entry(input)?;
        let now = now();
        let conn = self.db_mut()?;
        let tx = conn.transaction().map_err(err)?;
        let (entry_id, version) = if let Some(id) = id {
            let current: Option<i64> = tx
                .query_row(
                    "SELECT current_version FROM entries WHERE id=?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(err)?;
            let current = current.ok_or("Entry not found")?;
            tx.execute("UPDATE entries SET name=?1,folder=?2,kind=?3,encoding=?4,metadata=?5,agent_allowed=?6,current_version=?7,updated_at=?8 WHERE id=?9",
                params![entry.name,entry.folder,entry.kind,entry.encoding,entry.metadata.to_string(),entry.agent_allowed,current+1,now,id]).map_err(err)?;
            (id.to_string(), current + 1)
        } else {
            let id = Uuid::new_v4().simple().to_string();
            tx.execute("INSERT INTO entries(id,name,folder,kind,encoding,metadata,agent_allowed,current_version,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,?8)",
                params![id,entry.name,entry.folder,entry.kind,entry.encoding,entry.metadata.to_string(),entry.agent_allowed,now]).map_err(err)?;
            (id, 1)
        };
        let snapshot = json!({"name":entry.name,"folder":entry.folder,"kind":entry.kind,"encoding":entry.encoding,"metadata":entry.metadata,"agent_allowed":entry.agent_allowed}).to_string();
        tx.execute("INSERT INTO versions(entry_id,version,content,created_at,note,snapshot) VALUES(?1,?2,?3,?4,?5,?6)",params![entry_id,version,entry.blob,now,entry.note,snapshot]).map_err(err)?;
        tx.execute(
            "INSERT INTO audit(event,entry_id,at) VALUES('save',?1,?2)",
            params![entry_id, now],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        self.persist_or_lock()?;
        self.list_entries()?
            .into_iter()
            .find(|e| e["id"] == entry_id)
            .ok_or_else(|| "Entry not found after save".into())
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        let conn = self.db_mut()?;
        let tx = conn.transaction().map_err(err)?;
        let n = tx
            .execute("DELETE FROM entries WHERE id=?1", [id])
            .map_err(err)?;
        if n == 0 {
            return Err("Entry not found".into());
        }
        tx.execute(
            "INSERT INTO audit(event,entry_id,at) VALUES('delete',?1,?2)",
            params![id, now()],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        self.persist_or_lock()
    }

    pub fn rollback(&mut self, id: &str, target: i64) -> Result<Value> {
        let old = self.get_entry(id, Some(target))?;
        let mut input = old.clone();
        input["note"] = json!(format!("Rollback to v{target}"));
        self.put_entry(input, Some(id))
    }

    pub fn import_entries(&mut self, raw: &str, format: &str) -> Result<usize> {
        if raw.len() > MAX_IMPORT {
            return Err("Import is larger than 4 MiB".into());
        }
        let data: Value = match format {
            "json" => serde_json::from_str(raw).map_err(|_| "Invalid import syntax")?,
            "yaml" => serde_yaml::from_str(raw).map_err(|_| "Invalid import syntax")?,
            _ => return Err("Only yaml or json import supported".into()),
        };
        if data["format"] != "local-vault-export-v1" {
            return Err("Not a supported Local Vault export".into());
        }
        let entries = data["entries"]
            .as_array()
            .ok_or("Expected entries list (max 1000)")?;
        if entries.len() > 1000 {
            return Err("Expected entries list (max 1000)".into());
        }
        let checked = entries
            .iter()
            .cloned()
            .map(|mut v| {
                if v.get("note").is_none() {
                    v["note"] = json!("");
                }
                validate_entry(v)
            })
            .collect::<Result<Vec<_>>>()?;
        let now = now();
        let conn = self.db_mut()?;
        let tx = conn.transaction().map_err(err)?;
        for e in &checked {
            let id = Uuid::new_v4().simple().to_string();
            tx.execute("INSERT INTO entries(id,name,folder,kind,encoding,metadata,agent_allowed,current_version,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,?8)",params![id,e.name,e.folder,e.kind,e.encoding,e.metadata.to_string(),e.agent_allowed,now]).map_err(err)?;
            let snapshot=json!({"name":e.name,"folder":e.folder,"kind":e.kind,"encoding":e.encoding,"metadata":e.metadata,"agent_allowed":e.agent_allowed}).to_string();
            tx.execute("INSERT INTO versions(entry_id,version,content,created_at,note,snapshot) VALUES(?1,1,?2,?3,'',?4)",params![id,e.blob,now,snapshot]).map_err(err)?;
        }
        tx.execute("INSERT INTO audit(event,at) VALUES('import',?1)", [now])
            .map_err(err)?;
        tx.commit().map_err(err)?;
        self.persist_or_lock()?;
        Ok(checked.len())
    }

    pub fn export_entries(&self, format: &str) -> Result<String> {
        let mut items = Vec::new();
        for row in self.list_entries()? {
            let entry = self.get_entry(row["id"].as_str().ok_or("Invalid entry id")?, None)?;
            items.push(json!({"name":entry["name"],"folder":entry["folder"],"kind":entry["kind"],"encoding":entry["encoding"],"content":entry["content"],"metadata":entry["metadata"],"agent_allowed":entry["agent_allowed"]}));
        }
        let data = json!({"format":"local-vault-export-v1","entries":items});
        match format {
            "json" => serde_json::to_string_pretty(&data).map_err(err),
            "yaml" => serde_yaml::to_string(&data).map_err(err),
            _ => Err("Only yaml or json export supported".into()),
        }
    }

    pub fn audit(&self) -> Result<Vec<Value>> {
        let mut stmt = self
            .db()?
            .prepare("SELECT event,entry_id,at FROM audit ORDER BY id DESC LIMIT 100")
            .map_err(err)?;
        let rows=stmt.query_map([],|r|Ok(json!({"event":r.get::<_,String>(0)?,"entry_id":r.get::<_,Option<String>>(1)?,"at":r.get::<_,String>(2)?}))).map_err(err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)
    }

    fn db(&self) -> Result<&Connection> {
        self.conn.as_ref().ok_or_else(|| "Vault is locked".into())
    }
    fn db_mut(&mut self) -> Result<&mut Connection> {
        self.conn.as_mut().ok_or_else(|| "Vault is locked".into())
    }
    fn persist_or_lock(&mut self) -> Result<()> {
        if let Err(e) = self.persist(false) {
            self.lock();
            Err(e)
        } else {
            Ok(())
        }
    }

    fn persist(&self, initial: bool) -> Result<()> {
        let conn = self.db()?;
        let salt = self.salt.as_ref().ok_or("Vault is locked")?;
        let key = self.key.as_ref().ok_or("Vault is locked")?;
        let plain = conn.serialize("main").map_err(err)?;
        if plain.len() as u64 > MAX_VAULT {
            return Err("Vault exceeds 32 MiB maximum".into());
        }
        let bytes = encrypt(key, salt, &plain)?;
        let temp = self.path.with_file_name(format!(
            ".{}.tmp-{}",
            self.path.file_name().unwrap_or_default().to_string_lossy(),
            Uuid::new_v4().simple()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let result = (|| {
            let mut file = options.open(&temp).map_err(err)?;
            file.write_all(&bytes).map_err(err)?;
            file.sync_all().map_err(err)?;
            if initial {
                fs::hard_link(&temp, &self.path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        "Vault already exists".to_string()
                    } else {
                        err(e)
                    }
                })?;
                fs::remove_file(&temp).map_err(err)?;
            } else {
                fs::rename(&temp, &self.path).map_err(err)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).map_err(err)?;
            }
            if let Some(parent) = self.path.parent() {
                File::open(parent).and_then(|f| f.sync_all()).map_err(err)?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}

struct Validated {
    name: String,
    folder: String,
    kind: String,
    encoding: String,
    metadata: Value,
    agent_allowed: bool,
    note: String,
    blob: Vec<u8>,
}

fn validate_entry(v: Value) -> Result<Validated> {
    let name = v["name"]
        .as_str()
        .ok_or("Name must be between 1 and 120 characters")?
        .trim()
        .to_string();
    if name.is_empty() || name.chars().count() > 120 {
        return Err("Name must be between 1 and 120 characters".into());
    }
    let kind = v["kind"]
        .as_str()
        .ok_or("Unsupported secret kind")?
        .to_string();
    if !KINDS.contains(&kind.as_str()) {
        return Err("Unsupported secret kind".into());
    }
    let encoding = v
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("utf-8")
        .to_string();
    if !["utf-8", "base64"].contains(&encoding.as_str()) {
        return Err("Unsupported content encoding".into());
    }
    let content = v["content"].as_str().ok_or("Content must be a string")?;
    let blob = if encoding == "base64" {
        STANDARD
            .decode(content)
            .map_err(|_| "Invalid base64 content")?
    } else {
        content.as_bytes().to_vec()
    };
    if blob.len() > MAX_CONTENT {
        return Err("Entry exceeds 1 MiB maximum".into());
    }
    let folder = v
        .get("folder")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if folder.chars().count() > 160 {
        return Err("Invalid folder".into());
    }
    let metadata = v.get("metadata").cloned().unwrap_or_else(|| json!({}));
    let object = metadata.as_object().ok_or("Metadata must be an object")?;
    if object
        .values()
        .any(|v| !(v.is_string() || v.is_boolean() || v.is_number()))
        || metadata.to_string().len() > 8192
    {
        return Err("Metadata only accepts scalar values and must be under 8 KiB".into());
    }
    let agent_allowed = v
        .get("agent_allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if agent_allowed && !["api", "ssh"].contains(&kind.as_str()) {
        return Err("Agent access is only available for API and SSH entries".into());
    }
    let note = v
        .get("note")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if note.len() > 500 {
        return Err("Invalid note".into());
    }
    Ok(Validated {
        name,
        folder,
        kind,
        encoding,
        metadata,
        agent_allowed,
        note,
        blob,
    })
}

fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
    if password.is_empty() {
        return Err("Master password is required".into());
    }
    let params = Params::new(65536, 3, 2, Some(32)).map_err(err)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(err)?;
    Ok(key)
}

fn encrypt(key: &[u8; 32], salt: &[u8; 16], plain: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(err)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(err)?;
    let mut aad = Vec::from(MAGIC.as_slice());
    aad.extend_from_slice(salt);
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| "Encryption failed")?;
    let mut out = Vec::with_capacity(36 + encrypted.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

type Decrypted = ([u8; 16], [u8; 32], Zeroizing<Vec<u8>>);

fn decrypt(password: &str, bytes: &[u8]) -> Result<Decrypted> {
    if bytes.len() < 52 || bytes.len() as u64 > MAX_VAULT || &bytes[..8] != MAGIC {
        return Err("Unsupported or corrupt vault format".into());
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[8..24]);
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(err)?;
    let mut aad = Vec::from(MAGIC.as_slice());
    aad.extend_from_slice(&salt);
    let nonce: [u8; 12] = bytes[24..36].try_into().map_err(err)?;
    let plain = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &bytes[36..],
                aad: &aad,
            },
        )
        .map_err(|_| "Wrong password or damaged vault")?;
    Ok((salt, key, Zeroizing::new(plain)))
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sqlite_container_roundtrip_versions_rollback_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault");
        let mut vault = Vault::new(path.clone());
        vault.create("synthetic master password").unwrap();
        let input = |value: &str| json!({"name":"API","kind":"api","encoding":"utf-8","content":value,"metadata":{"base_url":"https://example.invalid"},"agent_allowed":true});
        let first = vault.put_entry(input("first"), None).unwrap();
        let id = first["id"].as_str().unwrap().to_string();
        vault.put_entry(input("second"), Some(&id)).unwrap();
        vault.put_entry(input("third"), Some(&id)).unwrap();
        vault.rollback(&id, 1).unwrap();
        assert_eq!(vault.get_entry(&id, None).unwrap()["content"], "first");
        assert_eq!(vault.versions(&id).unwrap().len(), 4);
        vault.lock();
        assert_eq!(&fs::read(&path).unwrap()[..8], MAGIC);
        assert!(vault.unlock("wrong password").is_err());
        vault.unlock("synthetic master password").unwrap();
        assert_eq!(vault.get_entry(&id, None).unwrap()["content"], "first");
    }

    #[test]
    fn import_validation_is_atomic_and_yaml_json_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::new(dir.path().join("test.vault"));
        vault.create("synthetic master password").unwrap();
        let input = json!({"format":"local-vault-export-v1","entries":[{"name":"line","kind":"kubeconfig","content":"a\nb\n"}]});
        let raw = serde_yaml::to_string(&input).unwrap();
        assert_eq!(vault.import_entries(&raw, "yaml").unwrap(), 1);
        let exported = vault.export_entries("json").unwrap();
        assert_eq!(vault.import_entries(&exported, "json").unwrap(), 1);
        let count = vault.list_entries().unwrap().len();
        let bad = r#"{"format":"local-vault-export-v1","entries":[{"name":"ok","kind":"secret","content":"x"},{"name":"bad","kind":"unknown","content":"x"}]}"#;
        assert!(vault.import_entries(bad, "json").is_err());
        assert_eq!(vault.list_entries().unwrap().len(), count);
    }
}

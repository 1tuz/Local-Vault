use std::{
  fs,
  io::{Read, Write},
  os::unix::{
    fs::{FileTypeExt, MetadataExt, PermissionsExt},
    net::UnixStream,
  },
  path::PathBuf,
  time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use url::{Host, Url};

use crate::{cli::local_config::ResolvedServer, config::dopbase_home};

const SOCKET_NAME: &str = "desktop-session.sock";
const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Deserialize)]
pub(super) struct DesktopSession {
  pub token: String,
  pub csrf_token: String,
}

pub(super) fn current(server: &ResolvedServer) -> Result<Option<DesktopSession>> {
  let socket_path = socket_path();
  let Some(parent) = socket_path.parent() else {
    return Ok(None);
  };
  let Ok(parent_metadata) = fs::metadata(parent) else {
    return Ok(None);
  };
  if parent_metadata.permissions().mode() & 0o077 != 0 {
    return Ok(None);
  }
  let Ok(metadata) = fs::symlink_metadata(&socket_path) else {
    return Ok(None);
  };
  if !metadata.file_type().is_socket()
    || metadata.permissions().mode() & 0o777 != 0o600
    || metadata.uid() != parent_metadata.uid()
  {
    return Ok(None);
  }
  let url = Url::parse(&server.url).context("invalid configured Dopbase URL")?;
  if !matches!(url.host(), Some(Host::Ipv4(host)) if host.is_loopback())
    && !matches!(url.host(), Some(Host::Ipv6(host)) if host.is_loopback())
    && !matches!(url.host(), Some(Host::Domain(host)) if host.eq_ignore_ascii_case("localhost"))
  {
    return Ok(None);
  }
  let mut stream = match UnixStream::connect(&socket_path) {
    Ok(stream) => stream,
    Err(error)
      if matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
      ) =>
    {
      return Ok(None);
    }
    Err(error) => {
      return Err(error).context("could not connect to the Dopbase desktop session broker");
    }
  };
  stream.set_read_timeout(Some(Duration::from_secs(2)))?;
  stream.set_write_timeout(Some(Duration::from_secs(2)))?;
  writeln!(stream, "{}", server.url)?;
  let mut response = Vec::new();
  stream
    .take((MAX_RESPONSE_BYTES + 1) as u64)
    .read_to_end(&mut response)?;
  if response.len() > MAX_RESPONSE_BYTES {
    bail!("Dopbase desktop session response exceeded its size limit");
  }
  if response.is_empty() || response == b"null\n" {
    return Ok(None);
  }
  let session: DesktopSession = serde_json::from_slice(&response)
    .context("Dopbase desktop session broker returned an invalid response")?;
  if session.token.is_empty() || session.csrf_token.is_empty() {
    return Ok(None);
  }
  Ok(Some(session))
}

pub(super) fn socket_path() -> PathBuf {
  dopbase_home().join(SOCKET_NAME)
}

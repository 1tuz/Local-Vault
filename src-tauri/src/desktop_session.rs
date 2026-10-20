#![cfg(unix)]

use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixListener as StdUnixListener,
    },
    path::PathBuf,
};

use serde::Serialize;
use tauri::{AppHandle, Manager, WebviewWindow};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use url::{Host, Url};

const SOCKET_NAME: &str = "desktop-session.sock";

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    csrf_token: String,
}

pub fn start(handle: AppHandle, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path();
    let parent = path
        .parent()
        .ok_or("session socket has no parent directory")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    remove_stale_socket(&path)?;
    let listener = StdUnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(listener)?;

    tauri::async_runtime::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let handle = handle.clone();
            tokio::spawn(async move {
                if let Err(error) = serve_client(stream, handle, port).await {
                    eprintln!("Dopbase desktop session request failed: {error}");
                }
            });
        }
    });
    Ok(())
}

async fn serve_client(
    stream: UnixStream,
    handle: AppHandle,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read).take(2048).read_line(&mut line).await?;
    let response = match requested_url(&line, port) {
        Some(url) => browser_session(handle, url).await.unwrap_or(None),
        None => None,
    };
    let body = serde_json::to_vec(&response)?;
    write.write_all(&body).await?;
    write.write_all(b"\n").await?;
    Ok(())
}

fn requested_url(value: &str, port: u16) -> Option<Url> {
    let mut url = Url::parse(value.trim()).ok()?;
    if url.scheme() != "http" || url.port_or_known_default()? != port {
        return None;
    }
    match url.host()? {
        Host::Ipv4(host) if host.is_loopback() => {}
        Host::Ipv6(host) if host.is_loopback() => {}
        Host::Domain(host) if host.eq_ignore_ascii_case("localhost") => {
            url.set_host(Some("127.0.0.1")).ok()?;
        }
        _ => return None,
    }
    Some(url)
}

async fn browser_session(
    handle: AppHandle,
    url: Url,
) -> Result<Option<SessionResponse>, Box<dyn std::error::Error + Send + Sync>> {
    let result = tokio::task::spawn_blocking(move || {
        handle
            .get_webview_window("main")
            .ok_or_else(|| "Dopbase window is unavailable".to_owned())
            .and_then(|window| read_session_cookie(&window, url).map_err(|error| error.to_string()))
    })
    .await
    .map_err(std::io::Error::other)?
    .map_err(std::io::Error::other)?;
    Ok(result)
}

fn read_session_cookie(window: &WebviewWindow, url: Url) -> tauri::Result<Option<SessionResponse>> {
    let Some(host) = url.host_str() else {
        return Ok(None);
    };
    let cookies = window.cookies()?;
    let token = cookies
        .iter()
        .find(|cookie| {
            cookie.name() == "dopbase_session"
                && cookie
                    .domain()
                    .unwrap_or_default()
                    .trim_start_matches('.')
                    .eq_ignore_ascii_case(host)
        })
        .map(|cookie| cookie.value().to_owned());
    let csrf_token = cookies
        .iter()
        .find(|cookie| {
            cookie.name() == "dopbase_csrf"
                && cookie
                    .domain()
                    .unwrap_or_default()
                    .trim_start_matches('.')
                    .eq_ignore_ascii_case(host)
        })
        .map(|cookie| cookie.value().to_owned());
    Ok(token
        .zip(csrf_token)
        .map(|(token, csrf_token)| SessionResponse { token, csrf_token }))
}

fn socket_path() -> PathBuf {
    app::config::dopbase_home().join(SOCKET_NAME)
}

fn remove_stale_socket(path: &std::path::Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "refusing to replace a non-socket desktop session path",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

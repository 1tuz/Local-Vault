use std::sync::{Arc, Mutex};

use app::{
    config::{ServerConfig, ServerOverrides, dopbase_home},
    server,
};
use tauri::{WebviewUrl, WebviewWindowBuilder};
use tokio::sync::oneshot;

#[cfg(unix)]
mod desktop_session;

type ShutdownSender = Arc<Mutex<Option<oneshot::Sender<()>>>>;

fn main() {
    let shutdown: ShutdownSender = Arc::new(Mutex::new(None));
    let shutdown_setup = Arc::clone(&shutdown);

    let application = tauri::Builder::default()
        .setup(move |app| {
            let config = ServerConfig::load(&ServerOverrides {
                data_dir: Some(dopbase_home()),
                host: Some("127.0.0.1".to_string()),
                // Keep the upstream default/configured port so its CLI and MCP
                // commands attach to the same desktop-owned server.
                port: None,
                docs: Some(false),
                web_ui: Some(true),
                ..ServerOverrides::default()
            })?;
            let broker_port = config.bind_address.parse::<std::net::SocketAddr>()?.port();

            let (ready_tx, ready_rx) = oneshot::channel();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            *shutdown_setup.lock().expect("shutdown lock poisoned") = Some(shutdown_tx);

            tauri::async_runtime::spawn(async move {
                if let Err(error) = server::serve_desktop(config, ready_tx, shutdown_rx).await {
                    eprintln!("Dopbase desktop server stopped: {error:#}");
                }
            });

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                match ready_rx.await {
                    Ok(ready) => {
                        let mut url = match url::Url::parse(&ready.url) {
                            Ok(url) => url,
                            Err(error) => {
                                eprintln!(
                                    "Dopbase desktop received an invalid server URL: {error}"
                                );
                                handle.exit(1);
                                return;
                            }
                        };
                        if ready.setup_token.is_some() {
                            url.set_path("/setup");
                            let mut fragment = url::form_urlencoded::Serializer::new(String::new());
                            fragment.append_pair(
                                "token",
                                ready.setup_token.as_deref().unwrap_or_default(),
                            );
                            url.set_fragment(Some(&fragment.finish()));
                        }
                        if let Err(error) =
                            WebviewWindowBuilder::new(&handle, "main", WebviewUrl::External(url))
                                .title("Dopbase")
                                .inner_size(1180.0, 780.0)
                                .min_inner_size(900.0, 620.0)
                                .build()
                        {
                            eprintln!("Dopbase desktop window failed to open: {error}");
                            handle.exit(1);
                            return;
                        }
                        #[cfg(unix)]
                        if let Err(error) = desktop_session::start(handle, broker_port) {
                            eprintln!("Dopbase desktop session broker failed to start: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("Dopbase desktop server failed before becoming ready: {error}");
                        handle.exit(1);
                    }
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Dopbase desktop failed to initialize");

    application.run(move |_handle, event| {
        if matches!(event, tauri::RunEvent::Exit)
            && let Some(shutdown) = shutdown.lock().expect("shutdown lock poisoned").take()
        {
            let _ = shutdown.send(());
        }
    });
}

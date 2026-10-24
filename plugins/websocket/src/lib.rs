// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Open a WebSocket connection using a Rust client in JS.
//!
//! The plugin opens each connection's TCP stream itself, so the host can configure its socket
//! ([`Builder::socket_configurer`]) and close open connections ([`close_all`], [`close_bound_to`]).
//!
//! ## Cargo features
//!
//! - **rustls-tls** *(enabled by default)*: Enables TLS functionality provided by `rustls` with WebPKI roots.
//! - **rustls-tls-native-roots**: Enables TLS functionality provided by `rustls` with the platform's native certificate roots.
//! - **native-tls**: Enables TLS functionality provided by `native-tls`.
//! - **native-tls-vendored**: Enables the `vendored` feature of `native-tls`.
//!
//! At least one TLS feature is required for `wss://`; plain `ws://` works without one.

#![doc(
    html_logo_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png",
    html_favicon_url = "https://github.com/tauri-apps/tauri/raw/dev/app-icon.png"
)]

use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use http::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize, ser::Serializer};
use socket2::SockRef;
use tauri::{
    AppHandle, Manager, Runtime, State, Window,
    async_runtime::JoinHandle,
    ipc::Channel,
    plugin::{Builder as PluginBuilder, TauriPlugin},
};
use tokio::{net::TcpStream, sync::Mutex, task::AbortHandle};
#[cfg(any(
    feature = "rustls-tls",
    feature = "rustls-tls-native-roots",
    feature = "native-tls"
))]
use tokio_tungstenite::client_async_tls_with_config;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{
        Error as TungsteniteError, Message,
        client::IntoClientRequest,
        error::UrlError,
        protocol::{CloseFrame as ProtocolCloseFrame, WebSocketConfig},
    },
};
#[cfg(not(any(
    feature = "rustls-tls",
    feature = "rustls-tls-native-roots",
    feature = "native-tls"
)))]
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{client::uri_mode, stream::Mode},
};

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, PoisonError};

/// Re-exported for [`Builder::socket_configurer`], whose function receives a [`socket2::SockRef`].
pub use socket2;

type Id = u32;
type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WebSocketWriter = SplitSink<WebSocket, Message>;
type Result<T> = std::result::Result<T, Error>;
type ConfigureSocket = dyn Fn(&SockRef<'_>) -> io::Result<()> + Send + Sync;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Websocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("connection not found for the given id: {0}")]
    ConnectionNotFound(Id),
    #[error(transparent)]
    InvalidHeaderValue(#[from] tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue),
    #[error(transparent)]
    InvalidHeaderName(#[from] tokio_tungstenite::tungstenite::http::header::InvalidHeaderName),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

/// A connection the `connect` command opened, kept until its reader receives a `Close` frame or
/// the host closes it with [`close_all`] or [`close_bound_to`].
struct Connection {
    /// Shared with each `send` in flight, so a send waiting on the network holds no lock that
    /// closing a connection needs.
    writer: Arc<Mutex<WebSocketWriter>>,
    local_addr: SocketAddr,
    on_message: Channel<serde_json::Value>,
    reader: AbortHandle,
}

impl Connection {
    /// Ends the connection from the host: sends its frontend a `Close` message, aborts its reader
    /// task and drops its writer. The socket closes once the aborted reader and any `send` still
    /// in flight have released their halves of the stream.
    fn close(self) {
        // Dropping the last clone of a channel the frontend created sends the frontend only an
        // end marker, which `@tauri-apps/api`'s `Channel` consumes without calling `onmessage`,
        // so its listeners would never see the connection close. This connection holds a clone
        // until it is dropped below, so the `Close` sent here reaches the frontend ahead of that
        // marker.
        match serde_json::to_value(WebSocketMessage::Close(None)) {
            Ok(close) => {
                let _ = self.on_message.send(close);
            }
            Err(e) => unreachable!("a Close without a close frame always serializes: {e}"),
        }
        self.reader.abort();
    }
}

#[derive(Default)]
struct ConnectionManager(std::sync::Mutex<HashMap<Id, Connection>>);

impl ConnectionManager {
    fn connections(&self) -> std::sync::MutexGuard<'_, HashMap<Id, Connection>> {
        // A panic while the lock was held leaves a valid map, so keep serving it.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn writer(&self, id: Id) -> Option<Arc<Mutex<WebSocketWriter>>> {
        self.connections()
            .get(&id)
            .map(|connection| Arc::clone(&connection.writer))
    }
}

/// The function set by [`Builder::socket_configurer`], if any.
struct SocketConfigurer(Option<Box<ConfigureSocket>>);

#[cfg(any(
    feature = "rustls-tls",
    feature = "rustls-tls-native-roots",
    feature = "native-tls"
))]
struct TlsConnector(Mutex<Option<Connector>>);

#[derive(Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
enum Max {
    None,
    Number(usize),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionConfig {
    pub read_buffer_size: Option<usize>,
    pub write_buffer_size: Option<usize>,
    pub max_write_buffer_size: Option<usize>,
    pub max_message_size: Option<Max>,
    pub max_frame_size: Option<Max>,
    #[serde(default)]
    pub accept_unmasked_frames: bool,
    pub headers: Option<Vec<(String, String)>>,
}

impl From<ConnectionConfig> for WebSocketConfig {
    fn from(config: ConnectionConfig) -> Self {
        let mut builder =
            WebSocketConfig::default().accept_unmasked_frames(config.accept_unmasked_frames);

        if let Some(read_buffer_size) = config.read_buffer_size {
            builder = builder.read_buffer_size(read_buffer_size)
        }

        if let Some(write_buffer_size) = config.write_buffer_size {
            builder = builder.write_buffer_size(write_buffer_size)
        }

        if let Some(max_write_buffer_size) = config.max_write_buffer_size {
            builder = builder.max_write_buffer_size(max_write_buffer_size)
        }

        if let Some(max_message_size) = config.max_message_size {
            let max_size = match max_message_size {
                Max::None => Option::None,
                Max::Number(n) => Some(n),
            };
            builder = builder.max_message_size(max_size);
        }

        if let Some(max_frame_size) = config.max_frame_size {
            let max_size = match max_frame_size {
                Max::None => Option::None,
                Max::Number(n) => Some(n),
            };
            builder = builder.max_frame_size(max_size);
        }

        builder
    }
}

#[derive(Deserialize, Serialize)]
struct CloseFrame {
    pub code: u16,
    pub reason: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", content = "data")]
enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<CloseFrame>),
}

#[tauri::command]
async fn connect<R: Runtime>(
    window: Window<R>,
    url: String,
    on_message: Channel<serde_json::Value>,
    config: Option<ConnectionConfig>,
) -> Result<Id> {
    let id = rand::random();
    // The reader runs detached; `close_all` and `close_bound_to` abort it.
    let _reader = open_connection(window.app_handle(), id, url, on_message, config).await?;
    Ok(id)
}

/// Opens the connection `connect` reports as `id`: its TCP stream, its socket configured by the
/// [`Builder::socket_configurer`] function, the WebSocket handshake over that stream, and the
/// reader task forwarding what it receives to `on_message`, whose handle it returns.
async fn open_connection<R: Runtime>(
    app: &AppHandle<R>,
    id: Id,
    url: String,
    on_message: Channel<serde_json::Value>,
    config: Option<ConnectionConfig>,
) -> Result<JoinHandle<()>> {
    let mut request = url.into_client_request()?;

    if let Some(headers) = config.as_ref().and_then(|c| c.headers.as_ref()) {
        for (k, v) in headers {
            let header_name = HeaderName::from_str(k.as_str())?;
            let header_value = HeaderValue::from_str(v.as_str())?;
            request.headers_mut().insert(header_name, header_value);
        }
    }

    #[cfg(any(
        feature = "rustls-tls",
        feature = "rustls-tls-native-roots",
        feature = "native-tls"
    ))]
    let tls_connector = match app.try_state::<TlsConnector>() {
        Some(tls_connector) => tls_connector.0.lock().await.clone(),
        None => None,
    };

    let uri = request.uri();
    let host = uri
        .host()
        .ok_or(TungsteniteError::Url(UrlError::NoHostName))?;
    // The URI keeps the brackets around an IPv6 host.
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let port = uri
        .port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or(TungsteniteError::Url(UrlError::UnsupportedUrlScheme))?;
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(TungsteniteError::Io)?;
    let local_addr = stream.local_addr().map_err(TungsteniteError::Io)?;
    if let Some(configure) = app
        .try_state::<SocketConfigurer>()
        .and_then(|configurer| configurer.inner().0.as_deref())
    {
        configure(&SockRef::from(&stream)).map_err(TungsteniteError::Io)?;
    }

    #[cfg(any(
        feature = "rustls-tls",
        feature = "rustls-tls-native-roots",
        feature = "native-tls"
    ))]
    let (ws_stream, _) =
        client_async_tls_with_config(request, stream, config.map(Into::into), tls_connector)
            .await?;
    #[cfg(not(any(
        feature = "rustls-tls",
        feature = "rustls-tls-native-roots",
        feature = "native-tls"
    )))]
    let (ws_stream, _) = match uri_mode(request.uri())? {
        Mode::Plain => {
            client_async_with_config(
                request,
                MaybeTlsStream::Plain(stream),
                config.map(Into::into),
            )
            .await?
        }
        Mode::Tls => return Err(TungsteniteError::Url(UrlError::TlsFeatureNotEnabled).into()),
    };

    let (write, read) = ws_stream.split();
    let manager = app.state::<ConnectionManager>();
    // The reader takes this lock to remove the connection on a `Close` frame, so holding it until
    // the insert below keeps that removal after the insert.
    let mut connections = manager.connections();
    let reader = tauri::async_runtime::spawn({
        let app = app.clone();
        let on_message = on_message.clone();
        read.for_each(move |message| {
            let app_ = app.clone();
            let on_message_ = on_message.clone();
            async move {
                if let Ok(Message::Close(_)) = message {
                    app_.state::<ConnectionManager>().connections().remove(&id);
                }

                let response = match message {
                    Ok(Message::Text(t)) => {
                        serde_json::to_value(WebSocketMessage::Text(t.to_string())).unwrap()
                    }
                    Ok(Message::Binary(t)) => {
                        serde_json::to_value(WebSocketMessage::Binary(t.to_vec())).unwrap()
                    }
                    Ok(Message::Ping(t)) => {
                        serde_json::to_value(WebSocketMessage::Ping(t.to_vec())).unwrap()
                    }
                    Ok(Message::Pong(t)) => {
                        serde_json::to_value(WebSocketMessage::Pong(t.to_vec())).unwrap()
                    }
                    Ok(Message::Close(t)) => {
                        serde_json::to_value(WebSocketMessage::Close(t.map(|v| CloseFrame {
                            code: v.code.into(),
                            reason: v.reason.to_string(),
                        })))
                        .unwrap()
                    }
                    Ok(Message::Frame(_)) => serde_json::Value::Null, // This value can't be recieved.
                    Err(e) => serde_json::to_value(Error::from(e)).unwrap(),
                };

                let _ = on_message_.send(response);
            }
        })
    });
    connections.insert(
        id,
        Connection {
            writer: Arc::new(Mutex::new(write)),
            local_addr,
            on_message,
            reader: reader.inner().abort_handle(),
        },
    );

    Ok(reader)
}

#[tauri::command]
async fn send(
    manager: State<'_, ConnectionManager>,
    id: Id,
    message: WebSocketMessage,
) -> Result<()> {
    if let Some(write) = manager.writer(id) {
        write
            .lock()
            .await
            .send(match message {
                WebSocketMessage::Text(t) => Message::Text(t.into()),
                WebSocketMessage::Binary(t) => Message::Binary(t.into()),
                WebSocketMessage::Ping(t) => Message::Ping(t.into()),
                WebSocketMessage::Pong(t) => Message::Pong(t.into()),
                WebSocketMessage::Close(t) => Message::Close(t.map(|v| ProtocolCloseFrame {
                    code: v.code.into(),
                    reason: v.reason.into(),
                })),
            })
            .await?;
        Ok(())
    } else {
        Err(Error::ConnectionNotFound(id))
    }
}

/// Closes every open connection: each frontend is sent a `Close` message without a close frame,
/// and the connection is dropped without a closing handshake. A connection is open from its
/// `connect` until it receives a `Close` frame or the host closes it.
pub fn close_all<R: Runtime>(app: &AppHandle<R>) {
    close_where(app, |_| true);
}

/// Closes, as [`close_all`] does, each open connection whose socket's local IP address is one of
/// `addresses`, such as the addresses of a network interface that went down.
pub fn close_bound_to<R: Runtime>(app: &AppHandle<R>, addresses: &[IpAddr]) {
    close_where(app, |connection| {
        addresses.contains(&connection.local_addr.ip())
    });
}

fn close_where<R: Runtime>(app: &AppHandle<R>, closes: impl Fn(&Connection) -> bool) {
    let Some(manager) = app.try_state::<ConnectionManager>() else {
        return;
    };
    let closed: Vec<Connection> = manager
        .connections()
        .extract_if(|_, connection| closes(connection))
        .map(|(_, connection)| connection)
        .collect();
    for connection in closed {
        connection.close();
    }
}

/// Initializes the plugin with the default [`Builder`], i.e. without a custom TLS [`Connector`]
/// or a socket configurer.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::default().build()
}

/// Builder for the WebSocket plugin, used to configure a custom TLS [`Connector`] or a socket
/// configurer before calling [`Builder::build`].
#[derive(Default)]
pub struct Builder {
    tls_connector: Option<Connector>,
    socket_configurer: Option<Box<ConfigureSocket>>,
}

impl Builder {
    /// Creates a new [`Builder`] with no custom TLS [`Connector`] and no socket configurer.
    pub fn new() -> Self {
        Self {
            tls_connector: None,
            socket_configurer: None,
        }
    }

    /// Sets the TLS [`Connector`] used to establish `wss://` connections.
    ///
    /// When this is not called (or is called with [`Connector::Plain`]) and a `rustls-tls` or
    /// `rustls-tls-native-roots` feature is enabled, [`Builder::build`] installs `rustls`'s `ring`
    /// crypto provider as the process default if none is installed yet.
    pub fn tls_connector(mut self, connector: Connector) -> Self {
        self.tls_connector.replace(connector);
        self
    }

    /// Sets a function that configures the socket of each connection, such as its TCP keepalive.
    ///
    /// It is called once per connection, after the TCP stream connects and before the TLS and
    /// WebSocket handshakes. An error it returns fails the connection with that error.
    pub fn socket_configurer<F>(mut self, configurer: F) -> Self
    where
        F: Fn(&SockRef<'_>) -> io::Result<()> + Send + Sync + 'static,
    {
        self.socket_configurer.replace(Box::new(configurer));
        self
    }

    /// Builds the plugin, registering the `connect` and `send` commands and the shared connection state.
    pub fn build<R: Runtime>(self) -> TauriPlugin<R> {
        PluginBuilder::new("websocket")
            .invoke_handler(tauri::generate_handler![connect, send])
            .setup(|app, _api| {
                #[cfg(any(feature = "rustls-tls", feature = "rustls-tls-native-roots"))]
                if (self.tls_connector.is_none()
                    || matches!(self.tls_connector, Some(Connector::Plain)))
                    && rustls::crypto::CryptoProvider::get_default().is_none()
                {
                    // This can only fail if there is already a default provider which we checked for already.
                    let _ = rustls::crypto::ring::default_provider().install_default();
                }

                app.manage(ConnectionManager::default());
                app.manage(SocketConfigurer(self.socket_configurer));
                #[cfg(any(
                    feature = "rustls-tls",
                    feature = "rustls-tls-native-roots",
                    feature = "native-tls"
                ))]
                app.manage(TlsConnector(Mutex::new(self.tls_connector)));
                Ok(())
            })
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Builder, Channel, ConnectionManager, IpAddr, Manager, StreamExt, WebSocketMessage,
        close_all, close_bound_to, open_connection, send,
    };
    use serde_json::{Value, json};
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tauri::{
        App,
        ipc::InvokeResponseBody,
        test::{MockRuntime, mock_builder, mock_context, noop_assets},
    };
    use tokio::{net::TcpListener, sync::mpsc, time::timeout};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    const WITHIN: Duration = Duration::from_secs(1);

    fn app(builder: Builder) -> tauri::Result<App<MockRuntime>> {
        mock_builder()
            .plugin(builder.build())
            .build(mock_context(noop_assets()))
    }

    /// Serves WebSocket connections on a local port, echoing back what each one receives.
    async fn echo_listener() -> io::Result<String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("ws://{}", listener.local_addr()?);
        tauri::async_runtime::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tauri::async_runtime::spawn(async move {
                    if let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await {
                        let (write, read) = ws_stream.split();
                        let _ = read.forward(write).await;
                    }
                });
            }
        });
        Ok(url)
    }

    /// A channel like the one a frontend passes to `connect`, whose messages arrive on the
    /// returned receiver.
    fn recording_channel() -> (Channel<Value>, mpsc::UnboundedReceiver<Value>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let channel = Channel::new(move |body| {
            let message = match body {
                InvokeResponseBody::Json(json) => serde_json::from_str(&json)?,
                InvokeResponseBody::Raw(_) => Value::Null,
            };
            let _ = sender.send(message);
            Ok(())
        });
        (channel, receiver)
    }

    fn ignoring_channel() -> Channel<Value> {
        Channel::new(|_| Ok(()))
    }

    #[test]
    fn the_socket_configurer_runs_once_per_connect_on_the_connected_socket() -> TestResult {
        tauri::async_runtime::block_on(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            let app = app(Builder::new().socket_configurer(move |socket| {
                counted.fetch_add(1, Ordering::SeqCst);
                socket.peer_addr().map(drop)
            }))?;
            let url = echo_listener().await?;

            open_connection(app.handle(), 1, url.clone(), ignoring_channel(), None).await?;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            open_connection(app.handle(), 2, url, ignoring_channel(), None).await?;
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            Ok(())
        })
    }

    #[test]
    fn a_socket_configurer_error_fails_the_connect() -> TestResult {
        tauri::async_runtime::block_on(async {
            let app =
                app(Builder::new()
                    .socket_configurer(|_| Err(io::Error::other("refused by the host"))))?;
            let url = echo_listener().await?;

            let opened = open_connection(app.handle(), 1, url, ignoring_channel(), None).await;
            assert!(opened.is_err());
            assert!(app.state::<ConnectionManager>().connections().is_empty());
            Ok(())
        })
    }

    #[test]
    fn close_all_sends_one_close_and_ends_the_reader() -> TestResult {
        tauri::async_runtime::block_on(async {
            let app = app(Builder::new())?;
            let url = echo_listener().await?;
            let (channel, mut messages) = recording_channel();
            let reader = open_connection(app.handle(), 1, url, channel, None).await?;

            send(app.state(), 1, WebSocketMessage::Text("live".into())).await?;
            let echo = timeout(WITHIN, messages.recv()).await?;
            assert_eq!(echo, Some(json!({"type": "Text", "data": "live"})));

            close_all(app.handle());
            let ended = timeout(WITHIN, reader).await?;
            assert!(ended.is_err(), "the reader was aborted");
            let mut after_close = Vec::new();
            while let Some(message) = timeout(WITHIN, messages.recv()).await? {
                after_close.push(message);
            }
            assert_eq!(after_close, [json!({"type": "Close", "data": null})]);
            assert!(app.state::<ConnectionManager>().connections().is_empty());
            Ok(())
        })
    }

    #[test]
    fn close_bound_to_closes_only_connections_from_the_given_addresses() -> TestResult {
        tauri::async_runtime::block_on(async {
            let app = app(Builder::new())?;
            let url = echo_listener().await?;
            let reader = open_connection(app.handle(), 1, url, ignoring_channel(), None).await?;

            close_bound_to(app.handle(), &[IpAddr::V6(Ipv6Addr::LOCALHOST)]);
            assert!(
                app.state::<ConnectionManager>()
                    .connections()
                    .contains_key(&1)
            );

            close_bound_to(app.handle(), &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
            assert!(app.state::<ConnectionManager>().connections().is_empty());
            let ended = timeout(WITHIN, reader).await?;
            assert!(ended.is_err(), "the reader was aborted");
            Ok(())
        })
    }
}

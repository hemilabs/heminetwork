use crate::trust_rpc::protocol::{JobStatus, Payload};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::sync::{Arc, RwLock, atomic::AtomicUsize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::{
    runtime::Runtime,
    sync::{Mutex, mpsc},
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tokio_util::sync::CancellationToken;
use tungstenite::client::IntoClientRequest;

pub mod protocol;

#[cfg(test)]
mod trust_rpc_test;

#[cfg(test)]
mod protocol_test;

#[derive(Error, Debug)]
pub enum TrustRPCError {
    #[error("Tungstenite error: {0}")]
    Tungstenite(#[from] tungstenite::Error),
    #[error("Tokio IO error: {0}")]
    TokioIO(#[from] tokio::io::Error),
    #[error("JSON error: {0}")]
    JSON(#[from] serde_json::Error),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    #[error("cancelled")]
    Cancelled,
    #[error("protocol error {0}")]
    Protocol(#[from] protocol::ProtocolError),
    #[error("Connection lost")]
    ConnectionLost,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TrustRPCError>;

type WsSink = futures_util::stream::SplitSink<
    WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    tungstenite::Message,
>;
type WsStream =
    futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;

enum ChannelEvent {
    Message(protocol::Message),
    Disconnected,
    Connected,
}

/// TrustRPC starts a websocket connection to a TBC node, creating an
/// asynchronous reader, paired with synchronous / sequential writers.
///
/// Calls that send a request to TBC all require borrowing a mutable
/// version of TrustRPC, preventing them from being executing in parallel.
///
/// When TrustRPC receives a Message from TBC, it's discarded if there
/// is no associated caller (unprompted message), or redirected to a
/// channel to the caller.
///
/// Long running tasks (jobs) that require longer execution periods can
/// survive even after the connection is dropped, so one can attempt to
/// resubscribe to its notfications upon restarting.
pub struct TrustRPC {
    config: Config,
    rt: Runtime,
    cancel: CancellationToken,
    write: Arc<Mutex<WsSink>>,
    msg_chan: Arc<RwLock<Option<mpsc::Sender<ChannelEvent>>>>,
    msg_counter: AtomicUsize,
}

impl Drop for TrustRPC {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// RAII guard that clears `msg_chan` back to `None` when dropped.
/// Callers MUST bind it with `let _guard = ...` to ensure cleanup.
struct ChanGuard(Arc<RwLock<Option<mpsc::Sender<ChannelEvent>>>>);

impl Drop for ChanGuard {
    fn drop(&mut self) {
        *self.0.write().unwrap() = None;
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub jwt_secret: [u8; 32],
    pub cmd_timeout: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "localhost:8082".into(),
            jwt_secret: [0u8; 32],
            cmd_timeout: Duration::from_secs(10),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
        }
    }
}

#[derive(Serialize)]
struct JwtClaims {
    iat: u64,
    exp: u64,
    nbf: u64,
}

fn mint_jwt(secret: &[u8; 32]) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = JwtClaims {
        iat: now,
        exp: now + 60,
        nbf: now,
    };

    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = enc.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let claims_b64 = enc.encode(serde_json::to_string(&claims)?);
    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(signing_input.as_bytes());
    let sig_b64 = enc.encode(mac.finalize().into_bytes());

    Ok(format!("{}.{}", signing_input, sig_b64))
}

fn make_request(
    tbc_url: &str,
    jwt_secret: &[u8; 32],
) -> Result<tungstenite::handshake::client::Request> {
    let mut request = tbc_url.into_client_request()?;
    let token = mint_jwt(jwt_secret)?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    Ok(request)
}

async fn connect_and_split(tbc_url: &str, jwt_secret: &[u8; 32]) -> Result<(WsSink, WsStream)> {
    let request = make_request(tbc_url, jwt_secret)?;
    let (ws_stream, _) = connect_async(request).await?;
    Ok(ws_stream.split())
}

impl TrustRPC {
    pub fn new(config: Config) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let (write, read_stream) =
            rt.block_on(connect_and_split(&config.url, &config.jwt_secret))?;

        let trpc = Self {
            write: Arc::new(Mutex::new(write)),
            rt,
            msg_counter: AtomicUsize::new(0),
            msg_chan: Arc::new(RwLock::new(None)),
            cancel: CancellationToken::new(),
            config: config.clone(),
        };

        trpc.spawn_reader(read_stream, config, trpc.cancel.clone());

        Ok(trpc)
    }

    /// Spawns the background reader/reconnect task.
    ///
    /// When a message is received, it's forwarded to any existing callers.
    /// When disconnected from the server, it attempts to reconnect using an
    /// exponential backoff strategy, and informs the in-flight caller.
    ///
    /// For long running tasks, the caller may choose to attempt to resubscribe to
    /// the event rather than fail the call.
    fn spawn_reader(&self, initial_stream: WsStream, config: Config, cancel: CancellationToken) {
        let chan_clone = Arc::clone(&self.msg_chan);
        let write_clone = Arc::clone(&self.write);

        self.rt.spawn(async move {
            let mut read_stream = initial_stream;

            loop {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        msg_result = read_stream.next() => match msg_result {
                            Some(Ok(msg)) => {
                                if !msg.is_text() {
                                    continue;
                                }
                                let t = msg.into_text().unwrap();
                                let pmsg = match protocol::unmarshal(t.as_str()) {
                                    Ok(m) => m,
                                    Err(_) => continue, // XXX log
                                };

                                // Clone the sender chan before dropping the lock
                                // so we never hold a RwLock guard across await.
                                let sender = {
                                    let g = chan_clone.read().unwrap();
                                    g.clone()
                                };

                                if let Some(s) = sender {
                                    tokio::select! {
                                        _ = cancel.cancelled() => return,
                                        _ = s.send(ChannelEvent::Message(pmsg)) => {} // XXX log
                                    }
                                }
                            }
                            Some(Err(_)) => continue, // XXX log
                            None => break, // stream ended, fall through to reconnect
                        }
                    }
                }

                // Connection lost
                // println!("Connection to {} lost, reconnecting...", config.url);

                let sender = {
                    let g = chan_clone.read().unwrap();
                    g.clone()
                };
                if let Some(s) = sender {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = s.send(ChannelEvent::Disconnected) => {} // XXX log
                    }
                }

                // Attempt to reconnect
                let mut backoff = config.backoff_initial;
                let (new_write, new_read) = loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    let conn = connect_and_split(&config.url, &config.jwt_secret).await;
                    if let Ok(halves) = conn {
                        // reconnection successful, break out of loop
                        // and assing new halves
                        break halves;
                    }
                    // println!("Reconnect failed: {}, retrying in {:?}...", e, backoff);
                    backoff = (backoff * 2).min(config.backoff_max);
                };
                *write_clone.lock().await = new_write;

                // Notify in-flight caller that the connection
                // was lost and is now restored.
                let sender = {
                    let g = chan_clone.read().unwrap();
                    g.clone()
                };
                if let Some(s) = sender {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = s.send(ChannelEvent::Connected) => {} // XXX log
                    }
                }
                read_stream = new_read;
            }
        });
    }

    pub fn ping(&mut self) -> Result<()> {
        let (id, mut rcv, _guard) = self.add_chan()?;
        let req = protocol::PingRequest { timestamp: 10 };
        let msg = protocol::encode(&id, &Payload::PingRequest(req))?;

        self.rt.block_on(async {
            tokio::time::timeout(self.config.cmd_timeout, async {
                let mut write = self.write.lock().await;

                // Send ping request
                tokio::select! {
                    _ = self.cancel.cancelled() => return Err(TrustRPCError::Cancelled),
                    res = write.send(tungstenite::Message::text(protocol::marshal(&msg)?)) => res,
                }?;

                // Wait for reply
                tokio::select! {
                    _ = self.cancel.cancelled() => Err(TrustRPCError::Cancelled),
                    event = rcv.recv() => match event {
                        Some(ChannelEvent::Message(resp)) => {
                            match resp.decode() {
                                Ok(Payload::PingResponse(_)) => {},
                                Ok(p) => {
                                    let err = format!("unexpected response type: {}", p.command());
                                    return Err(TrustRPCError::Other(err))
                                }
                                Err(e) => return Err(e),
                            };
                            Ok(())
                        }
                        _ => Err(TrustRPCError::ConnectionLost)
                    },
                }
            })
            .await
            .unwrap_or(Err(TrustRPCError::Timeout("ping response".into())))
        })
    }

    pub fn sync_indexers_to_hash(&mut self, hash: bitcoin::BlockHash) -> Result<()> {
        let (id, rcv, _guard) = self.add_chan()?;
        let req = protocol::SyncIndexersToHashRequest {
            hash: hash.to_string(),
        };
        let msg = protocol::encode(&id, &Payload::SyncIndexersToHashRequest(req))?;
        let cancel = self.cancel.clone();
        self.rt.block_on(async {
            tokio::time::timeout(self.config.cmd_timeout, async {
                {
                    // Send request; limit scope of guard since it's needed when
                    // waiting for job notifications.
                    let mut guard = self.write.lock().await;
                    tokio::select! {
                        _ = cancel.cancelled() => return Err(TrustRPCError::Cancelled),
                        res = guard.send(tungstenite::Message::text(protocol::marshal(&msg)?)) => res?,
                    }
                }
                self.wait_for_job(&id, rcv, &self.write).await
            })
            .await
            .unwrap_or(Err(TrustRPCError::Timeout("sync indexers to hash".into())))
        })
    }

    async fn wait_for_job(
        &self,
        id: &str,
        mut rcv: mpsc::Receiver<ChannelEvent>,
        write: &Mutex<WsSink>,
    ) -> Result<()> {
        let mut active_job: Option<String> = None;
        loop {
            let event = tokio::select! {
                _ = self.cancel.cancelled() => return Err(TrustRPCError::Cancelled),
                e = rcv.recv() => e,
            };
            match event {
                // Received message
                Some(ChannelEvent::Message(resp)) => {
                    let notif = match resp.decode() {
                        Ok(Payload::JobUpdateNotification(j)) => j,
                        Ok(_) => continue, // unexpected message type; ignore
                        Err(e) => return Err(e),
                    };
                    if active_job.is_none() {
                        active_job = Some(notif.job.job_id.clone());
                    }
                    if let Some(e) = notif.error {
                        return Err(TrustRPCError::Protocol(e));
                    }
                    match notif.job.status {
                        JobStatus::Completed => return Ok(()),
                        JobStatus::Failed => {
                            let err = format!("job {} failed", notif.job.job_id);
                            return Err(TrustRPCError::Other(err));
                        }
                        _ => continue,
                    }
                }

                // On disconnect do nothing and wait for reconnect or timeout.
                Some(ChannelEvent::Disconnected) => {
                    match active_job {
                        Some(_) => continue,
                        None => return Err(TrustRPCError::ConnectionLost),
                    };
                }

                // On reconnect try and resubscribe to this job.
                Some(ChannelEvent::Connected) => {
                    let jid = match active_job {
                        Some(ref j) => j.clone(),
                        None => return Err(TrustRPCError::ConnectionLost),
                    };
                    let sub = protocol::encode(
                        id,
                        &Payload::JobSubscribeRequest(protocol::JobSubscribeRequest {
                            job_id: jid.clone(),
                        }),
                    )?;
                    {
                        let mut guard = write.lock().await;
                        tokio::select! {
                            _ = self.cancel.cancelled() => return Err(TrustRPCError::Cancelled),
                            res = guard.send(tungstenite::Message::text(protocol::marshal(&sub)?)) => {
                                res.map_err(|e| TrustRPCError::Other(
                                    format!("resubscribe to job {} failed: {}", jid, e)
                                ))?;
                            }
                        }
                    }
                }

                None => {
                    let err = "channel closed unexpectedly while waiting for job";
                    return Err(TrustRPCError::Other(err.into()));
                }
            }
        }
    }

    fn add_chan(&self) -> Result<(String, mpsc::Receiver<ChannelEvent>, ChanGuard)> {
        let id = self
            .msg_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let mut guard = self.msg_chan.write().unwrap();
        let (sender, rcv) = mpsc::channel::<ChannelEvent>(10);
        *guard = Some(sender);

        Ok((id.to_string(), rcv, ChanGuard(Arc::clone(&self.msg_chan))))
    }

    #[allow(unused)] // XXX currently not needed
    async fn close(&mut self) -> Result<()> {
        self.write.lock().await.close().await?;
        Ok(())
    }
}

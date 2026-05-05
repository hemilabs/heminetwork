use super::*;
use bitcoin::hashes::Hash;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::TcpListener;
use std::time::Duration;
use tokio_tungstenite::accept_async;

fn test_config(url: &str) -> Config {
    Config {
        url: url.to_string(),
        jwt_secret: [0u8; 32],
        cmd_timeout: Duration::from_secs(5),
        backoff_initial: Duration::from_millis(20),
        backoff_max: Duration::from_millis(100),
    }
}

#[test]
fn test_mint_jwt() {
    let secret = [5u8; 32];

    // Check time before minting
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token = mint_jwt(&secret).unwrap();

    // Check time after minting
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // JWT is built with xxx.yyy.zzz
    let split: Vec<&str> = token.split('.').collect();
    assert_eq!(split.len(), 3);

    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header_json = enc.decode(split[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
    assert_eq!(header["alg"], "HS256");
    assert_eq!(header["typ"], "JWT");

    let claims_json = enc.decode(split[1]).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
    let iat = claims["iat"].as_u64().unwrap();
    let exp = claims["exp"].as_u64().unwrap();
    let nbf = claims["nbf"].as_u64().unwrap();
    assert!(iat >= before && iat <= after);
    assert_eq!(nbf, iat);
    assert_eq!(exp, iat + 60);

    let signing_input = format!("{}.{}", split[0], split[1]);
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
    mac.update(signing_input.as_bytes());
    let expected_sig = enc.encode(mac.finalize().into_bytes());
    assert_eq!(split[2], expected_sig);
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    tungstenite::Message,
>;
type WsStream =
    futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>>;

// mock_connect simulates a tbc connection. The caller passes in
// a future containing the expected behavior of the mock server,
// as well as a TCP Listener on which to accept connections.
fn mock_connect<F, Fut, T>(
    listener: &TcpListener,
    handler: F,
) -> impl std::future::Future<Output = T>
where
    F: FnOnce(WsSink, WsStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T> + Send,
    T: Send + 'static,
{
    let std_listener = listener.try_clone().unwrap();
    async move {
        std_listener.set_nonblocking(true).unwrap();
        let tokio_listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
        let (stream, _) = tokio_listener.accept().await.unwrap();
        let ws_stream = accept_async(stream).await.unwrap();
        let (write, read) = ws_stream.split();
        handler(write, read).await
    }
}

const TEST_JOB_ID: &str = "test_job_id";
const TEST_JOB_TYPE: &str = "test_job_type";

async fn send_job_update(write: &mut WsSink, id: &str, status: protocol::JobStatus) {
    let notif = protocol::encode(
        id,
        &protocol::Payload::JobUpdateNotification(protocol::JobUpdateNotification {
            job: protocol::JobInfo {
                job_id: TEST_JOB_ID.into(),
                job_type: TEST_JOB_TYPE.into(),
                status,
            },
            error: None,
        }),
    )
    .unwrap();
    write
        .send(tungstenite::Message::text(
            protocol::marshal(&notif).unwrap(),
        ))
        .await
        .unwrap();
}

#[test]
fn test_rpc_call_idempotence() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    // Server handles two sequential ping calls
    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |mut write, mut read| async move {
                for _ in 0..2 {
                    let msg = read.next().await.unwrap().unwrap();
                    let text = msg.into_text().unwrap();
                    let received: protocol::Message = serde_json::from_str(&text).unwrap();
                    let response = protocol::encode(
                        &received.header.id,
                        &protocol::Payload::PingResponse(protocol::PingResponse {
                            origin_timestamp: 10,
                            timestamp: 20,
                        }),
                    )
                    .unwrap();
                    write
                        .send(tungstenite::Message::text(
                            protocol::marshal(&response).unwrap(),
                        ))
                        .await
                        .unwrap();
                }
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    // Second call should hang if the message routing
    // channel is not reset and substituted.
    rpc.ping().unwrap();
    rpc.ping().unwrap();

    server_handle.join().unwrap();
}

#[test]
fn test_sync_indexers_to_hash() {
    let hash = bitcoin::BlockHash::all_zeros();
    let zero_hash = hash.to_string();

    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |mut write, mut read| async move {
                // Read the SyncIndexersToHashRequest.
                let msg = read.next().await.unwrap().unwrap();
                let text = msg.into_text().unwrap();
                let received: protocol::Message = serde_json::from_str(&text).unwrap();

                assert_eq!(
                    received.parse_command().unwrap(),
                    protocol::Command::SyncIndexersToHashRequest
                );

                // Decode and verify the payload.
                let decoded = received.decode().unwrap();
                let hash_str = match decoded {
                    protocol::Payload::SyncIndexersToHashRequest(r) => r.hash,
                    _ => panic!("expected SyncIndexersToHashRequest"),
                };
                assert_eq!(hash_str, zero_hash);

                let id = &received.header.id;

                // Send intermediate notifications first.
                send_job_update(&mut write, id, protocol::JobStatus::Pending).await;
                send_job_update(&mut write, id, protocol::JobStatus::Running).await;

                // Reply with "completed" status
                send_job_update(&mut write, id, protocol::JobStatus::Completed).await;
            }))
    });

    let url: String = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    let hash = bitcoin::BlockHash::all_zeros();
    rpc.sync_indexers_to_hash(hash)
        .expect("result should be ok");

    server_handle.join().unwrap();
}

#[test]
fn test_sync_indexers_to_hash_fail() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |mut write, mut read| async move {
                let msg = read.next().await.unwrap().unwrap();
                let text = msg.into_text().unwrap();
                let received: protocol::Message = serde_json::from_str(&text).unwrap();

                // Reply with "failed" status
                send_job_update(&mut write, &received.header.id, protocol::JobStatus::Failed).await;
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    let hash = bitcoin::BlockHash::all_zeros();
    let res = rpc.sync_indexers_to_hash(hash);
    assert!(matches!(res, Err(TrustRPCError::Other(_))));

    server_handle.join().unwrap();
}

#[test]
fn test_ping_disconnect() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |_, mut read| async move {
                read.next().await.unwrap().unwrap();
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    let res = rpc.ping();
    assert!(matches!(res, Err(TrustRPCError::ConnectionLost)));

    server_handle.join().unwrap();
}

#[test]
fn test_job_wait_reconnect() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // First connection
            mock_connect(&l, |mut write, mut read| async move {
                // Read the SyncIndexersToHashRequest.
                let msg = read.next().await.unwrap().unwrap();
                let text = msg.into_text().unwrap();
                let received: protocol::Message = serde_json::from_str(&text).unwrap();

                assert_eq!(
                    received.parse_command().unwrap(),
                    protocol::Command::SyncIndexersToHashRequest
                );

                let id = &received.header.id;

                // Send intermediate notifications first.
                send_job_update(&mut write, id, protocol::JobStatus::Pending).await;
                send_job_update(&mut write, id, protocol::JobStatus::Running).await;
            })
            .await;

            // Second connection (reconnect)
            mock_connect(&l, |mut write, mut read| async move {
                let msg = read.next().await.unwrap().unwrap();
                let text = msg.into_text().unwrap();
                let received: protocol::Message = serde_json::from_str(&text).unwrap();

                assert_eq!(
                    received.parse_command().unwrap(),
                    protocol::Command::JobSubscribeRequest
                );

                // Decode and verify the payload.
                let decoded = received.decode().unwrap();
                let jid = match decoded {
                    protocol::Payload::JobSubscribeRequest(r) => r.job_id,
                    _ => panic!("expected SyncIndexersToHashRequest"),
                };
                assert_eq!(jid, TEST_JOB_ID);

                // Reply with the final "completed" notification
                send_job_update(
                    &mut write,
                    &received.header.id,
                    protocol::JobStatus::Completed,
                )
                .await;
            })
            .await;
        });
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    let hash = bitcoin::BlockHash::all_zeros();
    let result = rpc.sync_indexers_to_hash(hash);
    assert!(
        result.is_ok(),
        "expected transparent reconnect + Ok(()), got {:?}",
        result
    );

    server_handle.join().unwrap();
}

#[test]
fn test_cmd_timeout() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |_, mut read| async move {
                while let Some(Ok(_)) = read.next().await {}
            }))
    });

    let url = format!("ws://{}", addr);
    let mut cfg = test_config(&url);
    cfg.cmd_timeout = Duration::from_millis(0);
    let mut rpc = TrustRPC::new(cfg).unwrap();

    let res = rpc.ping();
    assert!(matches!(res, Err(TrustRPCError::Timeout(_))));

    let hash = bitcoin::BlockHash::all_zeros();
    let res = rpc.sync_indexers_to_hash(hash);
    assert!(matches!(res, Err(TrustRPCError::Timeout(_))));

    drop(rpc);
    server_handle.join().unwrap();
}

#[test]
fn test_non_text_message_ignored() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |mut write, mut read| async move {
                _ = read.next().await.unwrap().unwrap();

                write
                    .send(tungstenite::Message::Binary(vec![1, 2, 3].into()))
                    .await
                    .unwrap();

                let response = protocol::encode(
                    "1",
                    &protocol::Payload::PingResponse(protocol::PingResponse {
                        origin_timestamp: 10,
                        timestamp: 20,
                    }),
                )
                .unwrap();

                write
                    .send(tungstenite::Message::text(
                        protocol::marshal(&response).unwrap(),
                    ))
                    .await
                    .unwrap();
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    rpc.ping().unwrap();

    server_handle.join().unwrap();
}

#[test]
fn test_job_protocol_error() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |mut write, mut read| async move {
                let msg = read.next().await.unwrap().unwrap();
                let text = msg.into_text().unwrap();
                let received: protocol::Message = serde_json::from_str(&text).unwrap();

                let notif = protocol::encode(
                    &received.header.id,
                    &protocol::Payload::JobUpdateNotification(protocol::JobUpdateNotification {
                        job: protocol::JobInfo {
                            job_id: TEST_JOB_ID.into(),
                            job_type: TEST_JOB_TYPE.into(),
                            status: protocol::JobStatus::Running,
                        },
                        error: Some(protocol::ProtocolError {
                            timestamp: 0,
                            trace: None,
                            message: "fail".into(),
                        }),
                    }),
                )
                .unwrap();

                write
                    .send(tungstenite::Message::text(
                        protocol::marshal(&notif).unwrap(),
                    ))
                    .await
                    .unwrap();
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    let hash = bitcoin::BlockHash::all_zeros();
    let res = rpc.sync_indexers_to_hash(hash);
    assert!(matches!(res, Err(TrustRPCError::Protocol(_))));

    server_handle.join().unwrap();
}

#[test]
fn test_job_wait_disconnect() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(mock_connect(&l, |_write, mut read| async move {
                let _ = read.next().await;
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    let hash = bitcoin::BlockHash::all_zeros();
    let res = rpc.sync_indexers_to_hash(hash);
    assert!(matches!(res, Err(TrustRPCError::ConnectionLost)));

    server_handle.join().unwrap();
}

#[test]
fn test_reconnect_exponential_backoff() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();

    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Read the request, send Pending to establish active_job, then drop.
            mock_connect(&l, |mut write, mut read| async move {
                let msg = read.next().await.unwrap().unwrap();
                let text = msg.into_text().unwrap();
                let received: protocol::Message = serde_json::from_str(&text).unwrap();
                send_job_update(
                    &mut write,
                    &received.header.id,
                    protocol::JobStatus::Pending,
                )
                .await;
            })
            .await;

            // Drop next connection attemps
            let tokio_listener = tokio::net::TcpListener::from_std(l.try_clone().unwrap()).unwrap();
            for _ in 0..2 {
                let (stream, _) = tokio_listener.accept().await.unwrap();
                drop(stream);
            }

            // Reconnect and send respond
            let (stream, _) = tokio_listener.accept().await.unwrap();
            let ws_stream = accept_async(stream).await.unwrap();
            let (mut write, mut read) = ws_stream.split();

            let msg = read.next().await.unwrap().unwrap();
            let text = msg.into_text().unwrap();
            let received: protocol::Message = serde_json::from_str(&text).unwrap();
            assert_eq!(
                received.parse_command().unwrap(),
                protocol::Command::JobSubscribeRequest
            );

            send_job_update(
                &mut write,
                &received.header.id,
                protocol::JobStatus::Completed,
            )
            .await;
        });
    });

    let url = format!("ws://{}", addr);
    let mut cfg = test_config(&url);
    cfg.backoff_initial = Duration::from_millis(20);
    cfg.backoff_max = Duration::from_millis(40);

    let mut rpc = TrustRPC::new(cfg).unwrap();

    let hash = bitcoin::BlockHash::all_zeros();
    assert!(rpc.sync_indexers_to_hash(hash).is_ok());

    server_handle.join().unwrap();
}
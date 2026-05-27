use super::*;
use bitcoin::hashes::Hash;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::net::TcpListener;
use std::time::Duration;
use tokio_tungstenite::accept_async;

mod container_tests {
    use super::*;
    use std::thread::sleep;
    use testcontainers::{
        GenericBuildableImage, GenericImage, ImageExt,
        core::{BuildImageOptions, ContainerPort, ExecCommand, WaitFor},
        runners::{AsyncBuilder, AsyncRunner},
    };

    const REGNET_TEST_ADDR: &str = "2MxGhR8wmKPC8Dwz3v4KpW3HGqUgrRmdur2";

    // JWT secret used for tbcd admin WebSocket auth.
    const JWT_SECRET: [u8; 32] = [0u8; 32];
    const JWT_SECRET_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    // tbcd serves the admin WebSocket (which handles all commands) at this path.
    const TBCD_WS_PATH: &str = "/v1/admin/ws";
    const TBCD_WS_PORT: u16 = 8082;

    fn skip_docker() -> bool {
        let res = match std::env::var("HEMI_DOCKER_TESTS") {
            Ok(v) => v,
            Err(_) => return true,
        };
        !matches!(res.as_str(), "true" | "t" | "1")
    }

    #[test]
    fn test_synced_with_tbc_container() {
        if skip_docker() {
            return;
        }

        let tbcd_root = project_root::get_project_root().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let x: u8 = rand::random();
        let bitcoind_container_name = format!("bitcoind-{}", x);

        let (bitcoind, tbcd, url) = rt.block_on(async {
            // Starts bitcoind (regtest)
            let bitcoind = GenericImage::new("kylemanna/bitcoind", "latest")
                .with_exposed_port(ContainerPort::Tcp(18444))
                .with_wait_for(WaitFor::message_on_stdout("dnsseed thread exit"))
                .with_network("trust_tests")
                .with_container_name(&bitcoind_container_name)
                .with_cmd([
                    "bitcoind",
                    "-regtest=1",
                    "-debug=1",
                    "-rpcallowip=0.0.0.0/0",
                    "-rpcbind=0.0.0.0:18443",
                    "-txindex=1",
                    "-noonion",
                    "-listenonion=0",
                    "-fallbackfee=0.01",
                    "-peerbloomfilters=1",
                ])
                .start()
                .await
                .expect("bitcoind failed to start");

            // Generate 10 blocks
            let cmd = ExecCommand::new([
                "bitcoin-cli",
                "-regtest=1",
                "generatetoaddress",
                "10",
                REGNET_TEST_ADDR,
            ]);

            bitcoind.exec(cmd).await.unwrap();

            let tbc_seeds = format!("{}:18444", bitcoind_container_name);

            // Starts tbcd.
            // It logs "handle (tbc admin): /v1/admin/ws" to stderr
            // once it has registered the admin WebSocket handler.
            let tbcd_image = GenericBuildableImage::new("hemilabs/tbcd-test", "latest")
                .with_dockerfile(tbcd_root.join("docker/tbcd/Dockerfile"))
                .with_file(tbcd_root, ".")
                .build_image_with(BuildImageOptions::new().with_skip_if_exists(true))
                .await
                .expect("could not build docker image for tbcd");

            let tbcd = tbcd_image
                .with_exposed_port(ContainerPort::Tcp(TBCD_WS_PORT))
                .with_wait_for(WaitFor::message_on_stderr("handle (tbc admin)"))
                .with_env_var("TBC_NETWORK", "localnet")
                .with_env_var("TBC_SEEDS", tbc_seeds)
                .with_env_var("TBC_LISTEN_ADDRESS", "0.0.0.0:8082")
                .with_env_var("TBC_LEVELDB_HOME", "/tmp/tbcd")
                .with_env_var("TBC_JWT_TOKEN", JWT_SECRET_HEX)
                .with_env_var("TBC_BLOCK_CACHE_SIZE", "10mb")
                .with_env_var("TBC_BLOCKHEADER_CACHE_SIZE", "1mb")
                .with_network("trust_tests")
                .start()
                .await
                .expect("tbcd failed to start");

            let tbcd_port = tbcd
                .get_host_port_ipv4(TBCD_WS_PORT)
                .await
                .expect("tbcd port not mapped");

            let url = format!("ws://127.0.0.1:{}{}", tbcd_port, TBCD_WS_PATH);
            (bitcoind, tbcd, url)
        });

        // Starts trust
        let config = Config {
            url: url.clone(),
            jwt_secret: JWT_SECRET,
            cmd_timeout: Duration::from_secs(15),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(5),
        };

        let mut rpc = TrustRPC::new(config).unwrap();

        // Wait up to 25 seconds for tbcd to sync
        let mut synced = false;
        for _ in 0..100 {
            let sync = rpc.synced().expect("synced should return valid response");
            if sync.synced && sync.blockheader_index_height.height == 10 {
                synced = true;
                break;
            }
            println!("received sync status: {:?}", sync);
            sleep(Duration::from_millis(250));
        }
        assert!(synced);

        rt.block_on(async move {
            bitcoind.stop().await.unwrap();
            tbcd.stop().await.unwrap();
        });
    }
}

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
    let notif = protocol::Payload::JobUpdateNotification(protocol::JobUpdateNotification {
        job: protocol::JobInfo {
            job_id: TEST_JOB_ID.into(),
            job_type: TEST_JOB_TYPE.into(),
            status,
        },
        error: None,
    })
    .encode(id)
    .unwrap();
    write
        .send(tungstenite::Message::text(notif.marshal().unwrap()))
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
                    let response = &&protocol::Payload::PingResponse(protocol::PingResponse {
                        origin_timestamp: 10,
                        timestamp: 20,
                    })
                    .encode(&received.header.id)
                    .unwrap();
                    write
                        .send(tungstenite::Message::text(response.marshal().unwrap()))
                        .await
                        .unwrap();
                }
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    // Second call should hang if the message routing
    // channel is not reset and substituted.
    rpc.running().unwrap();
    rpc.running().unwrap();

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
fn test_disconnect() {
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

    let res = rpc.synced();
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

    let res = rpc.synced();
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

                let response = protocol::Payload::PingResponse(protocol::PingResponse {
                    origin_timestamp: 10,
                    timestamp: 20,
                })
                .encode("1")
                .unwrap();

                write
                    .send(tungstenite::Message::text(response.marshal().unwrap()))
                    .await
                    .unwrap();
            }))
    });

    let url = format!("ws://{}", addr);
    let mut rpc = TrustRPC::new(test_config(&url)).unwrap();

    rpc.running().unwrap();

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

                let notif =
                    protocol::Payload::JobUpdateNotification(protocol::JobUpdateNotification {
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
                    })
                    .encode(&received.header.id)
                    .unwrap();

                write
                    .send(tungstenite::Message::text(notif.marshal().unwrap()))
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

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
    use bitcoin::{BlockHash, address::Address};
    use futures_util::StreamExt;
    use tar::Builder;
    use testcontainers::bollard::Docker;
    use testcontainers::bollard::body_full;
    use testcontainers::{
        ContainerAsync, GenericImage, ImageExt,
        core::{ContainerPort, ExecCommand, WaitFor},
        runners::AsyncRunner,
    };
    use walkdir::WalkDir;

    const REGNET_TEST_ADDR: &str = "2MxGhR8wmKPC8Dwz3v4KpW3HGqUgrRmdur2";

    // JWT secret used for tbcd admin WebSocket auth.
    const JWT_SECRET: [u8; 32] = [0u8; 32];
    const JWT_SECRET_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    // tbcd serves the admin WebSocket (which handles all commands) at this path.
    const TBCD_WS_PATH: &str = "/v1/admin/ws";
    const TBCD_WS_PORT: u16 = 8082;

    struct ContainerSet<'a> {
        rt: &'a Runtime,
        containers: Vec<ContainerAsync<GenericImage>>,
    }

    impl<'a> ContainerSet<'a> {
        // Returns the container ID of the tbcd container.
        fn tbcd_id(&self) -> &str {
            self.containers[0].id()
        }
    }

    impl<'a> Drop for ContainerSet<'a> {
        fn drop(&mut self) {
            let containers = std::mem::take(&mut self.containers);
            self.rt.block_on(async move {
                for c in containers {
                    c.stop().await.unwrap();
                }
            });
        }
    }

    fn run_subtests(tests: &[(&str, bool, Result<()>)]) {
        print!("\nRunning subtests:\n\n");
        let mut pass = true;
        for t in tests {
            match &t.2 {
                Ok(_) => println!("test {} ... ok", t.0),
                Err(e) => {
                    println!("test {} ... FAIL: {}", t.0, e);
                    if t.1 {
                        panic!("test {} failed early: {:?}", t.0, e);
                    }
                    pass = false;
                }
            }
        }

        if !pass {
            panic!("One or more subtests failed")
        }
        print!("\nAll subtests passed.\n\n")
    }

    fn skip_docker() -> bool {
        let res = match std::env::var("HEMI_DOCKER_TESTS") {
            Ok(v) => v,
            Err(_) => return true,
        };
        !matches!(res.as_str(), "true" | "t" | "1")
    }

    fn create_test_header(parent_hash: BlockHash, n: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: parent_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 12345,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: n,
        }
    }

    // Returns a block containing a keystone OP_RETURN tx, and the abrev hash
    // used to look it up via keystone_txs_by_hash.
    fn create_test_block_with_keystone(
        parent_hash: BlockHash,
        n: u32,
        utxo: &protocol::Utxo,
    ) -> (bitcoin::Block, [u8; 32]) {
        let mut abrev = [0u8; 76];
        abrev[0] = 1; // Version
        abrev[1..5].copy_from_slice(&1u32.to_be_bytes()); // L1BlockNumber
        abrev[5..9].copy_from_slice(&2u32.to_be_bytes()); // L2BlockNumber

        let abrev_hash = {
            let h = bitcoin::hashes::sha256d::Hash::hash(&abrev);
            let mut b = *h.as_byte_array();
            b.reverse();
            b
        };

        let mut op_return_data = Vec::with_capacity(4 + 76);
        op_return_data.extend_from_slice(b"HEMI");
        op_return_data.extend_from_slice(&abrev);

        let push_data = bitcoin::script::PushBytesBuf::try_from(op_return_data).unwrap();
        let keystone_script = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(&push_data)
            .into_script();

        let coinbase = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::Script::builder().push_int(n as i64).into_script(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(5000000000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let tx_id = bitcoin::transaction::Txid::from_str(&utxo.tx_id).unwrap();
        let prev_out = bitcoin::OutPoint::new(tx_id, utxo.out_index);

        let keystone_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: prev_out,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: keystone_script,
            }],
        };

        let txdata = vec![coinbase, keystone_tx];
        let merkle_root = bitcoin::merkle_tree::calculate_root(
            txdata.iter().map(|tx| tx.compute_txid().to_raw_hash()),
        )
        .map(bitcoin::TxMerkleNode::from_raw_hash)
        .unwrap_or(bitcoin::TxMerkleNode::all_zeros());

        let header = bitcoin::block::Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: parent_hash,
            merkle_root,
            time: 12345,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: n,
        };

        let block = bitcoin::Block { header, txdata };
        (block, abrev_hash)
    }

    fn create_test_containers(
        rt: &'_ Runtime,
        block_count: u32,
    ) -> (ContainerSet<'_>, String, Vec<String>) {
        let tbcd_root = project_root::get_project_root().unwrap();

        let x: u8 = rand::random();
        let bitcoind_container_name = format!("bitcoind-{}", x);

        let docker = Docker::connect_with_local_defaults().unwrap();

        rt.block_on(async {
            // Skip the build if the image already exists
            if docker
                .inspect_image("hemilabs/tbcd-test:latest")
                .await
                .is_err()
            {
                let tar_bytes = create_build_context(tbcd_root.to_str().unwrap());
                let options = testcontainers::bollard::query_parameters::BuildImageOptions {
                    dockerfile: "docker/tbcd/Dockerfile".to_string(),
                    t: Some("hemilabs/tbcd-test:latest".to_string()),
                    q: true,
                    ..Default::default()
                };
                let mut build_stream =
                    docker.build_image(options, None, Some(body_full(tar_bytes.into())));
                while let Some(msg) = build_stream.next().await {
                    match msg {
                        Ok(info) => println!("Build: {info:?}"),
                        Err(e) => panic!("Docker image build failed: {e:?}"),
                    }
                }
            }

            let mut wait_for_insert: String = "handle (tbc admin)".into();
            let mut tbc_seeds: String = "".into();
            let mut containers = vec![];
            let mut block_hashes = vec![];

            if block_count > 0 {
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

                let cmd = ExecCommand::new([
                    "bitcoin-cli",
                    "-regtest=1",
                    "generatetoaddress",
                    &block_count.to_string(),
                    REGNET_TEST_ADDR,
                ]);
                let mut res = bitcoind.exec(cmd).await.unwrap();
                let stdo = res.stdout_to_vec().await.unwrap();
                block_hashes = serde_json::from_slice(&stdo).expect("Failed to parse JSON");
                containers.push(bitcoind);

                // Wait for tbcd to insert blocks before returning
                wait_for_insert = format!(
                    "Insert block {} at {}",
                    block_hashes[block_hashes.len() - 1],
                    block_count
                );

                // Set bitcoind as a peer for tbcd
                tbc_seeds = format!("{}:18444", bitcoind_container_name);
            };

            // Starts tbcd.
            // It logs "handle (tbc admin): /v1/admin/ws" to stdout
            // once it has registered the admin WebSocket handler.
            let tbcd_image = GenericImage::new("hemilabs/tbcd-test", "latest");

            let tbcd = tbcd_image
                .with_exposed_port(ContainerPort::Tcp(TBCD_WS_PORT))
                .with_wait_for(WaitFor::message_on_stderr("handle (tbc admin)"))
                .with_wait_for(WaitFor::message_on_stderr(wait_for_insert))
                .with_env_var("TBC_NETWORK", "localnet")
                .with_env_var("TBC_AUTO_INDEX", "false")
                .with_env_var("TBC_SEEDS", tbc_seeds)
                .with_env_var("TBC_LISTEN_ADDRESS", "0.0.0.0:8082")
                .with_env_var("TBC_LEVELDB_HOME", "/tmp/tbcd")
                .with_env_var("TBC_JWT_TOKEN", JWT_SECRET_HEX)
                .with_env_var("TBC_BLOCK_CACHE_SIZE", "10mb")
                .with_env_var("TBC_BLOCKHEADER_CACHE_SIZE", "1mb")
                .with_env_var("TBC_HEMI_INDEX", "true")
                .with_network("trust_tests")
                .start()
                .await
                .expect("tbcd failed to start");

            let tbcd_port = tbcd
                .get_host_port_ipv4(TBCD_WS_PORT)
                .await
                .expect("tbcd port not mapped");

            containers.insert(0, tbcd);
            let url = format!("ws://127.0.0.1:{}{}", tbcd_port, TBCD_WS_PATH);
            let cs = ContainerSet { rt, containers };
            (cs, url, block_hashes)
        })
    }

    #[test]
    fn test_trust_rpc_e2e() {
        if skip_docker() {
            return;
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (_cs, url, hashes) = create_test_containers(&rt, 10);

        // Starts trust
        let config = Config {
            url: url.clone(),
            jwt_secret: JWT_SECRET,
            cmd_timeout: Duration::from_secs(15),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(5),
        };

        let mut rpc = TrustRPC::new(config).unwrap();

        struct TestTableItem {
            name: &'static str,
            run: fn(
                rpc: &mut TrustRPC,
                headers: &Vec<BlockHash>,
                txs: &mut Vec<protocol::Utxo>,
            ) -> Result<()>,
            early_exit: bool,
        }

        let hashes: Vec<BlockHash> = hashes
            .iter()
            .map(|bh| bitcoin::BlockHash::from_str(bh).unwrap())
            .collect();

        let tests = vec![
            TestTableItem {
                name: "running",
                run: |rpc, _, _| {
                    if !rpc.running()? {
                        return Err(TrustRPCError::Other("expected TBC to be running".into()));
                    }
                    Ok(())
                },
                early_exit: true,
            },
            TestTableItem {
                name: "sync_indexers_to_hash",
                run: |rpc, hashes, _| rpc.sync_indexers_to_hash(hashes[9]),
                early_exit: true,
            },
            TestTableItem {
                name: "block_headers_insert",
                run: |rpc, hashes, _| {
                    let fake_header = create_test_header(hashes[3], 10);
                    let (itt, canon, _, count) = rpc.block_headers_insert(&[fake_header])?;
                    if count != 1 || itt != "fork extended" || canon.block_hash() != hashes[9] {
                        return Err(TrustRPCError::Other(format!(
                            "Unexpected insert response: count {:?} itt {:?} canonical block {:?}",
                            count, itt, canon
                        )));
                    }
                    Ok(())
                },
                early_exit: true,
            },
            TestTableItem {
                name: "utxos_by_address",
                run: |rpc, _, utxos| {
                    let addr: Address = Address::from_str(REGNET_TEST_ADDR)
                        .unwrap()
                        .require_network(bitcoin::Network::Regtest)
                        .unwrap();
                    let new_utxos = rpc.utxos_by_address(addr, 0, 10, false)?;
                    if new_utxos.len() != 10 {
                        return Err(TrustRPCError::Other(format!(
                            "Expected 10 utxos, got {}",
                            utxos.len()
                        )));
                    }
                    *utxos = new_utxos.clone();
                    for x in new_utxos {
                        if x.value != 5000000000 {
                            return Err(TrustRPCError::Other(format!(
                                "expected utxo value 5000000000, got {}",
                                x.value
                            )));
                        }
                    }
                    Ok(())
                },
                early_exit: true,
            },
            TestTableItem {
                name: "synced",
                run: |rpc, _, _| {
                    let sync = rpc.synced()?;
                    if sync.at_least_missing != 1 || sync.blockheader_index_height.height != 10 {
                        return Err(TrustRPCError::Other(format!(
                            "Unexpected sync value: {:?}",
                            sync
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "download_block_from_random_peers",
                run: |rpc, hashes, _| {
                    let blk = rpc.download_block_from_random_peers(hashes[9], 1)?;
                    if blk.block_hash() != hashes[9] {
                        return Err(TrustRPCError::Other(format!(
                            "Unexpected block returned: {:?}",
                            blk
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "block_header_by_hash",
                run: |rpc, hashes, _| {
                    let (height, bh_by_hash) = rpc.block_header_by_hash(hashes[9])?;
                    if bh_by_hash.block_hash() != hashes[9] || height != 10 {
                        return Err(TrustRPCError::Other(format!(
                            "Unexpected header returned: {:?}",
                            bh_by_hash
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "block_header_best",
                run: |rpc, hashes, _| {
                    let (height, bh_by_hash) = rpc.block_header_best()?;
                    if bh_by_hash.block_hash() != hashes[9] || height != 10 {
                        return Err(TrustRPCError::Other(format!(
                            "Unexpected header returned: {:?}",
                            bh_by_hash
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "block_headers_by_height",
                run: |rpc, hashes, _| {
                    let headers: Vec<BlockHash> = rpc
                        .block_headers_by_height(5)?
                        .iter()
                        .map(|e| e.block_hash())
                        .collect();
                    if headers.len() != 2 {
                        return Err(TrustRPCError::Other(format!(
                            "expected 2 headers, got {}",
                            headers.len()
                        )));
                    }
                    let fake_header = create_test_header(hashes[3], 10);
                    if !headers.contains(&hashes[4]) || !headers.contains(&fake_header.block_hash())
                    {
                        return Err(TrustRPCError::Other(format!(
                            "Unexpected headers returned: {:?}",
                            headers
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "block_in_tx_index",
                run: |rpc, hashes, _| {
                    if !rpc.block_in_tx_index(hashes[9])? {
                        return Err(TrustRPCError::Other("block not in tx index".into()));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "full_block_available",
                run: |rpc, hashes, _| {
                    if !rpc.full_block_available(hashes[9])? {
                        return Err(TrustRPCError::Other("full block not available".into()));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "balance_by_address",
                run: |rpc, _, _| {
                    let addr: Address = Address::from_str(REGNET_TEST_ADDR)
                        .unwrap()
                        .require_network(bitcoin::Network::Regtest)
                        .unwrap();
                    let bal = rpc.balance_by_address(addr)?;
                    if bal != 50000000000 {
                        return Err(TrustRPCError::Other(format!(
                            "wanted balance 50000000000, got {}",
                            bal
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "tx_by_id",
                run: |rpc, _, utxos| {
                    let tx_id: bitcoin::transaction::Txid =
                        bitcoin::transaction::Txid::from_str(&utxos[0].tx_id).unwrap();
                    let tx = rpc.tx_by_id(tx_id)?;
                    if tx.compute_txid() != tx_id || !tx.is_coinbase() {
                        return Err(TrustRPCError::Other(format!(
                            "Unexpected TX returned: {:?}",
                            tx
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "script_hash_available_to_spend",
                run: |rpc, _, utxos| {
                    let tx_id: bitcoin::transaction::Txid =
                        bitcoin::transaction::Txid::from_str(&utxos[0].tx_id).unwrap();
                    if !rpc.script_hash_available_to_spend(tx_id, utxos[0].out_index)? {
                        return Err(TrustRPCError::Other(
                            "txOut should be available to spend".into(),
                        ));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "block_by_hash",
                run: |rpc, hashes, _| {
                    let blk = rpc.block_by_hash(hashes[9])?;
                    if blk.block_hash() != hashes[9] {
                        return Err(TrustRPCError::Other(format!(
                            "expected block hash {:?}, got {:?}",
                            hashes[9],
                            blk.block_hash()
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                name: "block_hash_by_tx_id",
                run: |rpc, hashes, utxos| {
                    let tx_id = bitcoin::transaction::Txid::from_str(&utxos[0].tx_id).unwrap();
                    let block_hash = rpc.block_hash_by_tx_id(tx_id)?;
                    if !hashes.contains(&block_hash) {
                        return Err(TrustRPCError::Other(format!(
                            "block hash {:?} not in expected chain",
                            block_hash
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
            TestTableItem {
                // Inserts a block with a keystone then syncs the indexer.
                name: "block_insert",
                run: |rpc, hashes, utxos| {
                    let (block, _) = create_test_block_with_keystone(hashes[9], 42, &utxos[9]);
                    let block_hash = block.block_hash();
                    rpc.block_headers_insert(&[block.header])?;
                    let inserted_hash = rpc.block_insert(block)?;
                    if inserted_hash != block_hash {
                        return Err(TrustRPCError::Other(format!(
                            "expected inserted hash {:?}, got {:?}",
                            block_hash, inserted_hash
                        )));
                    }
                    rpc.sync_indexers_to_hash(block_hash)?;
                    Ok(())
                },
                early_exit: true,
            },
            TestTableItem {
                name: "keystone_txs_by_hash",
                run: |rpc, hashes, utxos| {
                    let (_, abrev_hash) = create_test_block_with_keystone(hashes[9], 42, &utxos[9]);
                    let abrev_hash_hex = hex::encode(abrev_hash);
                    let txs = rpc.keystone_txs_by_hash(abrev_hash_hex, 1)?;
                    if txs.len() != 1 {
                        return Err(TrustRPCError::Other(format!(
                            "expected 1 keystone tx, got {}",
                            txs.len()
                        )));
                    }
                    Ok(())
                },
                early_exit: false,
            },
        ];

        let mut utxos = vec![];
        let subtests: Vec<(&str, bool, Result<()>)> = tests
            .iter()
            .map(|t| (t.name, t.early_exit, (t.run)(&mut rpc, &hashes, &mut utxos)))
            .collect();
        run_subtests(&subtests)
    }

    #[test]
    fn test_trust_rpc_e2e_negative() {
        if skip_docker() {
            return;
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (_cs, url, _) = create_test_containers(&rt, 1);

        let config = Config {
            url: url.clone(),
            jwt_secret: JWT_SECRET,
            cmd_timeout: Duration::from_secs(15),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(5),
        };

        let mut rpc = TrustRPC::new(config).unwrap();

        struct TestTableItem {
            name: &'static str,
            run: fn(&mut TrustRPC) -> Result<()>,
        }

        let tests: Vec<TestTableItem> = vec![
            TestTableItem {
                name: "block_headers_insert/empty_slice",
                run: |rpc| match rpc.block_headers_insert(&[]) {
                    Err(TrustRPCError::Protocol(_)) => Ok(()),
                    e => Err(TrustRPCError::Other(format!(
                        "expected Protocol error, got {:?}",
                        e
                    ))),
                },
            },
            TestTableItem {
                name: "block_header_by_hash/not_found",
                run: |rpc| {
                    let fake_hash = bitcoin::BlockHash::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.block_header_by_hash(fake_hash) {
                        Err(TrustRPCError::Protocol(_)) => Ok(()),
                        e => Err(TrustRPCError::Other(format!(
                            "expected Protocol error, got {:?}",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "block_by_hash/not_found",
                run: |rpc| {
                    let fake_hash = bitcoin::BlockHash::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.block_by_hash(fake_hash) {
                        Err(TrustRPCError::Protocol(_)) => Ok(()),
                        e => Err(TrustRPCError::Other(format!(
                            "expected Protocol error, got {:?}",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "download_block_from_random_peers/not_found",
                run: |rpc| {
                    let fake_hash = bitcoin::BlockHash::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.download_block_from_random_peers(fake_hash, 1) {
                        Err(TrustRPCError::NotFound(_, _)) => Ok(()),
                        e => Err(TrustRPCError::Other(format!(
                            "expected NotFound error, got {:?}",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "tx_by_id/not_found",
                run: |rpc| {
                    let fake_tx_id = bitcoin::transaction::Txid::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.tx_by_id(fake_tx_id) {
                        Err(TrustRPCError::Protocol(_)) => Ok(()),
                        e => Err(TrustRPCError::Other(format!(
                            "expected Protocol, got {:?}",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "block_hash_by_tx_id/not_found",
                run: |rpc| {
                    let fake_tx_id = bitcoin::transaction::Txid::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.block_hash_by_tx_id(fake_tx_id) {
                        Err(TrustRPCError::Protocol(_)) => Ok(()),
                        e => Err(TrustRPCError::Other(format!(
                            "expected Protocol, got {:?}",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "block_headers_by_height/out_of_range",
                run: |rpc| match rpc.block_headers_by_height(9999) {
                    Err(TrustRPCError::Protocol(_)) => Ok(()),
                    e => Err(TrustRPCError::Other(format!(
                        "expected Protocol, got {:?}",
                        e
                    ))),
                },
            },
            TestTableItem {
                name: "block_in_tx_index/not_indexed",
                run: |rpc| {
                    let fake_hash = bitcoin::BlockHash::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.block_in_tx_index(fake_hash) {
                        Ok(false) => Ok(()),
                        Ok(true) => Err(TrustRPCError::Other("expected not indexed".into())),
                        Err(e) => Err(TrustRPCError::Other(format!(
                            "expected Ok(false), got Err({:?})",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "full_block_available/not_available",
                run: |rpc| {
                    let fake_hash = bitcoin::BlockHash::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.full_block_available(fake_hash) {
                        Ok(false) => Ok(()),
                        Ok(true) => Err(TrustRPCError::Other("expected not available".into())),
                        Err(e) => Err(TrustRPCError::Other(format!(
                            "expected Ok(false), got Err({:?})",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "script_hash_available_to_spend/not_available",
                run: |rpc| {
                    let fake_tx_id = bitcoin::transaction::Txid::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.script_hash_available_to_spend(fake_tx_id, 0) {
                        Ok(false) => Ok(()),
                        e => Err(TrustRPCError::Other(format!(
                            "expected Ok(false), got {:?}",
                            e
                        ))),
                    }
                },
            },
            TestTableItem {
                name: "keystone_txs_by_hash/not_found",
                run: |rpc| match rpc.keystone_txs_by_hash(JWT_SECRET_HEX.to_string(), 1) {
                    Err(TrustRPCError::Protocol(_)) => Ok(()),
                    e => Err(TrustRPCError::Other(format!(
                        "expected Protocol, got {:?}",
                        e
                    ))),
                },
            },
            TestTableItem {
                name: "sync_indexers_to_hash/fake_hash",
                run: |rpc| {
                    let fake_hash = bitcoin::BlockHash::from_str(JWT_SECRET_HEX).unwrap();
                    match rpc.sync_indexers_to_hash(fake_hash) {
                        Err(TrustRPCError::JobFailed(_)) => Ok(()),
                        e => Err(TrustRPCError::Other(format!(
                            "expected JobFailed, got {:?}",
                            e
                        ))),
                    }
                },
            },
        ];

        let subtests: Vec<(&str, bool, Result<()>)> = tests
            .iter()
            .map(|t| (t.name, false, (t.run)(&mut rpc)))
            .collect();
        run_subtests(&subtests)
    }

    #[test]
    fn test_trust_rpc_reconnect() {
        if skip_docker() {
            return;
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (cs, url, _) = create_test_containers(&rt, 0);
        let tbcd_id = cs.tbcd_id().to_string();

        let config = Config {
            url: url.clone(),
            jwt_secret: JWT_SECRET,
            cmd_timeout: Duration::from_secs(1),
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_millis(500),
        };

        let mut rpc = TrustRPC::new(config).unwrap();

        rpc.running().unwrap();

        rt.block_on(async {
            use testcontainers::bollard::container::LogOutput;
            use testcontainers::bollard::query_parameters::LogsOptionsBuilder;

            let docker = Docker::connect_with_local_defaults().unwrap();
            docker
                .restart_container(&tbcd_id, None)
                .await
                .expect("failed to restart tbcd container");

            let mut stream = docker.logs(
                &tbcd_id,
                Some(
                    LogsOptionsBuilder::default()
                        .follow(true)
                        .stderr(true)
                        .stdout(false)
                        .tail("0")
                        .build(),
                ),
            );

            let wait = b"handle (tbc admin)";
            while let Some(Ok(entry)) = stream.next().await {
                match &entry {
                    LogOutput::StdErr { message } => {
                        if message.windows(wait.len()).any(|w| w == wait) {
                            break;
                        }
                        continue;
                    }
                    _ => continue,
                }
            }
        });

        rpc.running()
            .expect("TrustRPC did not reconnect after tbcd restart");
    }

    fn create_build_context(dir: &str) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut tar = Builder::new(&mut tar_buf);
            for entry in WalkDir::new(dir).follow_links(true) {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(dir).unwrap();

                if relative.as_os_str().is_empty()
                    || str::starts_with(relative.to_str().unwrap(), ".git")
                    || str::starts_with(relative.to_str().unwrap(), "target")
                    || str::starts_with(relative.to_str().unwrap(), ".gocache")
                {
                    // println!("skipping {}", relative.display());
                    continue;
                }

                println!("{}, {}", path.display(), relative.display());

                if path.is_file() {
                    tar.append_path_with_name(path, relative).unwrap();
                } else if path.is_dir() {
                    tar.append_dir(relative, path).unwrap();
                }
            }
            tar.finish().unwrap();
        }
        tar_buf
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
    assert!(matches!(res, Err(TrustRPCError::JobFailed(_))));

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

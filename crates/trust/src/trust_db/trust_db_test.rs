use std::vec;

use super::*;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use tempfile::tempdir;

fn new_test_db() -> Arc<TrustDB> {
    let tmp = tempdir().expect("temp dir should have been created");
    TrustDB::open(tmp.path()).expect("database should open")
}

fn create_test_header(parent_hash: BlockHash, n: u32) -> Header {
    Header {
        version: bitcoin::blockdata::block::Version::ONE,
        prev_blockhash: parent_hash,
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 12345,
        bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
        nonce: n,
    }
}

// Changing the bits can cause an overflow with invalid data, so
// this function guarantees you only change them if necessary.
fn create_test_header_with_bits(parent_hash: BlockHash, n: u32, bits: u32) -> Header {
    Header {
        version: bitcoin::blockdata::block::Version::ONE,
        prev_blockhash: parent_hash,
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 12345,
        bits: bitcoin::CompactTarget::from_consensus(bits),
        nonce: n,
    }
}

#[test]
fn test_get_cfs() {
    let db = new_test_db();
    for cf in TrustDBTable::iterator() {
        db.get_cf(cf);
    }
}

#[test]
fn test_basic() {
    let db = new_test_db();
    let key = "key";
    let value = "value";

    let result = db.put(&MetadataCF, key, value);
    assert!(result.is_ok());

    let mut has = db.has(&MetadataCF, key);
    assert!(has);

    let mut get = db.get(&MetadataCF, key);
    assert!(get.is_ok());
    assert_eq!(get.unwrap(), value.as_bytes());

    let del = db.del(&MetadataCF, key);
    assert!(del.is_ok());

    get = db.get(&MetadataCF, key);
    assert!(get.is_err());

    has = db.has(&MetadataCF, key);
    assert!(!has);
}

#[test]
fn test_get_neg() {
    let db = new_test_db();

    let get = db.get(&MetadataCF, "key");
    assert!(get.is_err());
}

#[test]
fn test_del_neg() {
    let db = new_test_db();

    let del = db.del(&MetadataCF, "key");
    assert!(del.is_ok());
}

#[test]
fn test_has_neg() {
    let db = new_test_db();

    let has = db.has(&MetadataCF, "key");
    assert!(!has);
}

#[test]
fn test_encode_block_header() {
    let header = create_test_header(BlockHash::all_zeros(), 1);
    let bh = &BlockHeader {
        hash: header.block_hash(),
        height: 99999,
        difficulty: U256::from(12345_u32),
        header,
    };

    let enc: EncodedHeader = bh.into();
    assert_eq!(enc.len(), BlockHeader::SIZE);

    // check height encoding
    assert_eq!(&enc[..8], bh.height.to_be_bytes());

    // check that header encoding
    let mut expected_header = [0u8; 80];
    header
        .consensus_encode(&mut &mut expected_header[..])
        .unwrap();
    assert_eq!(&enc[8..88], &expected_header);

    // check diff encoding
    let expected_diff = bh.difficulty.to_be_bytes();
    assert_eq!(&enc[88..], &expected_diff);
}

#[test]
fn test_decode_block_header() {
    let test_table = vec![
        (0, U256::ZERO),
        (u64::MAX, U256::MAX),
        (99999, U256::from(12345_u32)),
    ];

    let header = create_test_header(BlockHash::all_zeros(), 1);
    for (height, difficulty) in test_table {
        let bh = &BlockHeader {
            hash: header.block_hash(),
            height,
            difficulty,
            header,
        };
        let enc: EncodedHeader = bh.into();
        let dec = BlockHeader::from(&enc);
        assert_eq!(dec, *bh);
    }
}

#[test]
fn test_height_hash_to_key() {
    // Test with different values
    let test_table = vec![
        (0, BlockHash::all_zeros()),
        (u64::MAX, BlockHash::all_zeros()),
        (
            12345,
            create_test_header(BlockHash::all_zeros(), 1).block_hash(),
        ),
    ];

    for (height, hash) in test_table {
        let key = TrustDB::height_hash_to_key(height, hash);
        assert_eq!(key.len(), TrustDB::HH_KEY_SIZE);

        // check height encoding
        assert_eq!(&key[..8], height.to_be_bytes());

        // check hash encoding
        assert_eq!(&key[8..], hash.as_byte_array());
    }
}

#[test]
fn test_key_to_height_hash() {
    let test_table = vec![
        (0, BlockHash::all_zeros()),
        (u64::MAX, BlockHash::all_zeros()),
        (
            99999,
            create_test_header(BlockHash::all_zeros(), 1).block_hash(),
        ),
    ];

    for (height, hash) in test_table {
        let key = TrustDB::height_hash_to_key(height, hash);
        let (dec_height, dec_hash) = TrustDB::key_to_height_hash(&key);
        assert_eq!(dec_height, height);
        assert_eq!(dec_hash, hash);
    }
}

#[test]
fn test_block_header_genesis_insert() {
    let db = new_test_db();
    let header = create_test_header(BlockHash::all_zeros(), 1);
    let height = 0;
    let diff = U256::from(12345_u32);

    let mut res = db.block_header_genesis_insert(&header, height, diff);
    assert!(res.is_ok());

    let stored = db.get(&HeadersCF, header.block_hash());
    assert!(stored.is_ok());

    let tip = db.get(&HeadersCF, BHS_CANONICAL_TIP_KEY);
    assert!(tip.is_ok());

    let hh_key = TrustDB::height_hash_to_key(height, header.block_hash());
    let hh_stored = db.get(&HeightHashCF, hh_key);
    assert!(hh_stored.is_ok());

    // ensure duplicate fails
    res = db.block_header_genesis_insert(&header, height, diff);
    match res.unwrap_err() {
        TrustDBError::Duplicate(_) => (),
        _ => panic!("Expected Duplicate error"),
    }
}

#[test]
fn test_block_header_genesis_insert_zero_diff() {
    let db = new_test_db();
    let header = create_test_header(BlockHash::all_zeros(), 1);
    let height = 0;
    let diff = U256::ZERO; // should use header's work

    let res = db.block_header_genesis_insert(&header, height, diff);
    assert!(res.is_ok());

    let stored = db.get(&HeadersCF, header.block_hash());
    assert!(stored.is_ok());

    // check if stored header has the correct difficulty
    let stored = stored.unwrap();
    let stored_array: [u8; BlockHeader::SIZE] = stored.try_into().unwrap();
    let dec = BlockHeader::from(&stored_array);
    let work = U256::from_be_bytes(header.work().to_be_bytes());
    assert_ne!(work, diff);
    assert_eq!(dec.difficulty, work);
}

#[test]
fn test_block_header_best() {
    let db = new_test_db();
    let header = create_test_header(BlockHash::all_zeros(), 1);
    let height = 99999;
    let diff = U256::from(12345_u32);

    // check if fails before insert
    let mut best = db.block_header_best();
    match best.unwrap_err() {
        TrustDBError::NotFound(_) => (),
        _ => panic!("Expected NotFound error"),
    }

    let res = db.block_header_genesis_insert(&header, height, diff);
    assert!(res.is_ok());

    best = db.block_header_best();
    assert!(best.is_ok());

    let best_header = best.unwrap();
    assert_eq!(best_header.height, height);
    assert_eq!(best_header.header, header);
    assert_eq!(best_header.difficulty, diff);
    assert_eq!(best_header.hash, header.block_hash());
}

#[test]
fn test_block_header_by_hash() {
    let db = new_test_db();
    let header = create_test_header(BlockHash::all_zeros(), 1);
    let height = 99999;
    let diff = U256::from(12345_u32);

    // check if fails before insert
    let mut res = db.block_header_by_hash(header.block_hash());
    match res.unwrap_err() {
        TrustDBError::NotFound(_) => (),
        _ => panic!("Expected NotFound error"),
    }

    // insert header
    let insert_result = db.block_header_genesis_insert(&header, height, diff);
    assert!(insert_result.is_ok());

    res = db.block_header_by_hash(header.block_hash());
    assert!(res.is_ok());

    let retrieved_header = res.unwrap();
    assert_eq!(retrieved_header.height, height);
    assert_eq!(retrieved_header.header, header);
    assert_eq!(retrieved_header.difficulty, diff);
    assert_eq!(retrieved_header.hash, header.block_hash());

    // check fake hash
    let fake_hash = BlockHash::hash(&[40u8; 32]);
    res = db.block_header_by_hash(fake_hash);
    match res.unwrap_err() {
        TrustDBError::NotFound(_) => (),
        _ => panic!("Expected NotFound error"),
    }
}

#[test]
fn test_block_headers_by_height() {
    let db = new_test_db();
    let height = 99999;
    let diff = U256::from(12345_u32);

    // check if fails before insert
    let mut retrieved = db.block_headers_by_height(height);
    match retrieved.unwrap_err() {
        TrustDBError::NotFound(_) => (),
        _ => panic!("Expected NotFound error"),
    }

    // insert header
    let header = create_test_header(BlockHash::all_zeros(), 1);
    let res = db.block_header_genesis_insert(&header, height, diff);
    assert!(res.is_ok());

    retrieved = db.block_headers_by_height(height);
    assert!(retrieved.is_ok());

    let headers_vec = retrieved.unwrap();
    assert_eq!(headers_vec.len(), 1);

    let h: &BlockHeader = headers_vec.first().unwrap();
    assert_eq!(h.height, height);
    assert_eq!(h.header, header);
    assert_eq!(h.difficulty, diff);
    assert_eq!(h.hash, header.block_hash());

    // check fake height
    retrieved = db.block_headers_by_height(1111);
    match retrieved.unwrap_err() {
        TrustDBError::NotFound(_) => (),
        _ => panic!("Expected NotFound error"),
    }
}

#[test]
fn test_block_headers_by_height_different_heights() {
    let db = new_test_db();
    let height1 = 500;
    let height2 = 501;

    let header1 = create_test_header(BlockHash::all_zeros(), 1);
    let mut header2 = create_test_header(BlockHash::all_zeros(), 2);
    header2.prev_blockhash = header1.block_hash();
    let diff = U256::from(12345_u32);

    let insert = db.block_header_genesis_insert(&header1, height1, diff);
    assert!(insert.is_ok());

    let header2_to_encode = &BlockHeader {
        hash: header2.block_hash(),
        header: header2,
        difficulty: diff,
        height: height2,
    };

    let hh_key = TrustDB::height_hash_to_key(height2, header2.block_hash());
    let ebh: EncodedHeader = header2_to_encode.into();

    db.put(&HeightHashCF, hh_key, []).unwrap();
    db.put(&HeadersCF, header2_to_encode.hash, ebh).unwrap();

    let mut headers = db.block_headers_by_height(height1);
    let mut res = headers.unwrap();
    assert_eq!(res.first().unwrap().hash, header1.block_hash());

    headers = db.block_headers_by_height(height2);
    res = headers.unwrap();
    assert_eq!(res.first().unwrap().hash, header2.block_hash());
}

#[test]
fn test_block_headers_insert_multiple_different_genesis_blocks() {
    let db = new_test_db();

    let correct_genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&correct_genesis, 0, U256::from(1_u32))
        .unwrap();

    let incorrect_genesis = create_test_header(BlockHash::all_zeros(), 2);
    let res = db.block_header_genesis_insert(&incorrect_genesis, 0, U256::from(2_u32));

    match res {
        Err(TrustDBError::GenesisExists(val)) => {
            assert_eq!(val, correct_genesis.block_hash().to_string());
        }
        Err(e) => {
            panic!("unexpected error: {}", e)
        }
        _ => panic!("expected an error"),
    }
}

#[test]
fn test_block_headers_insert_effective_genesis_block() {
    let db = new_test_db();

    let mut genesis = create_test_header(BlockHash::all_zeros(), 0);
    genesis.prev_blockhash = bitcoin::BlockHash::hash(&[1, 2, 3]);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let res = db.block_header_by_hash(genesis.block_hash()).unwrap();

    let genesis_block_header = BlockHeader {
        hash: genesis.block_hash(),
        height: 0,
        difficulty: U256::from(1_u32),
        header: genesis,
    };

    assert_eq!(res, genesis_block_header);
}

fn insert_block_header(
    db: &TrustDB,
    prev_hash: BlockHash,
    height: u64,
    n: u32,
) -> Result<(BlockHeader, InsertType)> {
    let header = create_test_header(prev_hash, n);
    let difficulty = U256::from(n);

    if prev_hash == BlockHash::all_zeros() {
        db.block_header_genesis_insert(&header, height, difficulty)?;
        let block_header = BlockHeader {
            hash: header.block_hash(),
            height,
            header,
            difficulty,
        };
        Ok((block_header, ChainExtend))
    } else {
        let headers = [header];
        let (insert_type, _, last_inserted, _) = db.block_headers_insert(&headers, &[])?;

        // Return the last inserted header
        Ok((last_inserted, insert_type))
    }
}

#[test]
fn test_block_headers_insert() {
    let db = new_test_db();
    let mut hashes = vec![BlockHash::all_zeros()];

    for i in 0..2 {
        let (bh, it) = insert_block_header(&db, hashes[i], i as u64, i as u32).unwrap();
        assert_eq!(
            it,
            ChainExtend,
            "expected chain extend, got {}",
            it.as_str()
        );
        hashes.push(bh.hash);
    }

    let (fork_bh, it) = insert_block_header(&db, hashes[1], 1, 100).unwrap();
    assert_eq!(it, ForkExtend, "expected fork extend, got {}", it.as_str());

    let best = db.block_header_best().unwrap();
    assert_eq!(
        best.hash, hashes[2],
        "best hash should be original chain tip"
    );

    // Make fork canonical
    let (fork_bh2, it) = insert_block_header(&db, fork_bh.hash, 2, 101).unwrap();
    assert_eq!(it, ChainFork, "expected chain fork, got {}", it.as_str());

    let best = db.block_header_best().unwrap();
    assert_eq!(
        best.hash, fork_bh2.hash,
        "best hash should be fork chain tip"
    );
}

#[test]
fn test_block_headers_insert_empty() {
    let db = new_test_db();

    let headers = [];
    let res = db.block_headers_insert(&headers, &[]);
    assert!(res.is_err(), "Expected error for empty headers");
}

#[test]
fn test_block_headers_insert_duplicate() {
    let db = new_test_db();

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let headers = [genesis];
    let res = db.block_headers_insert(&headers, &[]);
    assert!(res.is_err(), "Expected error for duplicate headers");
}

#[test]
fn test_block_headers_insert_missing_parent() {
    let db = new_test_db();

    let header = create_test_header(bitcoin::hashes::Hash::hash(&[1u8; 32]), 1);
    let headers = [header];
    let res = db.block_headers_insert(&headers, &[]);
    match res {
        Err(TrustDBError::NotFound(_)) => (),
        _ => panic!("Expected NotFound error for missing parent"),
    }
}

#[test]
fn test_block_headers_insert_multiple() {
    let db = new_test_db();

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 2);
    let h3 = create_test_header(h2.block_hash(), 3);

    let headers = [h1, h2, h3];
    let (it, canonical, last, count) = db.block_headers_insert(&headers, &[]).unwrap();

    assert_eq!(it, ChainExtend);
    assert_eq!(count, 3);
    assert_eq!(last.height, 3);
    assert_eq!(last.hash, h3.block_hash());
    assert_eq!(canonical.hash, h3.block_hash());

    let best = db.block_header_best().unwrap();
    assert_eq!(best.hash, h3.block_hash());
}

#[test]
fn test_block_headers_insert_fork() {
    const HEADER_COUNT: usize = 3;

    // Forks from genesis
    // (headers to add, bits for difficulty control, expected insert type)
    let test_table = vec![
        (2, 0x1d010000, ForkExtend), // lower cumdiff fork
        (2, 0x1d00ffff, ForkExtend), // equal cumdiff fork
        (1, 0x1c00ffff, ChainFork),  // single header, higher cumdiff
        (3, 0x1c00ffff, ChainFork),  // higher cumdiff
    ];

    for (icount, bits, expected) in test_table {
        let db = new_test_db();

        // Insert canonical chain with standard difficulty
        let mut hashes = vec![BlockHash::all_zeros()];
        for i in 0..HEADER_COUNT {
            let (bh, _) = insert_block_header(&db, hashes[i], i as u64, 10 + i as u32).unwrap();
            hashes.push(bh.hash);
        }

        // Insert fork chain
        let mut new_hashes = vec![hashes[1]];
        let mut headers = vec![];
        for i in 0..icount {
            let fork = create_test_header_with_bits(new_hashes[i], 1000 + i as u32, bits);
            new_hashes.push(fork.block_hash());
            headers.push(fork);
        }

        let (it, canonical, last, count) = db.block_headers_insert(&headers, &[]).unwrap();
        assert_eq!(it, expected);
        assert_eq!(count, icount);
        assert_eq!(last.hash, *new_hashes.last().unwrap());

        let best = db.block_header_best().unwrap();
        assert_eq!(canonical.hash, best.hash);
        match it {
            ChainFork => assert_eq!(best.hash, last.hash),
            ForkExtend => assert_eq!(best.hash, *hashes.last().unwrap()),
            _ => panic!("unexpected insert type"),
        }
    }
}

#[test]
fn test_block_headers_insert_hooks() {
    let db = new_test_db();

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let headers = [h1];
    let key = b"test_key";
    let value = b"test_value";
    let hooks = [(&MetadataCF, key.as_ref(), value.as_ref())];

    let res = db.block_headers_insert(&headers, &hooks);
    assert!(res.is_ok());

    // Verify hook was applied
    let retrieved = db.get(&MetadataCF, key);
    assert!(retrieved.is_ok());
    assert_eq!(retrieved.unwrap(), value);
}

#[test]
fn test_block_headers_insert_partial() {
    let db = new_test_db();

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let headers = [h1];
    let hooks = vec![];
    db.block_headers_insert(&headers, &hooks).unwrap();

    let h2 = create_test_header(h1.block_hash(), 2);
    let headers = [h1, h2];

    let res = db.block_headers_insert(&headers, &hooks);
    assert!(res.is_ok());

    let (it, _, last, count) = res.unwrap();
    assert_eq!(it, ChainExtend);
    assert_eq!(count, 1);
    assert_eq!(last.height, 2);
    assert_eq!(last.hash, h2.block_hash());
}

#[test]
fn test_block_headers_insert_non_contiguous() {
    let db = new_test_db();

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let fake_hash = bitcoin::hashes::Hash::hash(&[42u8; 32]);
    let h2 = create_test_header(fake_hash, 2);
    let headers = [h1, h2];
    let res = db.block_headers_insert(&headers, &[]);
    assert!(res.is_err(), "expected error")
}

#[test]
fn test_block_headers_remove_errors() {
    struct Test {
        name: &'static str,
        pre_insert: Vec<Header>,
        to_remove: Vec<Header>,
        post_tip: Header,
        error_type: TrustDBError,
    }

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 2);
    let fake_hash = bitcoin::hashes::Hash::hash(&[42u8; 32]);
    let fake_block = create_test_header(fake_hash, 2);

    let test_cases = vec![
        Test {
            name: "empty set",
            pre_insert: vec![],
            to_remove: vec![],
            post_tip: genesis,
            error_type: TrustDBError::InvalidParams("".to_string()),
        },
        Test {
            name: "non-contiguous set",
            pre_insert: vec![],
            to_remove: vec![h1, fake_block],
            post_tip: genesis,
            error_type: TrustDBError::InvalidParams("".to_string()),
        },
        Test {
            name: "missing header",
            pre_insert: vec![],
            to_remove: vec![h1],
            post_tip: genesis,
            error_type: TrustDBError::NotFound("".to_string()),
        },
        Test {
            name: "invalid tip",
            pre_insert: vec![h1],
            to_remove: vec![h1],
            post_tip: fake_block,
            error_type: TrustDBError::NotFound("".to_string()),
        },
        Test {
            name: "tip in set",
            pre_insert: vec![h1],
            to_remove: vec![h1],
            post_tip: h1,
            error_type: TrustDBError::InvalidParams("".to_string()),
        },
        Test {
            name: "dangling children",
            pre_insert: vec![h1, h2],
            to_remove: vec![h1],
            post_tip: genesis,
            error_type: TrustDBError::DanglingChild("".to_string()),
        },
    ];

    for t in test_cases {
        let db = new_test_db();
        db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
            .unwrap();

        if !t.pre_insert.is_empty() {
            db.block_headers_insert(&t.pre_insert, &[]).unwrap();
        }

        let result = db.block_headers_remove(&t.to_remove, &t.post_tip, &[]);
        assert!(result.is_err(), "test '{}' should have failed", t.name);

        let err = result.unwrap_err();

        if std::mem::discriminant(&t.error_type) != std::mem::discriminant(&err) {
            panic!("unexpected error: {}", err)
        }
    }
}

#[test]
fn test_block_headers_remove_orphan() {
    let db = new_test_db();
    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let fake_parent = bitcoin::hashes::Hash::hash(&[88u8; 32]);
    let orphan = create_test_header(fake_parent, 1);

    let orphan_bh = BlockHeader {
        hash: orphan.block_hash(),
        height: 1,
        header: orphan,
        difficulty: U256::from(1_u32),
    };
    let enc: EncodedHeader = (&orphan_bh).into();
    db.put(&HeadersCF, orphan.block_hash(), enc).unwrap();

    let hh_key = TrustDB::height_hash_to_key(1, orphan.block_hash());
    db.put(&HeightHashCF, hh_key, []).unwrap();

    let result = db.block_headers_remove(&[orphan], &genesis, &[]);
    match result {
        Err(TrustDBError::NotFound(_)) => (),
        Err(e) => panic!("unexpected error {e}"),
        _ => panic!("expected error"),
    }
}

#[test]
fn test_block_headers_remove_invalid_tip() {
    let db = new_test_db();
    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 20);
    let h3 = create_test_header(h2.block_hash(), 30);
    let headers = [h1, h2, h3];
    db.block_headers_insert(&headers, &[]).unwrap();

    let fork1 = create_test_header(h1.block_hash(), 2);
    let headers = [fork1];
    db.block_headers_insert(&headers, &[]).unwrap();

    let res = db.block_headers_remove(&[h2, h3], &h1, &[]);
    match res {
        Err(TrustDBError::InvalidTip(_)) => (),
        Err(e) => panic!("unexpected error: {e}"),
        _ => panic!("expected error"),
    }
}

#[test]
fn test_block_headers_remove_types() {
    use self::RemoveType::*;

    struct Test {
        name: &'static str,
        pre_insert_first: Vec<Header>,
        pre_insert_second: Vec<Header>,
        to_remove: Vec<Header>,
        post_tip: Header,
        expected_type: RemoveType,
    }

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 2);
    let h3 = create_test_header(h2.block_hash(), 3);
    let fork1 = create_test_header_with_bits(h1.block_hash(), 100, 0x1d010000);
    let fork2 = create_test_header_with_bits(fork1.block_hash(), 101, 0x1d010000);

    let test_cases = vec![
        Test {
            name: "chain descend",
            pre_insert_first: vec![h1, h2],
            pre_insert_second: vec![],
            to_remove: vec![h2],
            post_tip: h1,
            expected_type: ChainDescend,
        },
        Test {
            name: "chain fork",
            pre_insert_first: vec![h1, h2, h3],
            pre_insert_second: vec![fork1, fork2],
            to_remove: vec![h2, h3],
            post_tip: fork2,
            expected_type: ChainFork,
        },
        Test {
            name: "fork descend",
            pre_insert_first: vec![h1, h2],
            pre_insert_second: vec![fork1],
            to_remove: vec![fork1],
            post_tip: h2,
            expected_type: ForkDescend,
        },
    ];

    for t in test_cases {
        let db = new_test_db();
        db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
            .unwrap();

        if !t.pre_insert_first.is_empty() {
            db.block_headers_insert(&t.pre_insert_first, &[]).unwrap();
        }

        if !t.pre_insert_second.is_empty() {
            db.block_headers_insert(&t.pre_insert_second, &[]).unwrap();
        }

        let result = db.block_headers_remove(&t.to_remove, &t.post_tip, &[]);
        assert!(result.is_ok(), "test '{}' fail: {:?}", t.name, result.err());

        let (rt, _) = result.unwrap();
        assert_eq!(
            rt, t.expected_type,
            "test '{}': expected {:?}, got {:?}",
            t.name, t.expected_type, rt
        );

        let best = db.block_header_best().unwrap();
        assert_eq!(
            best.hash,
            t.post_tip.block_hash(),
            "test '{}': invalid canonical tip",
            t.name
        );

        for header in t.to_remove {
            let result = db.block_header_by_hash(header.block_hash());
            assert!(
                result.is_err(),
                "test '{}': removed header {} still in database",
                t.name,
                header.block_hash()
            );
        }
    }
}

#[test]
fn test_block_headers_remove_integration() {
    let db = new_test_db();

    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 2);
    let h3 = create_test_header(h2.block_hash(), 3);
    let h4 = create_test_header(h3.block_hash(), 4);
    let headers = [h1, h2, h3, h4];
    db.block_headers_insert(&headers, &[]).unwrap();

    let (remove_type, parent_header) = db.block_headers_remove(&[h3, h4], &h2, &[]).unwrap();

    assert_eq!(remove_type, RemoveType::ChainDescend);
    assert_eq!(parent_header.hash, h2.block_hash());

    let best = db.block_header_best().unwrap();
    assert_eq!(best.hash, h2.block_hash());

    for header in &[h3, h4] {
        assert!(db.block_header_by_hash(header.block_hash()).is_err());
    }

    // Test hooks
    let key = b"test_key";
    let value = b"test_value";
    let hooks = vec![(&MetadataCF, key.as_ref(), value.as_ref())];

    let h5 = create_test_header(h2.block_hash(), 3);
    db.block_headers_insert(&[h5], &[]).unwrap();
    db.block_headers_remove(&[h5], &h2, &hooks).unwrap();

    let retrieved = db.get(&MetadataCF, key).unwrap();
    assert_eq!(retrieved, value);
}

#[test]
fn test_headers_insert_race() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const NUM_THREADS: usize = 8;

    let db = new_test_db();
    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 2);

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::new();

    for _ in 0..NUM_THREADS {
        let db_clone = Arc::clone(&db);
        let bc = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            bc.wait();
            db_clone.block_headers_insert(&[h1, h2], &[])
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.join().unwrap());
    }

    let mut found = false;
    for res in results {
        match res {
            Ok(_) => {
                if found {
                    panic!("multiple threads succeeded")
                }
                found = true;
            }
            Err(TrustDBError::Duplicate(_)) => (),
            Err(e) => panic!("unexpected error {e}"),
        }
    }
    if !found {
        panic!("expected one success")
    }
}

#[test]
fn test_headers_remove_race() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const NUM_THREADS: usize = 8;

    let db = new_test_db();
    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 2);
    db.block_headers_insert(&[h1, h2], &[]).unwrap();

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::new();

    for _ in 0..NUM_THREADS {
        let db_clone = Arc::clone(&db);
        let bc = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            bc.wait();
            db_clone.block_headers_remove(&[h1, h2], &genesis, &[])
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.join().unwrap());
    }

    let mut found = false;
    for res in results {
        match res {
            Ok(_) => {
                if found {
                    panic!("multiple threads succeeded")
                }
                found = true;
            }
            Err(TrustDBError::NotFound(_)) => (),
            Err(e) => panic!("unexpected error {e}"),
        }
    }
    if !found {
        panic!("expected one success")
    }
}

#[test]
fn test_update_headers_race() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let db = new_test_db();
    let genesis = create_test_header(BlockHash::all_zeros(), 0);
    db.block_header_genesis_insert(&genesis, 0, U256::from(1_u32))
        .unwrap();

    let h1 = create_test_header(genesis.block_hash(), 1);
    let h2 = create_test_header(h1.block_hash(), 2);
    db.block_headers_insert(&[h1, h2], &[]).unwrap();

    let h3 = create_test_header(h2.block_hash(), 3);

    // Test inserting and removing at the same time, for the chain:
    // g -> h1 -> h2
    // try and insert h3 and remove h2 concurrently

    let barrier = Arc::new(Barrier::new(2));

    // Removal
    let db_remove = Arc::clone(&db);
    let bc_remove = Arc::clone(&barrier);

    let remove = thread::spawn(move || {
        bc_remove.wait();
        db_remove.block_headers_remove(&[h2], &h1, &[])
    });

    // Insertion
    let db_insert = Arc::clone(&db);
    let bc_insert = Arc::clone(&barrier);

    let insert = thread::spawn(move || {
        bc_insert.wait();
        db_insert.block_headers_insert(&[h3], &[])
    });

    let remove_res = remove.join().unwrap();
    let insert_res = insert.join().unwrap();

    if remove_res.is_ok() {
        match insert_res {
            Ok(_) => panic!("expected failed insertion"),
            Err(TrustDBError::NotFound(_)) => (),
            Err(e) => panic!("unexpected insertion error: {e}"),
        }
    } else if insert_res.is_ok() {
        match remove_res {
            Ok(_) => panic!("expected failed removal"),
            Err(TrustDBError::DanglingChild(_)) => (),
            Err(e) => panic!("unexpected removal error: {e}"),
        }
    } else {
        panic!("insertion and deletion both failed")
    }
}

#[test]
fn test_clone_trust_db() {
    let db = new_test_db();
    let cloned_db = Arc::clone(&db);

    assert_eq!(std::ptr::addr_of!(db.db), std::ptr::addr_of!(cloned_db.db));
    assert!(std::ptr::eq(&db.db, &cloned_db.db));

    assert_eq!(
        std::ptr::addr_of!(db.update_mtx),
        std::ptr::addr_of!(cloned_db.update_mtx)
    );
    assert!(std::ptr::eq(&db.update_mtx, &cloned_db.update_mtx));
}

use self::InsertType::*;
use self::TrustDBTable::*;
use bitcoin::block::Header;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use hex::encode;
use primitive_types::U256;
use rocksdb::{ColumnFamilyDescriptor, ColumnFamilyRef, OptimisticTransactionDB, Options};
use std::cmp::Ordering;
use std::path::Path;
use std::slice::Iter;
use std::sync::Arc;
use std::sync::Mutex;
use thiserror::Error;

const BHS_CANONICAL_TIP_KEY: &str = "canonicaltip";
const BHS_GENESIS_KEY: &str = "genesis";

#[derive(Error, Debug)]
pub enum TrustDBError {
    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Duplicate key found: {0}")]
    Duplicate(String),
    #[error("Not a genesis block, prev block hash: {0}")]
    NotAGenesisBlockHeader(String),
    #[error("Genesis already exists with block hash: {0}")]
    GenesisExists(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TrustDBError>;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct BlockHeader {
    pub hash: bitcoin::BlockHash,
    pub height: u64,
    pub header: Header,
    pub difficulty: U256,
}

impl BlockHeader {
    // height + header + difficulty; hash is db key
    const SIZE: usize = 8 + 80 + 32;
}

type EncodedHeader = [u8; BlockHeader::SIZE];

impl From<&EncodedHeader> for BlockHeader {
    fn from(enc: &EncodedHeader) -> Self {
        let header =
            Header::consensus_decode(&mut &enc[8..88]).expect("encoded header should be decodable");
        let height = u64::from_be_bytes(enc[..8].try_into().unwrap());
        let difficulty = U256::from_big_endian(&enc[88..]);
        Self {
            hash: header.block_hash(),
            height,
            header,
            difficulty,
        }
    }
}

impl From<&BlockHeader> for EncodedHeader {
    fn from(value: &BlockHeader) -> EncodedHeader {
        let mut enc = [0u8; BlockHeader::SIZE];

        // encode height
        let hb = value.height.to_be_bytes();
        enc[..8].copy_from_slice(&hb);

        // encode block header
        let mut hdrb: [u8; 80] = [0u8; 80];
        value
            .header
            .consensus_encode(&mut &mut hdrb[..])
            .expect("[u8] encoding should never fail");
        enc[8..88].copy_from_slice(&hdrb);

        // encode diff
        let diffb = value.difficulty.to_big_endian();
        enc[88..].copy_from_slice(&diffb);

        enc
    }
}

#[derive(Debug, PartialEq)]
pub enum InsertType {
    ChainExtend, // Normal insert, does not require further action.
    ChainFork,   // Chain forked, unwind and rewind indexes.
    ForkExtend,  // Extended a fork, does not require further action.
}

impl InsertType {
    pub fn as_str(&self) -> &str {
        match self {
            ChainExtend => "chain extended",
            ChainFork => "chain forked",
            ForkExtend => "fork extended",
        }
    }
}

pub enum TrustDBTable {
    HeadersCF,
    MetadataCF,
    HeightHashCF,
}

impl TrustDBTable {
    pub fn as_str(&self) -> &str {
        match self {
            HeadersCF => "blockheaders",
            MetadataCF => "metadata",
            HeightHashCF => "heighthash",
        }
    }

    pub fn iterator() -> Iter<'static, TrustDBTable> {
        static TABLES: [TrustDBTable; 3] = [HeadersCF, MetadataCF, HeightHashCF];
        TABLES.iter()
    }
}

pub type BatchHook<'a> = (&'a TrustDBTable, &'a [u8], &'a [u8]);

pub struct TrustDB {
    db: Arc<OptimisticTransactionDB>,
    genesis_block_mtx: Mutex<bitcoin::BlockHash>,
}

impl TrustDB {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_it = TrustDBTable::iterator();
        let mut cfs: Vec<ColumnFamilyDescriptor> = Vec::new();
        for b in cf_it {
            let mut cf_opts = opts.clone();

            // configure prefix interator matching to height
            if matches!(b, TrustDBTable::HeightHashCF) {
                cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
            }

            cfs.push(ColumnFamilyDescriptor::new(b.as_str(), cf_opts));
        }
        let db = OptimisticTransactionDB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self {
            db: Arc::new(db),
            genesis_block_mtx: Mutex::new(bitcoin::BlockHash::all_zeros()),
        })
    }

    fn get_cf(&self, cf: &TrustDBTable) -> ColumnFamilyRef<'_> {
        self.db
            .cf_handle(cf.as_str())
            .unwrap_or_else(|| panic!("CF '{}' must exist after successful open", cf.as_str()))
    }

    pub fn put<K, V>(&self, cf: &TrustDBTable, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.db.put_cf(self.get_cf(cf), key, value)?;
        Ok(())
    }

    pub fn get<K: AsRef<[u8]>>(&self, cf: &TrustDBTable, key: K) -> Result<Vec<u8>> {
        let key_ref = key.as_ref();
        let res = self.db.get_cf(self.get_cf(cf), key_ref)?;
        if let Some(val) = res {
            return Ok(val);
        }
        Err(TrustDBError::NotFound(encode(key_ref)))
    }

    pub fn del<K: AsRef<[u8]>>(&self, cf: &TrustDBTable, key: K) -> Result<()> {
        self.db.delete_cf(self.get_cf(cf), key.as_ref())?;
        Ok(())
    }

    pub fn has<K: AsRef<[u8]>>(&self, cf: &TrustDBTable, key: K) -> bool {
        self.db.key_may_exist_cf(self.get_cf(cf), key.as_ref())
    }

    const HH_KEY_SIZE: usize = 8 + 32;

    fn height_hash_to_key(height: u64, hash: bitcoin::BlockHash) -> [u8; TrustDB::HH_KEY_SIZE] {
        let mut enc = [0u8; TrustDB::HH_KEY_SIZE];

        // encode height
        let hb = height.to_be_bytes();
        enc[..8].copy_from_slice(&hb);

        // encode diff
        let diffb = hash.to_byte_array();
        enc[8..].copy_from_slice(&diffb);

        enc
    }

    fn key_to_height_hash(enc: &[u8; TrustDB::HH_KEY_SIZE]) -> (u64, bitcoin::BlockHash) {
        let height = u64::from_be_bytes(enc[..8].try_into().unwrap());
        let hash = bitcoin::BlockHash::from_byte_array(enc[8..].try_into().unwrap());
        (height, hash)
    }

    pub fn block_header_genesis_insert(
        &self,
        header: &Header,
        height: u64,
        diff: U256,
    ) -> Result<()> {
        // ensure that the header being inserted is indeed a genesis block;
        // ensure that it has no parent
        if header.prev_blockhash != bitcoin::BlockHash::all_zeros() {
            return Err(TrustDBError::NotAGenesisBlockHeader(
                header.prev_blockhash.to_string(),
            ));
        }

        // since we read, check validity, then write we have to protect against
        // a race condition here.  these are our steps that are not thread-safe:
        // 1. check if a genesis block exists
        // 2. if not, write a new genesis block to the db
        //
        // if two threads were to perform these steps at the same time we may
        // get: 1 1 2 2.  if this is the case then we would insert two genesis
        // blocks
        let mut locked_genesis_block_hash = self.genesis_block_mtx.lock().unwrap();

        let bhash = header.block_hash();
        if self.has(&HeadersCF, bhash) {
            return Err(TrustDBError::Duplicate(bhash.to_string()));
        }

        // ensure that a different genesis block does not exist in the db
        // with a few strategies

        // 1. if we have the existing genesis block hash stored in the mutex,
        // then we know we have an existing genesis block inserted
        if *locked_genesis_block_hash != bitcoin::BlockHash::all_zeros() {
            return Err(TrustDBError::GenesisExists(
                locked_genesis_block_hash.to_string(),
            ));
        }

        // 2. this may be our first time entering this function, so the mutex
        // would not have a block hash stored within it, check the database
        let existing_genesis = self.get(&HeadersCF, BHS_GENESIS_KEY);
        match existing_genesis {
            Err(err) => match err {
                // if we could not find a genesis block, we're ok to continue
                // and insert one
                TrustDBError::NotFound(_) => {
                    // no-op
                }

                // any other error should cause a return
                err => return Err(err),
            },
            Ok(eg) => {
                // we found an existing genesis block, prepare it to be returned
                // in a descriptive error
                let existing_genesis_block_header_encoded: EncodedHeader = eg
                    .try_into()
                    .expect("genesis block header unexpected size/format");

                let existing_genesis_block_header =
                    BlockHeader::from(&existing_genesis_block_header_encoded);

                // since we found an existing genesis, store its hash in the
                // mutex for future calls if needed
                *locked_genesis_block_hash = existing_genesis_block_header.hash;

                return Err(TrustDBError::GenesisExists(
                    existing_genesis_block_header.hash.to_string(),
                ));
            }
        }

        let mut cdiff = U256::from_big_endian(&header.work().to_be_bytes());
        if !diff.is_zero() {
            cdiff = diff;
        }

        let bh_batch = self.db.transaction();

        let hh_key = TrustDB::height_hash_to_key(height, bhash);
        bh_batch.put_cf(self.get_cf(&HeightHashCF), hh_key, [])?;

        let ebh = &BlockHeader {
            hash: header.block_hash(),
            header: *header,
            difficulty: cdiff,
            height,
        };

        let ebh: EncodedHeader = ebh.into();
        bh_batch.put_cf(self.get_cf(&HeadersCF), bhash, ebh)?;
        bh_batch.put_cf(self.get_cf(&HeadersCF), BHS_CANONICAL_TIP_KEY, ebh)?;
        bh_batch.put_cf(self.get_cf(&HeadersCF), BHS_GENESIS_KEY, ebh)?;

        bh_batch.commit()?;

        // if we have successfully inserted a genesis block, store it in the
        // mutex
        *locked_genesis_block_hash = header.block_hash();

        Ok(())
    }

    pub fn block_header_best(&self) -> Result<BlockHeader> {
        let bhb = self.get(&HeadersCF, BHS_CANONICAL_TIP_KEY)?;
        let bhb: [u8; BlockHeader::SIZE] = bhb
            .try_into()
            .expect("canonical tip data should be valid size");
        Ok(BlockHeader::from(&bhb))
    }

    pub fn block_header_by_hash(&self, hash: bitcoin::BlockHash) -> Result<BlockHeader> {
        let bhb = self.get(&HeadersCF, hash)?;
        let bhb: [u8; BlockHeader::SIZE] =
            bhb.try_into().expect("header data should be valid size");
        Ok(BlockHeader::from(&bhb))
    }

    pub fn block_headers_by_height(&self, height: u64) -> Result<Vec<BlockHeader>> {
        let h = height.to_be_bytes();
        let it = self.db.prefix_iterator_cf(self.get_cf(&HeightHashCF), h);
        let mut bhs: Vec<BlockHeader> = Vec::new();
        for item in it {
            let (hh, _) = item?;
            let enc: [u8; Self::HH_KEY_SIZE] = hh
                .as_ref()
                .try_into()
                .expect("heighthash key should be valid size");
            let (_, hash) = TrustDB::key_to_height_hash(&enc);
            bhs.push(self.block_header_by_hash(hash)?);
        }
        if bhs.is_empty() {
            return Err(TrustDBError::NotFound(height.to_string()));
        }
        Ok(bhs)
    }

    /// block_headers_insert decodes and inserts the passed blockheaders into the
    /// database. Additionally it updates the height/hash and missing blocks table as
    /// well. On return it informs the caller about potential forking situations
    /// and always returns the canonical and last inserted blockheader, which may be
    /// the same. This call uses the database to prevent reentrancy.
    /// The passed header chain MUST be contiguous.
    pub fn block_headers_insert(
        &self,
        headers: &[Header],
        hooks: &[BatchHook],
    ) -> Result<(InsertType, BlockHeader, BlockHeader, usize)> {
        if headers.is_empty() {
            return Err(TrustDBError::Other(
                "block headers insert: invalid".to_string(),
            ));
        }
        let batch = self.db.transaction();

        // Ensure we can connect these blockheaders. This also obtains the
        // starting cumulative difficulty and height.
        // Iterate over the block headers and skip block headers we already
        // have in the database.
        let mut x: usize = 0;
        for rbh in headers {
            let hash = rbh.block_hash();
            let missing_hash = batch
                .get_pinned_cf(self.get_cf(&HeadersCF), hash)?
                .is_none();
            if missing_hash {
                break;
            }
            x += 1;
        }

        let headers = &headers[x..];
        if headers.is_empty() {
            return Err(TrustDBError::Other(
                "block headers insert: duplicate".to_string(),
            ));
        }

        // Ensure contiguity of new headers.
        let mut prev_bhh = headers[0].prev_blockhash;
        for (i, rbh) in headers.iter().enumerate() {
            let hash = rbh.block_hash();
            if rbh.prev_blockhash != prev_bhh {
                return Err(TrustDBError::Other(format!(
                    "header with hash {} at index {} does not connect to \
					previous header with hash {} at index {}",
                    hash,
                    x + i,
                    prev_bhh,
                    x + i - 1
                )));
            }
            prev_bhh = hash
        }

        let mut wbh = &headers[0];
        let pbh = self.block_header_by_hash(wbh.prev_blockhash)?;

        let bbh: EncodedHeader = batch
            .get_cf(self.get_cf(&HeadersCF), BHS_CANONICAL_TIP_KEY)?
            .ok_or(TrustDBError::NotFound("best block header".to_string()))?
            .try_into()
            .expect("canonical tip data should be valid size");

        let best_bh = BlockHeader::from(&bbh);
        let fork = wbh.prev_blockhash != best_bh.hash;

        let mut cdiff = pbh.difficulty;
        let mut height = pbh.height;
        let mut lbh = best_bh;
        let mut ebh = bbh;

        for bh in headers {
            // The first element is skipped, as it is pre-decoded.
            wbh = bh;
            let bhash = wbh.block_hash();

            // pre set values because we start with previous value
            height += 1;
            cdiff = cdiff
                .checked_add(U256::from_big_endian(&wbh.work().to_be_bytes()))
                .ok_or(TrustDBError::Other(
                    "work accumulation overflow".to_string(),
                ))?;

            // Store height_hash for future reference
            let hh_key = TrustDB::height_hash_to_key(height, bhash);
            let missing_hh = batch
                .get_pinned_cf(self.get_cf(&HeightHashCF), hh_key)?
                .is_none();
            if missing_hh {
                batch.put_cf(self.get_cf(&HeightHashCF), hh_key, [])?;
            }

            lbh = BlockHeader {
                hash: bhash,
                difficulty: cdiff,
                header: *bh,
                height,
            };

            ebh = (&lbh).into();
            batch.put_cf(self.get_cf(&HeadersCF), bhash, ebh)?;
        }

        let mut cbh = &lbh;

        let it: InsertType;
        if fork {
            // Insert last height into block headers if the new cumulative
            // difficulty exceeds the prior difficulty.
            match cdiff.cmp(&best_bh.difficulty) {
                Ordering::Less | Ordering::Equal => {
                    // Extend fork, fork did not overcome difficulty
                    it = ForkExtend;
                    cbh = &best_bh;
                }
                Ordering::Greater => {
                    // pick the right return value based on ancestor
                    it = ChainFork;
                    batch.put_cf(self.get_cf(&HeadersCF), BHS_CANONICAL_TIP_KEY, ebh)?;
                }
            }
        } else {
            // Extend current best tip
            it = ChainExtend;
            batch.put_cf(self.get_cf(&HeadersCF), BHS_CANONICAL_TIP_KEY, ebh)?;
        }

        for hook in hooks {
            batch.put_cf(self.get_cf(hook.0), hook.1, hook.2)?;
        }

        batch.commit()?;
        Ok((it, *cbh, lbh, headers.len()))
    }

    // TODOs
    // Caching
    // Other Tables (missing blocks)
    // Debug logging
}

impl Clone for TrustDB {
    fn clone(&self) -> Self {
        TrustDB {
            db: Arc::clone(&self.db),
            genesis_block_mtx: Mutex::new(bitcoin::BlockHash::all_zeros()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    fn new_test_db() -> TrustDB {
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
            difficulty: U256::from(12345),
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
        let expected_diff = bh.difficulty.to_big_endian();
        assert_eq!(&enc[88..], &expected_diff);
    }

    #[test]
    fn test_decode_block_header() {
        let test_table = vec![
            (0, U256::zero()),
            (u64::MAX, U256::MAX),
            (99999, U256::from(12345)),
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
        let diff = U256::from(12345);

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
        let diff = U256::zero(); // should use header's work

        let res = db.block_header_genesis_insert(&header, height, diff);
        assert!(res.is_ok());

        let stored = db.get(&HeadersCF, header.block_hash());
        assert!(stored.is_ok());

        // check if stored header has the correct difficulty
        let stored = stored.unwrap();
        let stored_array: [u8; BlockHeader::SIZE] = stored.try_into().unwrap();
        let dec = BlockHeader::from(&stored_array);
        let work = U256::from_big_endian(&header.work().to_be_bytes());
        assert_ne!(work, diff);
        assert_eq!(dec.difficulty, work);
    }

    #[test]
    fn test_block_header_best() {
        let db = new_test_db();
        let header = create_test_header(BlockHash::all_zeros(), 1);
        let height = 99999;
        let diff = U256::from(12345);

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
        let diff = U256::from(12345);

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
        let diff = U256::from(12345);

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
        let diff = U256::from(12345);

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
        db.block_header_genesis_insert(&correct_genesis, 0, U256::from(1))
            .unwrap();

        let incorrect_genesis = create_test_header(BlockHash::all_zeros(), 2);
        let res = db.block_header_genesis_insert(&incorrect_genesis, 0, U256::from(2));

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
    fn test_block_headers_insert_multiple_different_genesis_blocks_skip_mtx() {
        let db = new_test_db();

        let correct_genesis = create_test_header(BlockHash::all_zeros(), 0);
        db.block_header_genesis_insert(&correct_genesis, 0, U256::from(1))
            .unwrap();

        {
            // unset mutex to ensure that we hit db, do this in its own scope
            // to unset the mutex before we call block_header_genesis_insert
            // again
            let mut locked = db.genesis_block_mtx.lock().unwrap();
            if *locked == bitcoin::BlockHash::all_zeros() {
                panic!("mtx value should have been set");
            }
            *locked = bitcoin::BlockHash::all_zeros();
        }

        let incorrect_genesis = create_test_header(BlockHash::all_zeros(), 2);
        let res = db.block_header_genesis_insert(&incorrect_genesis, 0, U256::from(2));

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
    fn test_block_headers_insert_genesis_that_is_not_a_genesis_block() {
        let db = new_test_db();

        let mut genesis = create_test_header(BlockHash::all_zeros(), 0);
        genesis.prev_blockhash = bitcoin::BlockHash::hash(&[1, 2, 3]);
        let res = db.block_header_genesis_insert(&genesis, 0, U256::from(1));
        match res {
            Err(TrustDBError::NotAGenesisBlockHeader(hash)) => {
                assert_eq!(hash, genesis.prev_blockhash.to_string());
            }
            Err(e) => {
                panic!("unexpected error: {}", e)
            }
            _ => panic!("expected an error"),
        }
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
        db.block_header_genesis_insert(&genesis, 0, U256::from(1))
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
        db.block_header_genesis_insert(&genesis, 0, U256::from(1))
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
        db.block_header_genesis_insert(&genesis, 0, U256::from(1))
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
        db.block_header_genesis_insert(&genesis, 0, U256::from(1))
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
        db.block_header_genesis_insert(&genesis, 0, U256::from(1))
            .unwrap();

        let h1 = create_test_header(genesis.block_hash(), 1);
        let fake_hash = bitcoin::hashes::Hash::hash(&[42u8; 32]);
        let h2 = create_test_header(fake_hash, 2);
        let headers = [h1, h2];
        let res = db.block_headers_insert(&headers, &[]);
        assert!(res.is_err(), "expected error")
    }
}

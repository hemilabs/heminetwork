use self::TrustDBTable::*;
use bitcoin::block::Header;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use hex::encode;
use primitive_types::U256;
use rocksdb::{ColumnFamilyDescriptor, ColumnFamilyRef, OptimisticTransactionDB, Options};
use std::path::Path;
use std::slice::Iter;
use std::sync::Arc;
use thiserror::Error;

const BHS_CANONICAL_TIP_KEY: &str = "canonicaltip";

#[derive(Error, Debug)]
pub enum TrustDBError {
    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Duplicate key found: {0}")]
    Duplicate(String),
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

pub struct TrustDB {
    db: Arc<OptimisticTransactionDB>,
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
        Ok(Self { db: Arc::new(db) })
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
        let bhash = header.block_hash();
        if self.has(&HeadersCF, bhash) {
            return Err(TrustDBError::Duplicate(bhash.to_string()));
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

        bh_batch.commit()?;
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
}

impl Clone for TrustDB {
    fn clone(&self) -> Self {
        TrustDB {
            db: Arc::clone(&self.db),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    fn new_test_db() -> TrustDB {
        let tmp = tempdir().expect("temp dir should have been created");
        TrustDB::open(tmp.path()).expect("database should open")
    }

    fn create_test_header(nonce: u32) -> Header {
        Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 12345,
            bits: bitcoin::CompactTarget::from_consensus(0xd3adb33f),
            nonce,
        }
    }

    #[test]
    fn test_open_db() {
        new_test_db();
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
        let header = create_test_header(1);
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

        let header = create_test_header(1);
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
            (0, bitcoin::BlockHash::all_zeros()),
            (u64::MAX, bitcoin::BlockHash::all_zeros()),
            (12345, create_test_header(1).block_hash()),
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
            (0, bitcoin::BlockHash::all_zeros()),
            (u64::MAX, bitcoin::BlockHash::all_zeros()),
            (99999, create_test_header(1).block_hash()),
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
        let header = create_test_header(1);
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
        let header = create_test_header(1);
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
        let header = create_test_header(1);
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
        let header = create_test_header(1);
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
        let fake_hash = bitcoin::BlockHash::hash(&[40u8; 32]);
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
        let header = create_test_header(1);
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

        let header1 = create_test_header(1);
        let header2 = create_test_header(2);
        let diff = U256::from(12345);

        let mut insert = db.block_header_genesis_insert(&header1, height1, diff);
        assert!(insert.is_ok());

        insert = db.block_header_genesis_insert(&header2, height2, diff);
        assert!(insert.is_ok());

        let mut headers = db.block_headers_by_height(height1);
        let mut res = headers.unwrap();
        assert_eq!(res.first().unwrap().hash, header1.block_hash());

        headers = db.block_headers_by_height(height2);
        res = headers.unwrap();
        assert_eq!(res.first().unwrap().hash, header2.block_hash());
    }
}

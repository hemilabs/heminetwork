use self::InsertType::*;
use self::TrustDBTable::*;
use bitcoin::block::Header;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;

use ethnum::U256;
use hex::encode;
use rocksdb::{ColumnFamilyDescriptor, ColumnFamilyRef, OptimisticTransactionDB, Options};
use std::cmp::Ordering;
use std::path::Path;
use std::slice::Iter;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[cfg(test)]
mod trust_db_test;

const BHS_CANONICAL_TIP_KEY: &str = "canonicaltip";
const BHS_GENESIS_KEY: &str = "genesis";
pub static DB_METADATA_KEY_UPSTREAM_STATE_ID: &str = "upstream_state_id";

#[derive(Error, Debug)]
pub enum TrustDBError {
    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Duplicate key found: {0}")]
    Duplicate(String),
    #[error("Genesis already exists with block hash: {0}")]
    GenesisExists(String),
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    #[error("Invalid tip: {0}")]
    InvalidTip(String),
    #[error("Dangling header: {0}")]
    DanglingChild(String),
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
        let difficulty = U256::from_be_bytes(enc[88..].try_into().unwrap());
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
        let diffb = value.difficulty.to_be_bytes();
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

#[derive(Debug, PartialEq)]
pub enum RemoveType {
    ChainDescend, // Removal walked the canonical chain backwards, but existing chain is still canonical
    ChainFork, // Removal walked canonical chain backwards far enough that another chain is now canonical
    ForkDescend, // Removal walked a non-canonical chain backwards, no change to canonical chain remaining canonical
}

impl RemoveType {
    pub fn as_str(&self) -> &str {
        match self {
            RemoveType::ChainDescend => "canonical chain descend",
            RemoveType::ChainFork => "canonical descend changed canonical",
            RemoveType::ForkDescend => "fork chain descend",
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
    db: OptimisticTransactionDB,
    update_mtx: Mutex<()>,
}

impl TrustDB {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Arc<Self>> {
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
        Ok(Arc::new(Self {
            db,
            update_mtx: Mutex::new(()),
        }))
    }

    fn get_cf(&self, cf: &TrustDBTable) -> ColumnFamilyRef<'_> {
        self.db
            .cf_handle(cf.as_str())
            .unwrap_or_else(|| panic!("CF '{}' must exist after successful open", cf.as_str()))
    }

    fn put<K, V>(&self, cf: &TrustDBTable, key: K, value: V) -> Result<()>
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

    // we use this function only in tests at the time of writing this,
    // so rust thinks it's "unused".  allow it to be "unused" (even though
    // it is used) for now
    #[allow(unused)]
    fn del<K: AsRef<[u8]>>(&self, cf: &TrustDBTable, key: K) -> Result<()> {
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

    pub fn set_upstream_state_id(&self, upstream_state_id: &[u8; 32]) {
        let _lock = self.update_mtx.lock().unwrap();

        self.put(
            &MetadataCF,
            DB_METADATA_KEY_UPSTREAM_STATE_ID,
            upstream_state_id,
        )
        .expect("could not insert into metadata table: {e}")
    }

    pub fn block_header_genesis_insert(
        &self,
        header: &Header,
        height: u64,
        diff: U256,
    ) -> Result<()> {
        // since we read, check validity, then write we have to protect against
        // a race condition here.  these are our steps that are not thread-safe:
        // 1. check if a genesis block exists
        // 2. if not, write a new genesis block to the db
        //
        // if two threads were to perform these steps at the same time we may
        // get: 1 1 2 2.  if this is the case then we would insert two genesis
        // blocks
        let _lock = self.update_mtx.lock().unwrap();

        let bhash = header.block_hash();
        if self.has(&HeadersCF, bhash) {
            return Err(TrustDBError::Duplicate(bhash.to_string()));
        }

        // this may be our first time entering this function, so the mutex
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

                return Err(TrustDBError::GenesisExists(
                    existing_genesis_block_header.hash.to_string(),
                ));
            }
        }

        let mut cdiff = U256::from_be_bytes(header.work().to_be_bytes());
        if diff != U256::ZERO {
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
            let res = self.block_header_by_hash(hash);
            match res {
                Err(TrustDBError::NotFound(_)) => {
                    panic!("height hash key with hash {hash} not in headers table");
                }
                Err(e) => return Err(e),
                Ok(v) => bhs.push(v),
            }
        }
        if bhs.is_empty() {
            return Err(TrustDBError::NotFound(height.to_string()));
        }
        Ok(bhs)
    }

    /// `block_header_by_hash_tx` emulates the behavior of `block_header_by_hash`
    /// within a transaction's snapshot view of the database.
    fn block_header_by_hash_tx(
        &self,
        tx: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
        hash: bitcoin::BlockHash,
    ) -> Result<BlockHeader> {
        let full_header = tx.get_cf(self.get_cf(&HeadersCF), hash)?;
        let bhb = match full_header {
            Some(val) => val.try_into().expect("header data should be valid size"),
            None => return Err(TrustDBError::NotFound(hash.to_string())),
        };
        Ok(BlockHeader::from(&bhb))
    }

    /// `block_headers_by_height_tx` emulates the behavior of
    /// `block_headers_by_height` within a transaction's
    /// snapshot view of the database.
    fn block_headers_by_height_tx(
        &self,
        tx: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
        height: u64,
    ) -> Result<Vec<BlockHeader>> {
        let h = height.to_be_bytes();
        let it = tx.prefix_iterator_cf(self.get_cf(&HeightHashCF), h);
        let mut bhs: Vec<BlockHeader> = Vec::new();
        for item in it {
            let (hh, _) = item?;
            let enc: [u8; Self::HH_KEY_SIZE] = hh
                .as_ref()
                .try_into()
                .expect("heighthash key should be valid size");

            let (_, hash) = TrustDB::key_to_height_hash(&enc);
            let res = self.block_header_by_hash(hash);
            match res {
                Err(TrustDBError::NotFound(_)) => {
                    panic!("height hash key with hash {hash} not in headers table");
                }
                Err(e) => return Err(e),
                Ok(v) => bhs.push(v),
            }
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
            return Err(TrustDBError::InvalidParams(
                "block headers insert: empty header set".to_string(),
            ));
        }

        // Prevent other calls that change the inner state of the DB
        // from running concurrently.
        let _guard = self.update_mtx.lock().unwrap();

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
            return Err(TrustDBError::Duplicate("headers set".to_string()));
        }

        // Ensure contiguity of new headers.
        let mut prev_bhh = headers[0].prev_blockhash;
        for (i, rbh) in headers.iter().enumerate() {
            let hash = rbh.block_hash();
            if rbh.prev_blockhash != prev_bhh {
                return Err(TrustDBError::InvalidParams(format!(
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
        let pbh = self.block_header_by_hash_tx(&batch, wbh.prev_blockhash)?;

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
                .checked_add(U256::from_be_bytes(wbh.work().to_be_bytes()))
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

    /// BlockHeadersRemove decodes and removes the passed blockheaders into the
    /// database. Additionally it updates the canonical height/hash.
    /// On return it informs the caller about the removal type which is self-evident
    /// from the headers and post-removal canonical tip passed in as a convenience,
    /// as well as the header the batch of headers was removed from which is now
    /// the tip of that particular chain.
    ///
    /// The caller of this function must pass in the tipAfterRemoval which they
    /// *know* to be the correct canonical tip after removal of the passed-in blocks.
    /// This is critical to ensure that an operator of a TBC instance in External
    /// Header mode can set a specific header as canonical in the event that removal
    /// of header(s) results in a split tip where two or more headers are all at
    /// the highest cumulative difficulty and TBC would otherwise have to choose one
    /// without knowing what the upstream consumer considered canonical.
    ///
    /// This function is only intended to be used on a database which is used by
    /// an instance of TBC running in External Header mode, where the header consensus
    /// view needs to be walked back to account for information no longer being
    /// known by an upstream consumer. For example, an L2 reorg could remove Bitcoin
    /// consensus information from the L2 protocol's knowledge, so the External Header
    /// mode TBC instance needs to represent Bitcoin consensus knowledge of the L2
    /// protocol at the older tip height so that the full indexed TBC instance can
    /// be moved to the correct indexed state to return queries that are consistent
    /// with the L2's view of Bitcoin at that previous L2 block, otherwise L2 nodes
    /// that processed the reorg versus L2 nodes that were always on the reorged-onto
    /// chain could have a state divergence since queries against TBC would not be
    /// deterministic between both types of nodes.
    ///
    /// All of the headers passed to the remove function must exist in the database.
    ///
    /// Headers must be ordered from lowest height to highest and must be contiguous,
    /// meaning if header 0 is at height H, header N-1 must be at height H+N and for
    /// each header N its previous block hash must be the hash of header N-1.
    ///
    /// The last header in the array must be the current tip of its chain (whether
    /// canonical or fork); in other words the database must not have knowledge of
    /// any headers who reference the last header as their previous block as this removal
    /// would result in a dangling orphan chain segment in the database. A block can have
    /// multiple children and calling this function with non-contiguous (non-linear)
    /// blocks is not allowed, but this is correct behavior as removing chunks of
    /// headers in the reverse order they were originally added will ensure that
    /// a header being removed only has a maximum of one child (which must be included
    /// in the headers passed to this function).
    ///
    /// For example given a chain:
    ///
    /// _______/-[2a]-[3a]-[4a]
    ///
    /// [ G]-[ 1]-[2b]-[3b]-[4b]-[5b]
    ///
    /// ____________\-[3c]-[4c]-[5c]-[6c]
    ///
    /// Where the tip is [6c], the next removal could for example be:
    ///
    /// [3a]-[4a]
    /// [3b]-[4b]-[5b]
    /// [5c]-[6c] (and pass in tipAfterRemoval=[5b])
    ///
    /// But the next removal could not for example be:
    ///
    /// [2a]-[3a] // Leaves [4a] dangling
    /// [2b]-[3b]-[4b]-[5b] // Leaves "c" fork dangling
    ///
    /// The upstream user of a TBC instance in External Header mode is expected
    /// to always remove chunks of headers in the opposite order they were
    /// originally added. While this is not checked explicitly, failure to do so
    /// can result in these types of dangling chain scenarios. In the above example,
    /// block [2b] must have been added at or before the time of adding [3b] and [3c].
    ///
    /// It could have either been:
    /// Update #1: ADD [2b]-[3b]-[4b]-[5b]
    /// Update #2: ADD [3c]-[4c]-[5c]-[6c]
    /// OR
    /// Update #1: ADD [2b]-[3c]-[4c]-[5c]-[6c]
    /// Update #2: ADD [3b]-[4b]-[5b]
    /// (Or some similar order where some of the higher b/c blocks were added back
    /// and forth between the chains or split into multiple smaller updates.)
    ///
    /// Assuming the upstream caller needs to remove the entire b and c chains:
    ///
    /// If it was the first order, then we would expect upstream caller to first
    /// remove [3c]-...-[6c] (undo update #2), and then remove [2b]-...-[5b] (undo
    /// update #1), which would never leave a chain dangling.
    ///
    /// Similarly, if it was the second order, then we would expect upstream caller
    /// to first remove [3b]-...-[5b] (undo update #2), and then remove [2b]-...-[6c]
    /// (undo update #1) which would also never leave a chain dangling.
    ///
    /// If the upstream caller removed [2b]-...-[5b] first, then they did not
    /// remove headers in the same order that they added them, because it would
    /// have been impossible to originally add [2b] after adding [3c].
    ///
    /// Calling this function with the incorrect tipAfterRemoval WILL FAIL as that
    /// indicates incorrect upstream behavior.
    ///
    /// If any of the above requirements are not true, this function will return
    /// an error. If this function returns an error, no changes have been made to
    /// the underlying database state as all validity checks are done before db
    /// modifications are applied.
    ///
    /// If an upstreamCursor is provided, it is updated atomically in the database
    /// along with the state transition of removing the block headers.
    pub fn block_headers_remove(
        &self,
        headers: &[Header],
        tip_after_removal: &Header,
        hooks: &[BatchHook],
    ) -> Result<(RemoveType, BlockHeader)> {
        if headers.is_empty() {
            return Err(TrustDBError::InvalidParams(
                "block headers remove: empty header set".to_string(),
            ));
        }

        // Ensure contiguity of headers.
        let mut prev_bhh = headers[0].prev_blockhash;
        for (i, rbh) in headers.iter().enumerate() {
            let hash = rbh.block_hash();
            if rbh.prev_blockhash != prev_bhh {
                return Err(TrustDBError::InvalidParams(format!(
                    "block headers remove: header with hash {} at index {} does \
                    not connect to previous header with hash {} at index {}",
                    hash,
                    i,
                    prev_bhh,
                    i - 1
                )));
            }
            prev_bhh = hash
        }

        // Prevent other calls that change the inner state of the DB
        // from running concurrently.
        let _guard = self.update_mtx.lock().unwrap();

        let batch = self.db.transaction();

        // Get current canonical tip for later use
        let origin_tip = batch.get_cf(self.get_cf(&HeadersCF), BHS_CANONICAL_TIP_KEY)?;
        let bhb = match origin_tip {
            Some(val) => val
                .try_into()
                .expect("canonical tip data should be valid size"),
            None => return Err(TrustDBError::NotFound("canonical tip".to_string())),
        };
        let origin_tip = BlockHeader::from(&bhb);

        let headers_parsed = headers;

        // Looking up each full header (with height and cumulative difficulty)
        // in the next check; store so that later we have the data to create deletion
        // keys.
        let mut full_headers: Vec<BlockHeader> = vec![];
        // Check that each header exists in the database, and that no header
        // to remove has a child unless that child is also going to be removed;
        // no dangling chains will be left. Also check that none of the blocks
        // to be removed match the tip the caller wants to be canonical after
        // the removal.
        let tip_after_removal_hash = tip_after_removal.block_hash();
        for (i, header_to_check) in headers_parsed.iter().enumerate() {
            let hash = header_to_check.block_hash();

            // Ensure that the header which should be canonical after removal is not one
            // of the blocks to remove
            if tip_after_removal_hash == hash {
                return Err(TrustDBError::InvalidParams(format!(
                    "block headers remove: cannot remove \
                    header with hash {hash} when that is \
                    supposed to be the tip after removal"
                )));
            }

            // Get full header that has height in it for the block to remove we are checking
            let full_header = self.block_header_by_hash_tx(&batch, hash)?;

            // Save the full header from database (with height and cumulative difficulty)
            full_headers.push(full_header);
            let next_height = full_header.height + 1;

            // Get all headers from the database that could possibly be children
            let res = self.block_headers_by_height_tx(&batch, next_height);
            let potential_children = match res {
                Err(TrustDBError::NotFound(_)) => continue,
                Err(e) => return Err(e),
                Ok(v) => v,
            };

            // Check all potential children. If one has our header to remove's hash as their
            // previous block, then make sure it is in the removal list. Two or more cannot
            // be in our removal list because they would have failed contiguous check prior.
            for to_check in potential_children {
                if to_check.header.prev_blockhash != hash {
                    // Not a child of header to remove
                    continue;
                }

                // This is a child of the header we are going to remove, make sure it is
                // also going to be removed.
                if i == (headers_parsed.len() - 1) {
                    // We do not have another header in our removal list, meaning it would
                    // be left dangling.
                    return Err(TrustDBError::DanglingChild(format!(
                        "want to remove header with hash {} but it is the last \
                        header in our removal list, and database has a child \
                        header with hash {}",
                        hash, to_check.hash
                    )));
                }

                // This check will always fail if there are two children which claim the
                // current header as a child, as one of them will not match the next
                // header to remove, which is the only block which could be the removed
                // child.
                let next = headers_parsed[i + 1].block_hash();
                if next != to_check.hash {
                    // The header of the confirmed child does not match the next header to
                    // remove, meaning it would be left dangling.
                    return Err(TrustDBError::DanglingChild(format!(
                        "want to remove header with hash {}, but database has a \
                        child header with hash {}",
                        hash, to_check.hash
                    )));
                }
            }
        }

        // Ensure that the tip which the caller claims should be canonical after the
        // removal is a valid block in the database.
        let tip_after_removal_from_db = self
            .block_header_by_hash_tx(&batch, tip_after_removal_hash)
            .map_err(|e| {
                TrustDBError::NotFound(format!(
                    "block headers remove: cannot find tip after removal header \
                    with hash {} in database: {}",
                    tip_after_removal_hash, e
                ))
            })?;

        for (i, rbh) in full_headers.iter().enumerate() {
            // Check that the raw header we retrieved from the database matches the
            // header we expected to move as an additional sanity check.
            let expected_hash = headers_parsed[i].block_hash();
            if expected_hash != rbh.header.block_hash() {
                panic!(
                    "block headers remove: unexpected internal error, header with hash \
                    {} at position {} in headers to remove does not match header with \
                    hash {} retrieved from db",
                    expected_hash,
                    i,
                    rbh.header.block_hash()
                );
            }
        }

        // Insert each block header deletion into the batch (for header itself and
        // height-header association)
        for (i, rbh) in headers_parsed.iter().enumerate() {
            // Delete header i
            let bhash = rbh.block_hash();
            let fh = full_headers[i];
            batch.delete_cf(self.get_cf(&HeadersCF), bhash)?;

            // Delete height mapping for header i
            let hh_key = TrustDB::height_hash_to_key(fh.height, bhash);
            batch.delete_cf(self.get_cf(&HeightHashCF), hh_key)?;
        }

        // Check if proposed tip after removal has children.
        let next_height = tip_after_removal_from_db.height + 1;
        let res = self.block_headers_by_height_tx(&batch, next_height);
        match res {
            Err(TrustDBError::NotFound(_)) => (),
            Err(e) => return Err(e),
            Ok(potential_children) => {
                for to_check in potential_children {
                    if to_check.header.prev_blockhash == tip_after_removal_hash {
                        // Expected tip has children, so cannot be the actual tip.
                        return Err(TrustDBError::InvalidTip(
                            "block headers remove: passed in \
                            tip after removal has children"
                                .to_string(),
                        ));
                    }
                }
            }
        };

        // Insert updated canonical tip after removal of the provided block headers
        let tip = BlockHeader {
            hash: tip_after_removal_from_db.hash,
            difficulty: tip_after_removal_from_db.difficulty,
            header: *tip_after_removal,
            height: tip_after_removal_from_db.height,
        };
        let tip_enc: EncodedHeader = (&tip).into();
        batch.put_cf(self.get_cf(&HeadersCF), BHS_CANONICAL_TIP_KEY, tip_enc)?;

        // Get parent block from database
        let ggp = headers_parsed[0].prev_blockhash;
        let res = self.block_header_by_hash_tx(&batch, ggp);
        let parent_to_removal_set = res.map_err(|e| {
            TrustDBError::NotFound(format!(
                "block headers remove: cannot find previous header \
                (with hash {}) to lowest header removed (with hash {}) \
                in database: {}",
                ggp,
                headers_parsed[0].block_hash(),
                e
            ))
        })?;

        let origin_tip_hash = origin_tip.hash;
        let heaviest_removed_hash = headers_parsed[headers_parsed.len() - 1].block_hash();

        let removal_type: RemoveType;
        if tip_after_removal_hash == parent_to_removal_set.hash {
            // Canonical tip set by caller is the parent to the blocks removed
            removal_type = RemoveType::ChainDescend;
        } else if tip_after_removal_hash == origin_tip_hash {
            // Canonical tip did not change, meaning blocks we removed were on a non-canonical chain
            removal_type = RemoveType::ForkDescend;
        } else if origin_tip_hash == heaviest_removed_hash {
            // The original canonical tip was a block we removed, but parent to removal set is
            // not the new canonical per first condition, therefore we descended the canonical
            // chain far enough that a previous fork is now canonical
            removal_type = RemoveType::ChainFork;
        } else {
            // This should never happen, one of the above three conditions must be true.
            // Do this before the end of function so we don't apply database changes.
            return Err(TrustDBError::Other(
                "none of the chain geometry checks applies to this removal".to_string(),
            ));
        }

        // Call post hooks if set.
        for hook in hooks {
            batch.put_cf(self.get_cf(hook.0), hook.1, hook.2)?;
        }

        batch.commit()?;
        Ok((removal_type, parent_to_removal_set))
    }

    // TODOs
    // Caching
    // Other Tables (missing blocks)
    // Debug logging
}

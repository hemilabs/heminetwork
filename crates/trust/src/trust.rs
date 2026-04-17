use crate::trust_db::{BlockHeader, InsertType, RemoveType};
use crate::trust_db::{
    DB_METADATA_KEY_UPSTREAM_STATE_ID, TrustDB, TrustDBError, TrustDBTable::MetadataCF,
};
use bitcoin::Network;
use bitcoin::block::Header;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustError {
    #[error("TrustDB error: {0}")]
    TrustDB(#[from] TrustDBError),
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
}

pub type Result<T> = std::result::Result<T, TrustError>;

pub struct TrustConfig {
    db_home: String,
    network: String,
}

impl TrustConfig {
    pub fn new_default_config(path: &str) -> Self {
        TrustConfig {
            db_home: path.to_string(),
            network: String::from("testnet"),
        }
    }

    pub fn db_home(&self) -> &str {
        &self.db_home
    }
}

// XXX remove when fields are used
#[allow(dead_code)]
pub struct Trust {
    db: Arc<TrustDB>,
    cfg: TrustConfig,
    network: Network,
}

impl Trust {
    pub fn new(cfg: TrustConfig) -> Result<Self> {
        let network = match cfg.network.as_str() {
            "regtest" => Network::Regtest,
            "testnet3" | "testnet" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "mainnet" => Network::Bitcoin,
            _ => return Err(TrustError::InvalidNetwork(cfg.network.clone())),
        };

        let path = Path::new(cfg.db_home.as_str()).join(network.to_string());
        let db = TrustDB::open(path)?;

        Ok(Self { db, cfg, network })
    }

    pub fn set_upstream_state_id(&self, upstream_state_id: &[u8; 32]) {
        self.db.set_upstream_state_id(upstream_state_id);
    }

    pub fn get_upstream_state_id(&self) -> Result<[u8; 32]> {
        let upstream_state_id_binding =
            &self.db.get(&MetadataCF, DB_METADATA_KEY_UPSTREAM_STATE_ID);

        let upstream_state_id = match upstream_state_id_binding {
            Ok(u) => u.as_array::<32>(),
            Err(e) => return Err(TrustError::NotFound(e.to_string())),
        };

        match upstream_state_id {
            Some(u) => Ok(*u),
            None => panic!("could not return upstream_state_id as a 32 byte array"),
        }
    }

    /// Sets up external header mode by inserting genesis. The value of genesis
    /// to insert can be overwritten using the tuple (Header, Height, Difficulty).
    /// Pass None for default chain genesis block.
    pub fn external_header_setup(
        &self,
        genesis_override: Option<(&Header, u64, ethnum::U256)>,
        upstream_state_id: &[u8; 32],
    ) -> Result<()> {
        let mut genesis = &bitcoin::blockdata::constants::genesis_block(self.network).header;
        let mut height = u64::MIN;
        let mut diff = ethnum::U256::ZERO;
        if let Some(o) = genesis_override {
            (genesis, height, diff) = o
        }

        match self.db.block_header_best() {
            Err(e) => match e {
                TrustDBError::NotFound(_) => {
                    self.set_upstream_state_id(upstream_state_id);
                    self.db.block_header_genesis_insert(genesis, height, diff)?;
                    self.db.block_header_best()?;
                }
                _ => return Err(TrustError::TrustDB(e)),
            },
            Ok(_) => {
                let gb = self.db.block_headers_by_height(height)?;
                if gb.len() > 1 {
                    return Err(TrustError::InvalidState(format!(
                        "have {} effective genesis blocks",
                        gb.len()
                    )));
                }
                if genesis.block_hash() != gb[0].hash {
                    return Err(TrustError::InvalidState(format!(
                        "effective genesis block hash mismatch, 
                        db has {} but genesis should be {}",
                        gb[0].hash,
                        genesis.block_hash()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn add_external_headers(
        &self,
        headers: &[Header],
        upstream_state_id: &[u8; 32],
    ) -> Result<(InsertType, BlockHeader, BlockHeader, usize)> {
        if headers.is_empty() {
            return Err(TrustError::InvalidParams(
                "add_external_headers: called with no headers".to_string(),
            ));
        }

        if upstream_state_id == &[0u8; 32] {
            return Err(TrustError::InvalidParams(
                "add_external_headers: upstream state is invalid".to_string(),
            ));
        }

        let hooks = [(
            &MetadataCF,
            DB_METADATA_KEY_UPSTREAM_STATE_ID.as_bytes(),
            &upstream_state_id[..],
        )];
        self.db
            .block_headers_insert(headers, &hooks)
            .map_err(TrustError::TrustDB)
    }

    pub fn remove_external_headers(
        &self,
        headers: &[Header],
        tip_after_removal: &Header,
        upstream_state_id: &[u8; 32],
    ) -> Result<(RemoveType, BlockHeader)> {
        if headers.is_empty() {
            return Err(TrustError::InvalidParams(
                "remove_external_headers: called with no headers".to_string(),
            ));
        }

        if upstream_state_id == &[0u8; 32] {
            return Err(TrustError::InvalidParams(
                "remove_external_headers: upstream state is invalid".to_string(),
            ));
        }

        let hooks = [(
            &MetadataCF,
            DB_METADATA_KEY_UPSTREAM_STATE_ID.as_bytes(),
            &upstream_state_id[..],
        )];
        self.db
            .block_headers_remove(headers, tip_after_removal, &hooks)
            .map_err(TrustError::TrustDB)
    }

    pub fn block_header_by_hash(&self, hash: bitcoin::BlockHash) -> Result<(Header, u64)> {
        let res = self.db.block_header_by_hash(hash)?;
        Ok((res.header, res.height))
    }

    pub fn block_header_best(&self) -> Result<(Header, u64)> {
        let res = self.db.block_header_best()?;
        Ok((res.header, res.height))
    }

    pub fn block_headers_by_height(&self, height: u64) -> Result<Vec<Header>> {
        let res = self.db.block_headers_by_height(height)?;
        let val: Vec<Header> = res.into_iter().map(|i| i.header).collect();
        Ok(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    #[test]
    fn test_trust() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let s = Trust::new(cfg);
        assert!(s.is_ok());
    }

    #[test]
    fn test_invalid_network() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let mut cfg = TrustConfig::new_default_config(tmp.unwrap());
        cfg.network = "fake".to_string();
        let e = Trust::new(cfg);
        match e.err().expect("invalid network should return error") {
            TrustError::InvalidNetwork(_) => (),
            other_err => panic!("unexpected error {other_err}"),
        }
    }

    #[test]
    fn test_set_upstream_state_id() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        trust.set_upstream_state_id(b"this_is_a_test_for_this_test_yes");

        match trust.db.get(&MetadataCF, DB_METADATA_KEY_UPSTREAM_STATE_ID) {
            Err(e) => panic!("could not get upstream state id from metadata table: {e}"),
            Ok(state_id) => {
                assert_eq!(state_id, b"this_is_a_test_for_this_test_yes");
            }
        }
    }

    #[test]
    fn test_set_upstream_state_id_more_than_once() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        trust.set_upstream_state_id(b"this_is_a_test_for_this_test_yes");
        trust.set_upstream_state_id(b"this_is_a_test_for_this_test____");

        match trust.db.get(&MetadataCF, DB_METADATA_KEY_UPSTREAM_STATE_ID) {
            Err(e) => panic!("could not get upstream state id from metadata table: {e}"),
            Ok(state_id) => {
                assert_eq!(state_id, b"this_is_a_test_for_this_test____");
            }
        }
    }

    #[test]
    fn test_get_upstream_state_id() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        trust.set_upstream_state_id(b"this_is_a_test_for_this_test_yes");

        match trust.get_upstream_state_id() {
            Ok(u) => assert_eq!(u, *b"this_is_a_test_for_this_test_yes"),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn test_get_upstream_state_id_gets_the_latest() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        trust.set_upstream_state_id(b"this_is_a_test_for_this_test_yes");

        trust.set_upstream_state_id(b"this_is_a_test_for_this_test____");

        match trust.get_upstream_state_id() {
            Ok(u) => assert_eq!(u, *b"this_is_a_test_for_this_test____"),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn test_get_upstream_state_id_not_found() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        match trust
            .get_upstream_state_id()
            .expect_err("there should be no upstream state id")
        {
            TrustError::NotFound(_) => (),
            other_err => panic!("unexpected error {other_err}"),
        }
    }

    #[test]
    fn test_external_header_setup() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        let usi = b"this_is_a_test_for_this_test_yes";

        let res = trust.external_header_setup(None, usi);
        assert!(res.is_ok());

        match trust.get_upstream_state_id() {
            Ok(v) => assert_eq!(v, *usi),
            Err(e) => panic!("{e}"),
        }

        let (bhb, height) = trust.block_header_best().expect("best header should exist");
        assert_eq!(
            bhb.block_hash().as_byte_array(),
            trust.network.chain_hash().as_bytes()
        );
        assert_eq!(height, 0);
    }

    #[test]
    fn test_external_header_setup_override() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        let usi = b"this_is_a_test_for_this_test_yes";

        let header =
            &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Testnet).header;
        let height = 12345;
        let diff = ethnum::U256::from(99999_u32);

        let genesis_override = Some((header, height, diff));

        let res = trust.external_header_setup(genesis_override, usi);
        assert!(res.is_ok());

        match trust.get_upstream_state_id() {
            Ok(v) => assert_eq!(v, *usi),
            Err(e) => panic!("{e}"),
        }

        let hh = trust.block_headers_by_height(height).unwrap();
        assert_eq!(hh.len(), 1);
        assert_eq!(hh[0].block_hash(), header.block_hash());
    }

    #[test]
    fn test_external_header_setup_duplicate() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        let usi = b"this_is_a_test_for_this_test_yes";

        for _ in 0..5 {
            trust
                .external_header_setup(None, usi)
                .expect("should be able to setup with multiple identical calls");
        }
    }

    #[test]
    fn test_external_header_setup_genesis_hash_mismatch() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str();
        assert!(tmp.is_some());

        let cfg = TrustConfig::new_default_config(tmp.unwrap());
        let trust = Trust::new(cfg).unwrap();

        let usi = b"this_is_a_test_for_this_test_yes";

        let res = trust.external_header_setup(None, usi);
        assert!(res.is_ok());

        let genesis =
            &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header;
        let genesis_override = Some((genesis, 0, ethnum::U256::ZERO));

        match trust.external_header_setup(genesis_override, usi) {
            Err(e) => match e {
                TrustError::InvalidState(_) => (),
                _ => panic!("unexpected error: {e}"),
            },
            Ok(_) => panic!("setup should fail with mismatched hashes"),
        }
    }

    fn create_test_header(parent_hash: bitcoin::BlockHash, n: u32) -> Header {
        Header {
            version: bitcoin::blockdata::block::Version::ONE,
            prev_blockhash: parent_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 12345,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: n,
        }
    }

    fn setup_trust() -> (Trust, Header) {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str().expect("path should be string");
        let cfg = TrustConfig::new_default_config(tmp);
        let trust = Trust::new(cfg).unwrap();

        let usi = b"this_is_a_test_for_this_test_yes";
        let genesis = create_test_header(bitcoin::BlockHash::all_zeros(), 0);
        let genesis_override = Some((&genesis, 0u64, ethnum::U256::from(1_u32)));

        trust
            .external_header_setup(genesis_override, usi)
            .expect("external_header_setup should succeed");

        (trust, genesis)
    }

    #[test]
    fn test_add_external_headers() {
        let (trust, genesis) = setup_trust();

        let h1 = create_test_header(genesis.block_hash(), 1);
        let h2 = create_test_header(h1.block_hash(), 2);
        let h3 = create_test_header(h2.block_hash(), 3);

        let usi = b"add_external_headers_state_id_ok";
        let headers = [h1, h2, h3];
        let (it, canon, last, count) = trust.add_external_headers(&headers, usi).unwrap();

        assert_eq!(it, InsertType::ChainExtend);
        assert_eq!(count, 3);
        assert_eq!(last.hash, h3.block_hash());
        assert_eq!(last.height, 3);
        assert_eq!(canon.hash, h3.block_hash());

        let (bhb, height) = trust.block_header_best().expect("best header should exist");

        assert_eq!(bhb.block_hash(), h3.block_hash());
        assert_eq!(height, 3);

        let res = trust
            .get_upstream_state_id()
            .expect("upstream state id should be set");

        assert_eq!(res, *usi);
    }

    #[test]
    fn test_add_external_headers_errors() {
        let (trust, genesis) = setup_trust();
        let usi = b"add_external_headers_state_id_ok";

        // empty headers
        let empty_res: TrustError = trust
            .add_external_headers(&[], usi)
            .expect_err("should fail with empty headers");

        match empty_res {
            TrustError::InvalidParams(_) => (),
            e => panic!("unexpected error: {e}"),
        }

        // invalid upstream state id
        let h1 = create_test_header(genesis.block_hash(), 1);
        let invalid_res = trust
            .add_external_headers(&[h1], &[0u8; 32])
            .expect_err("should fail with with invalid upstream state id");

        match invalid_res {
            TrustError::InvalidParams(_) => (),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_remove_external_headers() {
        let (trust, genesis) = setup_trust();

        let h1 = create_test_header(genesis.block_hash(), 1);
        let h2 = create_test_header(h1.block_hash(), 2);
        let h3 = create_test_header(h2.block_hash(), 3);

        let usi_add = b"remove_ext_headers_state_add_ok_";
        trust
            .add_external_headers(&[h1, h2, h3], usi_add)
            .expect("add_external_headers should succeed");

        let usi_remove = b"remove_ext_headers_state_rem_ok_";
        let (rt, tip) = trust
            .remove_external_headers(&[h2, h3], &h1, usi_remove)
            .expect("remove_external_headers should succeed");

        assert_eq!(rt, RemoveType::ChainDescend);
        assert_eq!(tip.hash, h1.block_hash());

        let (bhb, height) = trust.block_header_best().expect("best header should exist");

        assert_eq!(bhb.block_hash(), h1.block_hash());
        assert_eq!(height, 1);

        let res = trust
            .get_upstream_state_id()
            .expect("upstream state id should be set");

        assert_eq!(res, *usi_remove);
    }

    #[test]
    fn test_remove_external_headers_errors() {
        let (trust, genesis) = setup_trust();
        let usi = b"add_external_headers_state_id_ok";

        let h1 = create_test_header(genesis.block_hash(), 1);
        trust
            .add_external_headers(&[h1], usi)
            .expect("add_external_headers should succeed");

        // empty headers
        let empty_res: TrustError = trust
            .remove_external_headers(&[], &genesis, usi)
            .expect_err("should fail with empty headers");

        match empty_res {
            TrustError::InvalidParams(_) => (),
            e => panic!("unexpected error: {e}"),
        }

        // invalid upstream state id
        let h1 = create_test_header(genesis.block_hash(), 1);
        let invalid_res = trust
            .remove_external_headers(&[h1], &genesis, &[0u8; 32])
            .expect_err("should fail with with invalid upstream state id");

        match invalid_res {
            TrustError::InvalidParams(_) => (),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_block_header_best() {
        let tmp = tempdir().expect("temp dir should have been created");
        let tmp = tmp.path().to_str().expect("path should be string");
        let cfg = TrustConfig::new_default_config(tmp);
        let trust = Trust::new(cfg).unwrap();

        // test error
        let res = trust
            .block_header_best()
            .expect_err("should fail with no best header");

        match res {
            TrustError::TrustDB(_) => (),
            e => panic!("unexpected error: {e}"),
        }

        // insert genesis
        let usi = b"this_is_a_test_for_this_test_yes";
        let genesis = create_test_header(bitcoin::BlockHash::all_zeros(), 0);
        let genesis_override = Some((&genesis, 0u64, ethnum::U256::from(1_u32)));

        trust
            .external_header_setup(genesis_override, usi)
            .expect("external_header_setup should succeed");

        // test success
        let (bhb, height) = trust.block_header_best().expect("best header should exist");

        assert_eq!(bhb.block_hash(), genesis.block_hash());
        assert_eq!(height, 0);

        let h1 = create_test_header(genesis.block_hash(), 1);
        let h2 = create_test_header(h1.block_hash(), 2);
        let usi = b"test_block_header_best_state_id_";
        trust
            .add_external_headers(&[h1, h2], usi)
            .expect("add_external_headers should succeed");

        let (bhb, height) = trust.block_header_best().expect("best header should exist");

        assert_eq!(bhb.block_hash(), h2.block_hash());
        assert_eq!(height, 2);
    }

    #[test]
    fn test_block_header_by_hash() {
        let (trust, genesis) = setup_trust();

        // test error
        let fake_hash = bitcoin::hashes::Hash::hash(&[0xffu8; 32]);
        let res = trust
            .block_header_by_hash(fake_hash)
            .expect_err("should fail for unknown hash");

        match res {
            TrustError::TrustDB(_) => (),
            e => panic!("unexpected error: {e}"),
        }

        // test success
        let (header, height) = trust
            .block_header_by_hash(genesis.block_hash())
            .expect("block_header_by_hash should succeed");

        assert_eq!(header.block_hash(), genesis.block_hash());
        assert_eq!(height, 0);
    }

    #[test]
    fn test_block_headers_by_height() {
        let (trust, genesis) = setup_trust();

        // test error
        let err = trust
            .block_headers_by_height(9999)
            .expect_err("should fail for non-existent height");

        match err {
            TrustError::TrustDB(_) => (),
            e => panic!("unexpected error: {e}"),
        }

        // test success
        let h1a = create_test_header(genesis.block_hash(), 1);
        let h1b = create_test_header(genesis.block_hash(), 2);
        let usi = b"test_block_headers_by_height_usi";
        trust
            .add_external_headers(&[h1a], usi)
            .expect("add_external_headers should succeed: h1a");
        trust
            .add_external_headers(&[h1b], usi)
            .expect("add_external_headers should succeed: h1b");

        let res0 = trust
            .block_headers_by_height(0)
            .expect("block_headers_by_height should succeed: 0");

        assert_eq!(res0.len(), 1);
        assert_eq!(res0[0].block_hash(), genesis.block_hash());

        let res1 = trust
            .block_headers_by_height(1)
            .expect("block_headers_by_height should succeed: 1");

        assert_eq!(res1.len(), 2);

        if !res1.iter().any(|i| i.block_hash() == h1a.block_hash()) {
            panic!("block header h1a not found")
        }

        if !res1.iter().any(|i| i.block_hash() == h1b.block_hash()) {
            panic!("block header h1b not found")
        }
    }
}

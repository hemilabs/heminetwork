use crate::trust_db::{
    DB_METADATA_KEY_UPSTREAM_STATE_ID, TrustDB, TrustDBError, TrustDBTable::MetadataCF,
};
use bitcoin::Network;
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
        genesis_override: Option<(&bitcoin::block::Header, u64, primitive_types::U256)>,
        upstream_state_id: &[u8; 32],
    ) -> Result<()> {
        let mut genesis = &bitcoin::blockdata::constants::genesis_block(self.network).header;
        let mut height = u64::MIN;
        let mut diff = primitive_types::U256::zero();
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

        let best = trust
            .db
            .block_header_best()
            .expect("best header should exist");
        assert_eq!(
            best.hash.as_byte_array(),
            trust.network.chain_hash().as_bytes()
        );
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
        let diff = primitive_types::U256::from(99999);

        let genesis_override = Some((header, height, diff));

        let res = trust.external_header_setup(genesis_override, usi);
        assert!(res.is_ok());

        match trust.get_upstream_state_id() {
            Ok(v) => assert_eq!(v, *usi),
            Err(e) => panic!("{e}"),
        }

        let hh = trust.db.block_headers_by_height(height).unwrap();
        assert_eq!(hh.len(), 1);
        assert_eq!(hh[0].hash, header.block_hash());
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
        let genesis_override = Some((genesis, 0, primitive_types::U256::zero()));

        match trust.external_header_setup(genesis_override, usi) {
            Err(e) => match e {
                TrustError::InvalidState(_) => (),
                _ => panic!("unexpected error: {e}"),
            },
            Ok(_) => panic!("setup should fail with mismatched hashes"),
        }
    }
}

use crate::trust_db::{TrustDB, TrustDBError, TrustDBTable::MetadataCF};
use bitcoin::Network;
use std::path::Path;
use thiserror::Error;

static DB_METADATA_KEY_UPSTREAM_STATE_ID: &str = "upstream_state_id";

#[derive(Error, Debug)]
pub enum TrustError {
    #[error("TrustDB error: {0}")]
    TrustDB(#[from] TrustDBError),
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),
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
    db: TrustDB,
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
        self.db
            .put(
                &MetadataCF,
                DB_METADATA_KEY_UPSTREAM_STATE_ID,
                upstream_state_id,
            )
            .expect("could not insert into metadata table: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}

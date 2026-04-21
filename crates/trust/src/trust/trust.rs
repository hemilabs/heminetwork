use crate::trust_db::{BlockHeader, InsertType, RemoveType, TrustDB, TrustDBError};
use crate::trust_db::{DB_METADATA_KEY_UPSTREAM_STATE_ID, TrustDBTable::MetadataCF};
use bitcoin::Network;
use bitcoin::block::Header;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[cfg(test)]
mod trust_tests;

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

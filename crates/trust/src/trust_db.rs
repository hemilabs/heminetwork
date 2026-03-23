use self::TrustDBTable::*;
use hex::encode;
use rocksdb::{ColumnFamilyDescriptor, ColumnFamilyRef, DB, Options};
use std::path::Path;
use std::slice::Iter;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustDBError {
    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),
    #[error("Key not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, TrustDBError>;

pub enum TrustDBTable {
    HeadersCF,
    MetadataCF,
}

impl TrustDBTable {
    pub fn as_str(&self) -> &str {
        match self {
            HeadersCF => "blockheaders",
            MetadataCF => "metadata",
        }
    }

    pub fn iterator() -> Iter<'static, TrustDBTable> {
        static TABLES: [TrustDBTable; 2] = [HeadersCF, MetadataCF];
        TABLES.iter()
    }
}

pub struct TrustDB {
    db: Arc<DB>,
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
            cfs.push(ColumnFamilyDescriptor::new(b.as_str(), opts.clone()));
        }

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn get_cf(&self, cf: &TrustDBTable) -> ColumnFamilyRef<'_> {
        self.db.cf_handle(cf.as_str()).unwrap_or_else(|| panic!(
            "CF '{}' must exist after successful open",
            cf.as_str()
        ))
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
    use tempfile::tempdir;

    fn new_test_db() -> TrustDB {
        let tmp = tempdir().expect("temp dir should have been created");
        TrustDB::open(tmp.path()).expect("database should open")
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
}

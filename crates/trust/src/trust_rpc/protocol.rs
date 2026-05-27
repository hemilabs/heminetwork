use serde::{Deserialize, Serialize};
use std::fmt;

/// Trait for response types that may contain a protocol error.
pub trait ProtocolErrable: Sized {
    /// Consumes self and returns `Ok(self)` if no error, or `Err(error)` if present.
    fn into_result(self) -> Result<Self, ProtocolError>;
}

macro_rules! impl_into_result {
    ($($name:ty),+ $(,)?) => {
        $(
            impl ProtocolErrable for $name {
                fn into_result(self) -> Result<Self, ProtocolError> {
                    match self.error {
                        Some(e) => Err(e),
                        None => Ok(self),
                    }
                }
            }
        )+
    };
}

/// Header prefixes all WebSocket commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Header {
    pub command: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub header: Header,
    pub payload: serde_json::Value,
}

impl Message {
    pub fn parse_command(&self) -> super::Result<Command> {
        serde_json::from_value(serde_json::Value::String(self.header.command.clone()))
            .map_err(super::TrustRPCError::JSON)
    }

    pub fn marshal(&self) -> super::Result<String> {
        let res = serde_json::to_string(self)?;
        Ok(res)
    }

    pub fn unmarshal(data: &str) -> super::Result<Message> {
        let res = serde_json::from_str(data)?;
        Ok(res)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Command {
    #[serde(rename = "tbcapi-ping-request")]
    PingRequest,
    #[serde(rename = "tbcapi-ping-response")]
    PingResponse,

    // TBC Admin API commands
    #[serde(rename = "tbcadmin-sync-indexers-to-hash-request")]
    SyncIndexersToHashRequest,
    #[serde(rename = "tbcadmin-job-status-request")]
    JobStatusRequest,
    #[serde(rename = "tbcadmin-job-subscribe-request")]
    JobSubscribeRequest,
    #[serde(rename = "tbcadmin-job-cancel-request")]
    JobCancelRequest,
    #[serde(rename = "tbcadmin-job-cancel-response")]
    JobCancelResponse,
    #[serde(rename = "tbcadmin-job-list-request")]
    JobListRequest,
    #[serde(rename = "tbcadmin-job-list-response")]
    JobListResponse,
    #[serde(rename = "tbcadmin-job-update-notification")]
    JobUpdateNotification,

    // TBC API commands
    #[serde(rename = "tbcapi-block-header-best-raw-request")]
    BlockHeaderBestRequest,
    #[serde(rename = "tbcapi-block-header-best-raw-response")]
    BlockHeaderBestResponse,
    #[serde(rename = "tbcapi-block-headers-by-height-raw-request")]
    BlockHeadersByHeightRequest,
    #[serde(rename = "tbcapi-block-headers-by-height-raw-response")]
    BlockHeadersByHeightResponse,
    #[serde(rename = "tbcapi-block-download-async-raw-request")]
    BlockDownloadAsyncRequest,
    #[serde(rename = "tbcapi-block-download-async-raw-response")]
    BlockDownloadAsyncResponse,
    #[serde(rename = "tbcapi-balance-by-address-request")]
    BalanceByAddressRequest,
    #[serde(rename = "tbcapi-balance-by-address-response")]
    BalanceByAddressResponse,
    #[serde(rename = "tbcapi-utxos-by-address-request")]
    UtxosByAddressRequest,
    #[serde(rename = "tbcapi-utxos-by-address-response")]
    UtxosByAddressResponse,
    #[serde(rename = "tbcapi-tx-by-id-raw-request")]
    TxByIdRequest,
    #[serde(rename = "tbcapi-tx-by-id-raw-response")]
    TxByIdResponse,
    #[serde(rename = "tbcapi-l2-keystone-txs-by-abrev-hash-request")]
    KeystoneTxsByL2KeystoneAbrevHashRequest,
    #[serde(rename = "tbcapi-l2-keystone-txs-by-abrev-hash-response")]
    KeystoneTxsByL2KeystoneAbrevHashResponse,
    #[serde(rename = "tbcapi-block-by-hash-raw-request")]
    BlockByHashRequest,
    #[serde(rename = "tbcapi-block-by-hash-raw-response")]
    BlockByHashResponse,
    #[serde(rename = "tbcapi-block-insert-request")]
    BlockInsertRequest,
    #[serde(rename = "tbcapi-block-insert-response")]
    BlockInsertResponse,
    #[serde(rename = "tbcapi-block-in-tx-index-request")]
    BlockInTxIndexRequest,
    #[serde(rename = "tbcapi-block-in-tx-index-response")]
    BlockInTxIndexResponse,
    #[serde(rename = "tbcapi-full-block-available-request")]
    FullBlockAvailableRequest,
    #[serde(rename = "tbcapi-full-block-available-response")]
    FullBlockAvailableResponse,
    #[serde(rename = "tbcapi-block-hash-by-tx-id-request")]
    BlockHashByTxIDRequest,
    #[serde(rename = "tbcapi-block-hash-by-tx-id-response")]
    BlockHashByTxIDResponse,
    #[serde(rename = "tbcapi-block-header-by-hash-raw-request")]
    BlockHeaderByHashRequest,
    #[serde(rename = "tbcapi-block-header-by-hash-raw-response")]
    BlockHeaderByHashResponse,
    #[serde(rename = "tbcapi-script-hash-available-to-spend-request")]
    ScriptHashAvailableToSpendRequest,
    #[serde(rename = "tbcapi-script-hash-available-to-spend-response")]
    ScriptHashAvailableToSpendResponse,
    #[serde(rename = "tbcapi-sync-status-request")]
    SyncStatusRequest,
    #[serde(rename = "tbcapi-sync-status-response")]
    SyncStatusResponse,
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::String(s)) => f.write_str(&s),
            _ => Err(fmt::Error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Payload {
    PingRequest(PingRequest),
    PingResponse(PingResponse),
    SyncIndexersToHashRequest(SyncIndexersToHashRequest),
    JobStatusRequest(JobStatusRequest),
    JobSubscribeRequest(JobSubscribeRequest),
    JobCancelRequest(JobCancelRequest),
    JobCancelResponse(JobCancelResponse),
    JobListRequest(JobListRequest),
    JobListResponse(JobListResponse),
    JobUpdateNotification(JobUpdateNotification),
    BlockHeaderBestRequest(BlockHeaderBestRequest),
    BlockHeaderBestResponse(BlockHeaderBestResponse),
    BlockHeadersByHeightRequest(BlockHeadersByHeightRequest),
    BlockHeadersByHeightResponse(BlockHeadersByHeightResponse),
    BlockDownloadAsyncRequest(BlockDownloadAsyncRequest),
    BlockDownloadAsyncResponse(BlockDownloadAsyncResponse),
    BalanceByAddressRequest(BalanceByAddressRequest),
    BalanceByAddressResponse(BalanceByAddressResponse),
    UtxosByAddressRequest(UtxosByAddressRequest),
    UtxosByAddressResponse(UtxosByAddressResponse),
    TxByIdRequest(TxByIdRequest),
    TxByIdResponse(TxByIdResponse),
    KeystoneTxsByL2KeystoneAbrevHashRequest(KeystoneTxsByL2KeystoneAbrevHashRequest),
    KeystoneTxsByL2KeystoneAbrevHashResponse(KeystoneTxsByL2KeystoneAbrevHashResponse),
    BlockByHashRequest(BlockByHashRequest),
    BlockByHashResponse(BlockByHashResponse),
    BlockInsertRequest(BlockInsertRequest),
    BlockInsertResponse(BlockInsertResponse),
    BlockInTxIndexRequest(BlockInTxIndexRequest),
    BlockInTxIndexResponse(BlockInTxIndexResponse),
    FullBlockAvailableRequest(FullBlockAvailableRequest),
    FullBlockAvailableResponse(FullBlockAvailableResponse),
    BlockHashByTxIDRequest(BlockHashByTxIDRequest),
    BlockHashByTxIDResponse(BlockHashByTxIDResponse),
    BlockHeaderByHashRequest(BlockHeaderByHashRequest),
    BlockHeaderByHashResponse(BlockHeaderByHashResponse),
    ScriptHashAvailableToSpendRequest(ScriptHashAvailableToSpendRequest),
    ScriptHashAvailableToSpendResponse(ScriptHashAvailableToSpendResponse),
    SyncStatusRequest(SyncStatusRequest),
    SyncStatusResponse(SyncStatusResponse),
}

impl Payload {
    pub fn encode(&self, id: &str) -> super::Result<Message> {
        let command = self.command();
        let payload_value = serde_json::to_value(self)?;
        Ok(Message {
            header: Header {
                command: command.to_string(),
                id: id.to_string(),
            },
            payload: payload_value,
        })
    }
}

/// Generates `Message::decode` and `Payload::command` from a single variant list,
/// keeping the types in sync.
macro_rules! impl_protocol_sync {
    ($($variant:ident),+ $(,)?) => {
        impl Message {
            pub fn decode(&self) -> super::Result<Payload> {
                match self.parse_command()? {
                    $(
                        Command::$variant => {
                            let p: $variant = serde_json::from_value(self.payload.clone())?;
                            Ok(Payload::$variant(p))
                        }
                    )+
                }
            }
        }

        impl Payload {
            pub fn command(&self) -> Command {
                match self {
                    $(Payload::$variant(_) => Command::$variant,)+
                }
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_value(self) {
            Ok(serde_json::Value::String(s)) => f.write_str(&s),
            _ => Err(fmt::Error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PingRequest {
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PingResponse {
    #[serde(rename = "origintimestamp")]
    pub origin_timestamp: i64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobInfo {
    pub job_id: String,
    pub job_type: String,
    pub status: JobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobStatusRequest {
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobSubscribeRequest {
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobCancelRequest {
    pub job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobCancelResponse {
    pub job_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobListResponse {
    pub jobs: Vec<JobInfo>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobUpdateNotification {
    pub job: JobInfo,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncIndexersToHashRequest {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeaderBestRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeaderBestResponse {
    pub height: u64,
    #[serde(default)]
    pub block_header: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeadersByHeightRequest {
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeadersByHeightResponse {
    pub block_headers: Vec<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockDownloadAsyncRequest {
    pub hash: String,
    pub peers: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockDownloadAsyncResponse {
    #[serde(default)]
    pub block: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BalanceByAddressRequest {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BalanceByAddressResponse {
    pub balance: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UtxosByAddressRequest {
    pub filter_mempool: bool,
    pub address: String,
    pub start: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    pub tx_id: String,
    pub value: i64,
    pub out_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UtxosByAddressResponse {
    pub utxos: Vec<Utxo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxByIdRequest {
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxByIdResponse {
    #[serde(default)]
    pub tx: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeystoneTxsByL2KeystoneAbrevHashRequest {
    pub l2_keystone_abrev_hash: String,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeystoneTx {
    pub block_hash: String,
    pub tx_index: u32,
    pub block_height: u32,
    pub raw_tx: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeystoneTxsByL2KeystoneAbrevHashResponse {
    pub keystone_txs: Vec<KeystoneTx>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockByHashRequest {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockByHashResponse {
    #[serde(default)]
    pub block: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockInsertRequest {
    pub block: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockInsertResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockInTxIndexRequest {
    pub block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockInTxIndexResponse {
    pub indexed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FullBlockAvailableRequest {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FullBlockAvailableResponse {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHashByTxIDRequest {
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHashByTxIDResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeaderByHashRequest {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeaderByHashResponse {
    pub height: u64,
    #[serde(default)]
    pub block_header: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HashHeight {
    pub hash: String,
    pub height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScriptHashAvailableToSpendRequest {
    pub tx_id: String,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScriptHashAvailableToSpendResponse {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncStatusRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncStatusResponse {
    pub synced: bool,
    pub at_least_missing: i32,
    pub blockheader_index_height: HashHeight,
    pub keystone_index_height: HashHeight,
    pub tx_index_height: HashHeight,
    pub utxo_index_height: HashHeight,
    pub zk_index_height: HashHeight,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolError {
    pub timestamp: i64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,

    pub message: String,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.trace {
            Some(trace) => write!(f, "{} [{}:{}]", self.message, trace, self.timestamp),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn decode_tx(raw: &Vec<u8>) -> Result<bitcoin::Transaction, bitcoin::consensus::encode::Error> {
    bitcoin::consensus::Decodable::consensus_decode(&mut std::io::Cursor::new(raw))
}

pub fn decode_block(raw: &Vec<u8>) -> Result<bitcoin::Block, bitcoin::consensus::encode::Error> {
    bitcoin::consensus::Decodable::consensus_decode(&mut std::io::Cursor::new(raw))
}

pub fn decode_header(
    raw: &Vec<u8>,
) -> Result<bitcoin::block::Header, bitcoin::consensus::encode::Error> {
    bitcoin::consensus::Decodable::consensus_decode(&mut std::io::Cursor::new(raw))
}

pub fn decode_header_batch(
    raw: &[Vec<u8>],
) -> Result<Vec<bitcoin::block::Header>, bitcoin::consensus::encode::Error> {
    raw.iter()
        .map(|bytes| {
            bitcoin::consensus::Decodable::consensus_decode(&mut std::io::Cursor::new(bytes))
        })
        .collect()
}

impl_protocol_sync!(
    PingRequest,
    PingResponse,
    SyncIndexersToHashRequest,
    JobStatusRequest,
    JobSubscribeRequest,
    JobCancelRequest,
    JobCancelResponse,
    JobListRequest,
    JobListResponse,
    JobUpdateNotification,
    BlockHeaderBestRequest,
    BlockHeaderBestResponse,
    BlockHeadersByHeightRequest,
    BlockHeadersByHeightResponse,
    BlockDownloadAsyncRequest,
    BlockDownloadAsyncResponse,
    BalanceByAddressRequest,
    BalanceByAddressResponse,
    UtxosByAddressRequest,
    UtxosByAddressResponse,
    TxByIdRequest,
    TxByIdResponse,
    KeystoneTxsByL2KeystoneAbrevHashRequest,
    KeystoneTxsByL2KeystoneAbrevHashResponse,
    BlockByHashRequest,
    BlockByHashResponse,
    BlockInsertRequest,
    BlockInsertResponse,
    BlockInTxIndexRequest,
    BlockInTxIndexResponse,
    FullBlockAvailableRequest,
    FullBlockAvailableResponse,
    BlockHashByTxIDRequest,
    BlockHashByTxIDResponse,
    BlockHeaderByHashRequest,
    BlockHeaderByHashResponse,
    ScriptHashAvailableToSpendRequest,
    ScriptHashAvailableToSpendResponse,
    SyncStatusRequest,
    SyncStatusResponse,
);

impl_into_result!(
    JobCancelResponse,
    JobListResponse,
    JobUpdateNotification,
    BlockHeaderBestResponse,
    BlockHeadersByHeightResponse,
    BlockDownloadAsyncResponse,
    BalanceByAddressResponse,
    UtxosByAddressResponse,
    TxByIdResponse,
    KeystoneTxsByL2KeystoneAbrevHashResponse,
    BlockByHashResponse,
    BlockInsertResponse,
    BlockInTxIndexResponse,
    FullBlockAvailableResponse,
    BlockHashByTxIDResponse,
    BlockHeaderByHashResponse,
    ScriptHashAvailableToSpendResponse,
    SyncStatusResponse,
);

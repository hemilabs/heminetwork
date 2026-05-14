use serde::{Deserialize, Serialize};
use std::fmt;

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

    pub fn decode(&self) -> super::Result<Payload> {
        match self.parse_command()? {
            Command::PingRequest => {
                let p: PingRequest = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::PingRequest(p))
            }
            Command::PingResponse => {
                let p: PingResponse = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::PingResponse(p))
            }
            Command::SyncIndexersToHashRequest => {
                let p: SyncIndexersToHashRequest = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::SyncIndexersToHashRequest(p))
            }
            Command::JobStatusRequest => {
                let p: JobStatusRequest = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::JobStatusRequest(p))
            }
            Command::JobSubscribeRequest => {
                let p: JobSubscribeRequest = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::JobSubscribeRequest(p))
            }
            Command::JobCancelRequest => {
                let p: JobCancelRequest = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::JobCancelRequest(p))
            }
            Command::JobCancelResponse => {
                let p: JobCancelResponse = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::JobCancelResponse(p))
            }
            Command::JobListRequest => {
                let p: JobListRequest = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::JobListRequest(p))
            }
            Command::JobListResponse => {
                let p: JobListResponse = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::JobListResponse(p))
            }
            Command::JobUpdateNotification => {
                let p: JobUpdateNotification = serde_json::from_value(self.payload.clone())?;
                Ok(Payload::JobUpdateNotification(p))
            }
        }
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
}

impl Payload {
    /// Returns the command associated with this payload.
    pub fn command(&self) -> Command {
        match self {
            Payload::PingRequest(_) => Command::PingRequest,
            Payload::PingResponse(_) => Command::PingResponse,
            Payload::SyncIndexersToHashRequest(_) => Command::SyncIndexersToHashRequest,
            Payload::JobStatusRequest(_) => Command::JobStatusRequest,
            Payload::JobSubscribeRequest(_) => Command::JobSubscribeRequest,
            Payload::JobCancelRequest(_) => Command::JobCancelRequest,
            Payload::JobCancelResponse(_) => Command::JobCancelResponse,
            Payload::JobListRequest(_) => Command::JobListRequest,
            Payload::JobListResponse(_) => Command::JobListResponse,
            Payload::JobUpdateNotification(_) => Command::JobUpdateNotification,
        }
    }
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

pub fn encode(id: &str, payload: &Payload) -> super::Result<Message> {
    let command = payload.command();
    let payload_value = serde_json::to_value(payload)?;
    Ok(Message {
        header: Header {
            command: command.to_string(),
            id: id.to_string(),
        },
        payload: payload_value,
    })
}

pub fn marshal(msg: &Message) -> super::Result<String> {
    let res = serde_json::to_string(msg)?;
    Ok(res)
}

pub fn unmarshal(data: &str) -> super::Result<Message> {
    let res = serde_json::from_str(data)?;
    Ok(res)
}

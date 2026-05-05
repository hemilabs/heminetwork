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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let payload = Payload::PingRequest(PingRequest {
            timestamp: 1234567890,
        });
        let msg = encode("1", &payload).unwrap();
        let json_str = marshal(&msg).unwrap();

        let parsed = unmarshal(&json_str).unwrap();
        assert_eq!(parsed.header.command, "tbcapi-ping-request");
        assert_eq!(parsed.header.id, "1");

        let decoded = parsed.decode().unwrap();
        match decoded {
            Payload::PingRequest(p) => assert_eq!(p.timestamp, 1234567890),
            _ => panic!("expected PingRequest"),
        }

        let payload = Payload::PingResponse(PingResponse {
            origin_timestamp: 1000,
            timestamp: 2000,
        });
        let msg = encode("2", &payload).unwrap();
        let json_str = marshal(&msg).unwrap();

        let parsed = unmarshal(&json_str).unwrap();
        assert_eq!(parsed.header.command, "tbcapi-ping-response");

        let decoded = parsed.decode().unwrap();
        match decoded {
            Payload::PingResponse(p) => {
                assert_eq!(p.origin_timestamp, 1000);
                assert_eq!(p.timestamp, 2000);
            }
            _ => panic!("expected PingResponse"),
        }
    }

    #[test]
    fn test_payload_command() {
        let p = Payload::PingRequest(PingRequest { timestamp: 0 });
        assert_eq!(p.command(), Command::PingRequest);
    }

    #[test]
    fn test_protocol_error_display() {
        let err = ProtocolError {
            timestamp: 100,
            trace: Some("test".to_string()),
            message: "fail".to_string(),
        };
        assert_eq!(err.to_string(), "fail [test:100]");

        let err2 = ProtocolError {
            timestamp: 100,
            trace: None,
            message: "fail".to_string(),
        };
        assert_eq!(err2.to_string(), "fail");
    }

    #[test]
    fn test_header_id_empty() {
        let header = Header {
            command: "test".to_string(),
            id: String::new(),
        };
        let json_str = serde_json::to_string(&header).unwrap();
        assert!(!json_str.contains("\"id\""));
    }

    #[test]
    fn test_unmarshal_missing_id() {
        let json_str = r#"{"header":{"command":"tbcapi-ping-request"},"payload":{"timestamp":42}}"#;
        let msg = unmarshal(json_str).unwrap();
        assert_eq!(msg.header.id, "");

        let decoded = msg.decode().unwrap();
        match decoded {
            Payload::PingRequest(p) => assert_eq!(p.timestamp, 42),
            _ => panic!("expected PingRequest"),
        }
    }

    #[test]
    fn test_unknown_command() {
        let json_str = r#"{"header":{"command":"unknown-cmd"},"payload":{}}"#;
        let msg = unmarshal(json_str).unwrap();
        assert!(msg.parse_command().is_err());
    }
}

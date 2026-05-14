use super::protocol::*;

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

# SOC Platform — Ingestion API Specification

## Ingestion Endpoints

### 1. Single Telemetry Event Ingestion
- **HTTP Method:** `POST`
- **Path:** `/api/v1/telemetry/ingest`
- **Authentication:** Required (Bearer Token)
- **Rate Limit:** Enforced

#### Request Body Example
```json
{
  "source_type": "windows",
  "environment": "lab",
  "sensor_id": "agent-dc01",
  "raw_event": {
    "EventID": 4625,
    "TargetUserName": "jdoe",
    "ComputerName": "CORP-DC01",
    "IpAddress": "192.168.1.105"
  }
}
```

#### Successful Response (200 OK)
```json
{
  "status": "success",
  "event_id": "EVT-8F29A10B3C4D5E6F",
  "deduplicated": false,
  "alerts_triggered": 0
}
```

#### Error Response — Validation Error (400 Bad Request)
```json
{
  "detail": {
    "message": "Telemetry validation failed",
    "errors": [
      "Invalid IP address in field 'source_ip': '999.999.999.999'"
    ]
  }
}
```

---

### 2. Batch Telemetry Ingestion
- **HTTP Method:** `POST`
- **Path:** `/api/v1/telemetry/ingest/batch`
- **Authentication:** Required (Bearer Token)
- **Limits:** Maximum 500 events per request

#### Request Body Example
```json
{
  "source_type": "auto",
  "environment": "simulation",
  "events": [
    {
      "EventID": 4624,
      "TargetUserName": "alice",
      "ComputerName": "WORKSTATION-01"
    },
    {
      "program": "sshd",
      "message": "Failed password for root from 198.51.100.5 port 22",
      "hostname": "bastion-host"
    }
  ]
}
```

#### Successful Response (200 OK)
```json
{
  "status": "success",
  "batch_summary": {
    "total_submitted": 2,
    "success_count": 2,
    "duplicate_count": 0,
    "rejected_count": 0,
    "error_count": 0,
    "total_alerts_triggered": 0,
    "results": [
      {
        "index": 0,
        "event_id": "EVT-1122334455667788",
        "status": "ok",
        "alerts_triggered": 0,
        "errors": []
      },
      {
        "index": 1,
        "event_id": "EVT-9988776655443322",
        "status": "ok",
        "alerts_triggered": 0,
        "errors": []
      }
    ]
  }
}
```

---

### 3. Event Search Endpoint
- **HTTP Method:** `GET`
- **Path:** `/api/v1/telemetry/events`
- **Authentication:** Required (`telemetry.read` permission)
- **Parameters:** `hostname`, `source_ip`, `destination_ip`, `username`, `event_type`, `severity`, `source_type`, `process_name`, `time_from`, `time_to`, `search_query`, `limit`, `offset`

---

### 4. Event Details Endpoint
- **HTTP Method:** `GET`
- **Path:** `/api/v1/telemetry/events/{event_id}`
- **Authentication:** Required (`telemetry.read` permission)

---

### 5. Event Timeline Endpoint
- **HTTP Method:** `GET`
- **Path:** `/api/v1/telemetry/timeline/{entity_type}/{entity_value}`
- **Authentication:** Required (`telemetry.read` permission)
- **Example:** `/api/v1/telemetry/timeline/host/CORP-DC01`

---

### 6. Telemetry Health Endpoint
- **HTTP Method:** `GET`
- **Path:** `/api/v1/telemetry/health`
- **Authentication:** None (Public health monitoring)

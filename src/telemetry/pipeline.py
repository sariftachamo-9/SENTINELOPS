"""
SOC Lab — Telemetry Ingestion Pipeline (Phase 3)
==============================================
Orchestrates the canonical telemetry ingestion flow:

  Raw Event
      │
      ▼
  Validation Layer      (TelemetryValidator — rejects malformed events)
      │
      ▼
  Normalization Layer   (EnhancedTelemetryNormalizer — converts to NormalizedEvent)
      │
      ▼
  Deduplication Layer   (EventDeduplicator — computes hash, updates counts)
      │
      ▼
  Storage Layer         (StorageBackend / SQLiteEventStore — saves to telemetry_events)
      │
      ▼
  Detection Pipeline    (AlertRulesEngine — evaluates rules against normalized event)
      │
      ▼
  Alert Engine          (Database — persists generated alerts to alerts table)

Does NOT bypass the normalized event layer under any circumstances.
Supports single-event and batch ingestion.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from src.telemetry.validator import TelemetryValidator, ValidationResult
from src.telemetry.normalizer import EnhancedTelemetryNormalizer
from src.telemetry.deduplication import EventDeduplicator
from src.telemetry.storage import StorageBackend, SQLiteEventStore
from src.telemetry.schema import NormalizedEvent, PipelineResult
from src.telemetry.health import TelemetryHealthMonitor
from src.telemetry.integration_health import IntegrationHealthManager
from src.alert_rules import AlertRulesEngine
from src.correlation_engine import CorrelationEngine
from src.risk_engine import RiskEngine
from src.database import Database


class TelemetryPipeline:
    """
    Main Telemetry Pipeline orchestrator.
    """

    def __init__(
        self,
        validator: Optional[TelemetryValidator] = None,
        normalizer: Optional[EnhancedTelemetryNormalizer] = None,
        deduplicator: Optional[EventDeduplicator] = None,
        storage: Optional[StorageBackend] = None,
        alert_engine: Optional[AlertRulesEngine] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        db: Optional[Database] = None,
    ):
        self.validator = validator or TelemetryValidator()
        self.normalizer = normalizer or EnhancedTelemetryNormalizer()
        self.deduplicator = deduplicator or EventDeduplicator()
        self.storage = storage or SQLiteEventStore()
        self.db = db or Database()
        self.alert_engine = alert_engine or AlertRulesEngine(db=self.db)
        self.correlation_engine = correlation_engine or CorrelationEngine(db=self.db)
        self.risk_engine = risk_engine or RiskEngine()
        self.health = TelemetryHealthMonitor()
        self.integration_health = IntegrationHealthManager()

    def process_event(
        self,
        raw_event: Dict[str, Any],
        source_type: str = "auto",
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> PipelineResult:
        """
        Process a single raw event through the complete 6-stage pipeline.
        """
        import time
        t0 = time.time()
        self.health.record_received(1)

        # 1. Validation
        val_res: ValidationResult = self.validator.validate(
            raw_event=raw_event,
            source_type=source_type,
            environment=environment
        )

        if not val_res.ok:
            self.health.record_rejected(1, reason="; ".join(val_res.errors))
            st = raw_event.get("source_type", source_type)
            self.integration_health.record_event_processed(
                integration_id=st if st in ("windows", "linux", "syslog", "wazuh", "suricata", "zeek") else "generic",
                success=False,
                latency_ms=(time.time() - t0) * 1000,
                error_msg="Validation failed: " + "; ".join(val_res.errors),
                source_mode=raw_event.get("source_mode", "live")
            )
            return PipelineResult(
                stored=False,
                validation_errors=val_res.errors,
                status="rejected"
            )

        try:
            # 2. Normalization
            normalized: NormalizedEvent = self.normalizer.normalize(
                raw_event=val_res.sanitized or raw_event,
                source_type=source_type,
                environment=environment,
                sensor_id=sensor_id
            )

            # Preserve source_mode if provided in raw request
            if "source_mode" in raw_event and raw_event["source_mode"] in ("live", "simulation"):
                normalized.source_mode = raw_event["source_mode"]
                normalized.simulation = (raw_event["source_mode"] == "simulation")

            # 3. Deduplication
            normalized, is_duplicate = self.deduplicator.process(normalized)
            if is_duplicate:
                self.health.record_deduplicated(1)

            # 4. Storage
            stored_ok = self.storage.store_event(normalized)
            if not stored_ok:
                self.health.record_error(f"Failed to store event {normalized.event_id}")

            self.health.record_processed(1)
            latency_ms = (time.time() - t0) * 1000
            integ_id = normalized.source_type if normalized.source_type in ("windows", "linux", "syslog", "wazuh", "suricata", "zeek") else "generic"
            self.integration_health.record_event_processed(
                integration_id=integ_id,
                success=stored_ok,
                latency_ms=latency_ms,
                source_mode=normalized.source_mode
            )

            # 5. Detection & Correlation Pipeline
            event_dict = normalized.model_dump()
            single_alerts = self.alert_engine.evaluate_event(event_dict)
            correlated_alerts = self.correlation_engine.process_event(event_dict)
            all_alerts = single_alerts + correlated_alerts

            # 6. Risk Scoring & Alert Engine Persistence
            alerts_count = 0
            for alert in all_alerts:
                alert["source_mode"] = normalized.source_mode
                if normalized.simulation:
                    alert["environment"] = normalized.environment
                    if "tags" not in alert or not isinstance(alert["tags"], list):
                        alert["tags"] = []
                    if "simulation" not in alert["tags"]:
                        alert["tags"].append("simulation")

                # Calculate transparent risk score breakdown
                risk_res = self.risk_engine.calculate_risk(alert)
                alert["risk_score"] = risk_res["risk_score"]
                alert["risk_level"] = risk_res["risk_level"]
                alert["risk_breakdown"] = risk_res["breakdown"]
                if not alert.get("reason"):
                    alert["reason"] = risk_res["explanation"]

                # Save alert to core database (with deduplication)
                self.db.save_alert(alert, deduplicate=True)
                alerts_count += 1

            return PipelineResult(
                event_id=normalized.event_id,
                stored=stored_ok,
                deduplicated=is_duplicate,
                alerts_triggered=alerts_count,
                status="duplicate" if is_duplicate else "ok"
            )

        except Exception as e:
            err_msg = f"Pipeline execution exception: {str(e)}"
            self.health.record_error(err_msg)
            return PipelineResult(
                stored=False,
                pipeline_errors=[err_msg],
                status="error"
            )

    def process_batch(
        self,
        raw_events: List[Dict[str, Any]],
        source_type: str = "auto",
        environment: str = "lab",
        sensor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process a batch of raw events with partial failure handling.
        Returns summary statistics and per-event result details.
        """
        success_count = 0
        rejected_count = 0
        duplicate_count = 0
        error_count = 0
        total_alerts = 0
        results: List[Dict[str, Any]] = []

        for idx, raw in enumerate(raw_events):
            res = self.process_event(
                raw_event=raw,
                source_type=source_type,
                environment=environment,
                sensor_id=sensor_id
            )

            res_dict = {
                "index": idx,
                "event_id": res.event_id,
                "status": res.status,
                "alerts_triggered": res.alerts_triggered,
                "errors": res.validation_errors + res.pipeline_errors
            }
            results.append(res_dict)

            if res.status == "ok":
                success_count += 1
            elif res.status == "duplicate":
                duplicate_count += 1
                success_count += 1  # Duplicates are stored with updated counters
            elif res.status == "rejected":
                rejected_count += 1
            elif res.status == "error":
                error_count += 1

            total_alerts += res.alerts_triggered

        return {
            "total_submitted": len(raw_events),
            "success_count": success_count,
            "duplicate_count": duplicate_count,
            "rejected_count": rejected_count,
            "error_count": error_count,
            "total_alerts_triggered": total_alerts,
            "results": results
        }

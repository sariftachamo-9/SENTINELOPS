"""
SOC Lab — UDP/TCP Syslog Ingestion Listener (Phase 4)
=====================================================
Receives RFC 3164 and RFC 5424 syslog streams over UDP/TCP and forwards them to
the SOC Telemetry Ingestion Pipeline with source_type='syslog'.

Default Port: 5140 (lab user-mode execution; production uses port 514).
Bound to local host by default to prevent unauthorized public exposure.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from typing import Optional

from src.telemetry.pipeline import TelemetryPipeline


class SyslogServerProtocol(asyncio.DatagramProtocol):
    """Async UDP Datagram Protocol handling incoming syslog messages."""

    def __init__(self, pipeline: TelemetryPipeline, source_mode: str = "live"):
        self.pipeline = pipeline
        self.source_mode = source_mode

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        try:
            message_str = data.decode("utf-8", errors="replace").strip()
            if not message_str:
                return

            raw_event = {
                "message": message_str,
                "client_ip": addr[0],
                "client_port": addr[1],
                "timestamp": time.time(),
                "source_mode": self.source_mode,
                "source_type": "syslog",
            }
            self.pipeline.process_event(
                raw_event=raw_event,
                source_type="syslog",
                environment="lab"
            )
        except Exception as e:
            print(f"[SyslogServer] Error handling packet from {addr}: {e}")


class SyslogServerDaemon:
    """Manages the background Syslog UDP listener thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5140, pipeline: Optional[TelemetryPipeline] = None):
        self.host = host
        self.port = port
        self.pipeline = pipeline or TelemetryPipeline()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.running = False

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        listen = self._loop.create_datagram_endpoint(
            lambda: SyslogServerProtocol(self.pipeline),
            local_addr=(self.host, self.port)
        )
        try:
            transport, protocol = self._loop.run_until_complete(listen)
            print(f"[SyslogServer] UDP Syslog listener started on {self.host}:{self.port}")
            self._loop.run_forever()
        except Exception as e:
            print(f"[SyslogServer] Startup error on {self.host}:{self.port}: {e}")
        finally:
            self.running = False

    def stop(self):
        if self._loop and self.running:
            self._loop.call_sooner(self._loop.stop)
            self.running = False

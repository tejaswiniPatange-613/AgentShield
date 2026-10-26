
"""Structured, privacy-conscious audit logging for AgentShield."""

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "audit.log"

ALLOWED_EVENTS = {
    "REDACTION_TRIGGERED",
    "PROMPT_INJECTION_REVIEW",
    "TOOL_ACCESS_BLOCKED",
    "SECURITY_CHECK_COMPLETED",
    "SECURITY_CHECK_FAILED",
}

ALLOWED_OUTCOMES = {"INFO", "PASS", "BLOCKED", "REVIEW", "FAIL"}

# Only explicitly approved metadata fields may enter the audit log.
ALLOWED_METADATA_KEYS = {
    "component",
    "test_id",
    "rule_id",
    "finding_id",
    "count",
    "severity",
    "status",
}

SENSITIVE_KEY_FRAGMENTS = {
    "prompt",
    "response",
    "secret",
    "password",
    "token",
    "credential",
    "authorization",
    "cookie",
    "email",
    "payload",
    "content",
}

_WRITE_LOCK = Lock()


class AuditLogger:
    """Write structured JSON Lines events without logging raw user content."""

    def __init__(self, log_path: Path | str = DEFAULT_LOG_PATH) -> None:
        self.log_path = Path(log_path)

    @staticmethod
    def _safe_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
        """Keep only approved, simple metadata fields."""
        if metadata is None:
            return {}

        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary.")

        safe = {}

        for key, value in metadata.items():
            if not isinstance(key, str):
                continue

            normalized_key = key.lower()

            if any(fragment in normalized_key for fragment in SENSITIVE_KEY_FRAGMENTS):
                continue

            if key not in ALLOWED_METADATA_KEYS:
                continue

            if isinstance(value, bool):
                safe[key] = value
            elif isinstance(value, int):
                safe[key] = value
            elif isinstance(value, str) and len(value) <= 80:
                safe[key] = value
            # Ignore lists, dictionaries, and other complex objects.

        return safe

    def log_event(
        self,
        event_type: str,
        outcome: str = "INFO",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Validate and append one event; raw prompts and outputs are not accepted."""
        if event_type not in ALLOWED_EVENTS:
            raise ValueError(f"Unsupported audit event: {event_type}")

        if outcome not in ALLOWED_OUTCOMES:
            raise ValueError(f"Unsupported audit outcome: {outcome}")

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "outcome": outcome,
            "metadata": self._safe_metadata(metadata),
        }

        serialized = json.dumps(record, ensure_ascii=True)

        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Prevent concurrent threads from interleaving writes in this process.
        with _WRITE_LOCK:
            with self.log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(serialized + "\n")

        return record

"""Turn screenshots and PDF business documents into observations with Gemini.

The model is asked for the records an artifact shows (resource ids, systems,
identifiers, and state facts such as enabled/restore flags). Results are cached
so the full run is reproducible without repeating calls.
"""
from pathlib import Path

from .evidence import Obs, _finish, _state_from, system_for

PROMPT = """You are extracting facts from a business artifact of the online shop "Northstar Shop"
(an internal product screen, a support attachment, a statement, a register, or a compliance extract).
List every customer-data record the artifact shows. For each record return:
- resource_id: the internal id exactly as printed, such as account_5762, search_428, support_1034,
  analytics_7438, export_1260, backup_9287, data_flow_1121, audit_record_003, marketing_001, tombstone_17,
  object_19 or legal_hold_123. If the artifact shows a file or order but no internal id, use the
  closest printed reference (file name, statement or order number).
- system_id: the owning service if printed or obvious (account_service, search_service, support_platform,
  analytics_platform, export_service, backup_service, integration_service, security_service,
  identity_service, marketing_platform, object_storage, legal_service), otherwise "".
- record_kind: one of USER_PROFILE, SEARCH_INDEX_ENTRY, SUPPORT_MESSAGE, SUPPORT_ATTACHMENT,
  ANALYTICS_PROFILE, USER_EXPORT, BACKUP_ARCHIVE, DATA_FLOW, SECURITY_AUDIT_LOG, LEGAL_HOLD_RECORD,
  ACCOUNT_TOMBSTONE, MARKETING_PROFILE, OTHER.
- user_id, name, email, phone: the direct identifiers printed for this record ("" when not shown).
- other_identifiers: any other emails, names or user ids printed in the record.
- state: PRESENT if the record is shown as existing, ABSENT if shown as deleted/not found.
- enabled: for connectors or data flows, true if active/continuous/healthy, false if disabled, null otherwise.
- restore_allowed: for backups, true if restorable, false if blocked, null if not shown.
- retain_until: retention end date in ISO format if shown, else "".
- observed_at: the most specific timestamp shown for the record in ISO 8601, else "".
- notes: one short sentence of other relevant facts (for example who the attachment belongs to).
Only report what is printed; do not guess identifiers.
Return JSON: {"records": [ ... ]}"""

SCHEMA = {
    "type": "object",
    "properties": {"records": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "resource_id": {"type": "string"}, "system_id": {"type": "string"}, "record_kind": {"type": "string"},
            "user_id": {"type": "string"}, "name": {"type": "string"}, "email": {"type": "string"},
            "phone": {"type": "string"},
            "other_identifiers": {"type": "array", "items": {"type": "string"}},
            "state": {"type": "string"}, "enabled": {"type": "boolean", "nullable": True},
            "restore_allowed": {"type": "boolean", "nullable": True},
            "retain_until": {"type": "string"}, "observed_at": {"type": "string"}, "notes": {"type": "string"},
        },
        "required": ["resource_id", "state"]}}},
    "required": ["records"],
}

MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".pdf": "application/pdf"}


class VisionExtractor:
    def __init__(self, client):
        self.client = client
        self.errors: list[str] = []

    def __call__(self, path: Path, evidence_id: str, captured_at: str) -> list[Obs]:
        mime = MIME.get(path.suffix.lower())
        if mime is None or self.client is None:
            return []
        try:
            reply = self.client.generate_json("evidence_extraction", PROMPT, attachment=path,
                                              mime_type=mime, schema=SCHEMA)
        except RuntimeError as exc:
            self.errors.append(f"{evidence_id}: {exc}")
            return []
        out = []
        for rec in reply.get("records", []):
            rid = (rec.get("resource_id") or "").strip()
            if not rid:
                continue
            attrs = {
                "record_type": rec.get("record_kind", ""),
                "customer_reference": rec.get("user_id") or None,
                "name": rec.get("name") or None,
                "email": rec.get("email") or None,
                "phone": rec.get("phone") or None,
                "other_identifiers": " ".join(rec.get("other_identifiers") or []) or None,
                "result": "NOT_FOUND" if str(rec.get("state", "")).upper() == "ABSENT" else "FOUND",
                "notes": rec.get("notes") or None,
            }
            if rec.get("enabled") is not None:
                attrs["enabled"] = rec["enabled"]
            if rec.get("restore_allowed") is not None:
                attrs["restore_allowed"] = rec["restore_allowed"]
            if rec.get("retain_until"):
                attrs["retention_until"] = rec["retain_until"]
            if mime == "application/pdf" and rid.startswith("support_"):
                # A support record read from a PDF document is that uploaded attachment.
                attrs["record_type"] = "SUPPORT_ATTACHMENT"
            system = rec.get("system_id") or system_for(rid)
            if system_for(rid) != "unknown":
                system = system_for(rid)
            # Printed dates describe business events; the artifact shows state as of capture.
            if rec.get("observed_at"):
                attrs["printed_at"] = rec["observed_at"]
            when = captured_at
            out.append(_finish(Obs(
                evidence_id=evidence_id, captured_at=captured_at, observed_at=when, system_id=system,
                resource_id=rid, state=_state_from(attrs, "PRESENT"), attrs=attrs,
                source="vision:" + (rec.get("record_kind") or "record").lower(),
            )))
        return out

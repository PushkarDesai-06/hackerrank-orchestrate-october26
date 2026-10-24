"""Hand-built evaluation cases that exercise traps the public samples do not.

`build(dir)` writes a miniature dataset in the same layout as dataset/ plus
`expected_output.csv`, so the real pipeline can be run and scored against it.
All people and identifiers are fictional.
"""
import csv
import hashlib
import json
from pathlib import Path


def sha(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()


USERS = [
    # user_id, name, current email, phone
    ("user_901", "Talia Brennan", "talia.brennan@example.org", "+44 7700 900111"),
    ("user_902", "Ruben Okafor", "ruben.okafor@example.org", "+234 803 555 0102"),
    ("user_903", "Mei Lindqvist", "mei.lindqvist@example.org", "+46 70 555 01 03"),
    ("user_904", "Jonas Ferreira", "jonas.ferreira@example.org", "+351 912 555 104"),
    ("user_905", "Priyanka Sole", "priyanka.sole@example.org", "+91 98100 55105"),
]
OLD_EMAIL_901 = "t.brennan.old@example.org"

REQUESTS = [
    # C1: request arrives under the historical email; primary is clean but a read
    # replica still holds the profile (replication drift).
    ("custom_01", OLD_EMAIL_901, "2026-09-01T10:00:00Z", "COMPLETE", "2026-09-02T10:00:00Z",
     "2026-09-10T10:00:00Z", "Please delete my account. I used this older address before I changed it."),
    # C2: compliant at audit time; a capture taken after the audit shows the
    # search entry re-created. Later evidence must not change the answer.
    ("custom_02", "ruben.okafor@example.org", "2026-09-01T10:00:00Z", "COMPLETE", "2026-09-02T10:00:00Z",
     "2026-09-10T10:00:00Z", "Please permanently erase the account registered to this email."),
    # C3: tombstone still exposes the name and email; a legal hold must stay.
    ("custom_03", "mei.lindqvist@example.org", "2026-09-01T10:00:00Z", "PARTIALLY_COMPLETE",
     "2026-09-02T10:00:00Z", "2026-09-10T10:00:00Z",
     "Close my account and keep only the internal reference you need for records you must retain."),
    # C4: uses deletion vocabulary but asks for a correction only.
    ("custom_04", "jonas.ferreira@example.org", "2026-09-01T10:00:00Z", "NOT_STARTED", "2026-09-02T10:00:00Z",
     "2026-09-10T10:00:00Z", "Please do not delete anything. I only want the phone number on my profile corrected."),
    # C5: an enabled connector and a restorable backup can recreate the data.
    ("custom_05", "priyanka.sole@example.org", "2026-09-01T10:00:00Z", "COMPLETE", "2026-09-02T10:00:00Z",
     "2026-09-10T10:00:00Z", "I am requesting deletion of my account and everything linked to it."),
]

PRIMARY_SQL = """-- Captured at: 2026-09-09T12:00:00Z
-- Database topology: read_replica
CREATE TABLE customer_data_primary (resource_id TEXT PRIMARY KEY, origin_system TEXT NOT NULL,
  collection_name TEXT NOT NULL, record_json TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE customer_data_read_replica (resource_id TEXT PRIMARY KEY, origin_system TEXT NOT NULL,
  collection_name TEXT NOT NULL, record_json TEXT NOT NULL, updated_at TEXT NOT NULL);
"""


def _row(table, rid, system, collection, record):
    payload = json.dumps(record).replace("'", "''")
    return (f"INSERT INTO \"{table}\" VALUES('{rid}','{system}','{collection}','{payload}',"
            f"'2026-09-09T12:00:00Z');\n")


def build(root: Path) -> Path:
    ev = root / "evidence"
    (ev / "databases").mkdir(parents=True, exist_ok=True)
    (ev / "records").mkdir(parents=True, exist_ok=True)

    def write_csv(name, header, rows):
        with open(root / name, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)

    write_csv("user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
              [(u, n, e, p, sha(e), "2026-06-01T00:00:00Z") for u, n, e, p in USERS])
    write_csv("user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
              [("audit_901", "user_901", "2026-05-01T00:00:00Z", "email", OLD_EMAIL_901, USERS[0][2]),
               ("audit_902", "user_901", "2026-05-01T00:00:00Z", "email_hash", sha(OLD_EMAIL_901),
                sha(USERS[0][2]))])
    write_csv("deletion_requests.csv",
              ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"],
              REQUESTS)
    rules_src = Path(__file__).resolve().parents[2] / "dataset" / "deletion_rules.csv"
    (root / "deletion_rules.csv").write_text(rules_src.read_text(encoding="utf-8"), encoding="utf-8")
    write_csv("system_activity.csv",
              ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id",
               "reported_result", "details"],
              # The workflow for custom_02 deleted the primary profile about an hour before reporting.
              [("activity_c1", "2026-09-02T09:02:13Z", "DELETE_RECORD", "deletion_worker", "account_service",
                "account_9002", "SUCCESS", "Deletion worker submitted primary profile account_9002 to account_service.")])

    # One replica snapshot (in window) shared by cases 01, 03 and 05.
    sql = PRIMARY_SQL
    sql += _row("customer_data_primary", "audit_record_9001", "security_service", "security_audit_events",
                {"subject_reference": "user_901", "event_name": "account_deletion_reviewed"})
    sql += _row("customer_data_read_replica", "account_9001", "account_service", "customer_profiles",
                {"customer_reference": "user_901", "full_name": "Talia Brennan", "email": OLD_EMAIL_901,
                 "account_status": "ACTIVE"})
    sql += _row("customer_data_primary", "tombstone_9003", "identity_service", "deleted_customer_references",
                {"subject_reference": "user_903", "name": "Mei Lindqvist", "email": USERS[2][2], "phone": None,
                 "email_hash": None, "account_status": "DELETED"})
    sql += _row("customer_data_primary", "legal_hold_9003", "legal_service", "retained_order_records",
                {"subject_reference": "user_903", "order_reference": "ORD-9003",
                 "retained_until": "2033-12-31T23:59:59Z"})
    sql += _row("customer_data_primary", "data_flow_9005", "integration_service", "connector_configurations",
                {"subject_selector": USERS[4][2], "enabled": True, "mode": "continuous_sync"})
    sql += _row("customer_data_primary", "backup_9005", "backup_service", "backup_catalog",
                {"subject_reference": "user_905", "restore_allowed": True})
    (ev / "databases" / "custom_replica_20260909.sql").write_text(sql, encoding="utf-8")

    # Case 02: in-window export shows the account gone and the index clean...
    in_window = {"exported_at": "2026-09-09T12:00:00Z", "service_exports": {
        "account_service": {"profile_lookups": [
            {"observed_at": "2026-09-09T11:00:00Z", "profile": None, "resource_id": "account_9002",
             "status_code": 404}]},
        "security_service": {"audit_records": [
            {"observed_at": "2026-09-09T11:05:00Z", "resource_id": "audit_record_9002",
             "subject_reference": "user_902", "event_code": "ACCOUNT_DELETION_RECORDED",
             "retention_until": "2031-12-31T23:59:59Z"}]},
        "search_service": {"index_queries": [
            {"observed_at": "2026-09-09T11:10:00Z", "query": USERS[1][2], "resource_id": "search_9002",
             "hits": {"documents": [], "total": 0}}]}}}
    # ...while a capture after the audit shows the entry back.
    late = {"exported_at": "2026-09-12T12:00:00Z", "service_exports": {
        "search_service": {"index_queries": [
            {"observed_at": "2026-09-12T11:10:00Z", "query": USERS[1][2], "resource_id": "search_9002",
             "hits": {"documents": [{"resource_id": "search_9002", "email": USERS[1][2]}], "total": 1}}]}}}
    (ev / "records" / "custom_export_20260909.json").write_text(json.dumps(in_window, indent=1), encoding="utf-8")
    (ev / "records" / "custom_export_20260912.json").write_text(json.dumps(late, indent=1), encoding="utf-8")

    write_csv("evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], [
        ("evidence_c1", "evidence/databases/custom_replica_20260909.sql", "custom_capture", "2026-09-09T12:00:00Z"),
        ("evidence_c2", "evidence/records/custom_export_20260909.json", "custom_export", "2026-09-09T12:00:00Z"),
        ("evidence_c3", "evidence/records/custom_export_20260912.json", "custom_export", "2026-09-12T12:00:00Z"),
    ])

    def steps(*items):
        return json.dumps([{"step_no": i + 1, "phase": p, "system_id": s, "resource_id": r, "operation": o,
                            "state": st, "evidence_id": e} for i, (p, s, r, o, st, e) in enumerate(items)])

    F, R, V = "FINDING", "REMEDIATION", "VERIFICATION"
    expected = [
        ("custom_01", "INCOMPLETE", steps(
            (F, "account_service", "account_9001", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_c1"),
            (R, "account_service", "account_9001", "DELETE_RECORD", "ABSENT", ""),
            (V, "account_service", "account_9001", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
            (V, "security_service", "audit_record_9001", "VERIFY_RECORD_PRESENT", "PRESENT", ""))),
        ("custom_02", "COMPLETE", steps(
            (V, "account_service", "account_9002", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_c2"),
            (V, "search_service", "search_9002", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_c2"),
            (V, "security_service", "audit_record_9002", "VERIFY_RECORD_PRESENT", "PRESENT", "evidence_c2"))),
        ("custom_03", "INCOMPLETE", steps(
            (F, "identity_service", "tombstone_9003", "REPORT_EXPOSED_PII", "PRESENT", "evidence_c1"),
            (R, "identity_service", "tombstone_9003", "REDACT_RECORD", "REDACTED", ""),
            (V, "legal_service", "legal_hold_9003", "VERIFY_RECORD_PRESENT", "PRESENT", ""),
            (V, "identity_service", "tombstone_9003", "VERIFY_RECORD_REDACTED", "REDACTED", ""))),
        ("custom_04", "NOT_APPLICABLE", "[]"),
        ("custom_05", "INCOMPLETE", steps(
            (F, "integration_service", "data_flow_9005", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "evidence_c1"),
            (F, "backup_service", "backup_9005", "REPORT_RESTORE_RISK", "ACTIVE", "evidence_c1"),
            (R, "integration_service", "data_flow_9005", "DISABLE_DATA_FLOW", "DISABLED", ""),
            (R, "backup_service", "backup_9005", "BLOCK_RESTORE", "BLOCKED", ""),
            (V, "integration_service", "data_flow_9005", "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""),
            (V, "backup_service", "backup_9005", "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))),
    ]
    write_csv("expected_output.csv", ["case_id", "deletion_status", "steps_json"], expected)
    return root

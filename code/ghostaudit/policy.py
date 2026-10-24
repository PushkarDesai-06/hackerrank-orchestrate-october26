"""Deletion policy: data categories, required treatment, and step vocabulary."""

# Operation order inside each phase, as listed in the problem statement.
FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                      "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
PHASE_ORDER = {"FINDING": FINDING_ORDER, "REMEDIATION": REMEDIATION_ORDER, "VERIFICATION": VERIFICATION_ORDER}

OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# Category -> (violation finding, remediation, final verification)
TREATMENT = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    "RETAIN": (None, None, "VERIFY_RECORD_PRESENT"),
    "DATA_FLOW": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    "BACKUP": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
}


def load_rules(rules: list[dict]) -> dict[str, str]:
    """data_category -> required_action from deletion_rules.csv."""
    return {r["data_category"]: r["required_action"] for r in rules}


def treatment_for(category: str, rules: dict[str, str]) -> str:
    if category == "DATA_FLOW":
        return "DATA_FLOW"
    if category == "BACKUP_ARCHIVE":
        # Backups are retained, but only when restore access is blocked.
        return "BACKUP"
    action = rules.get(category, "DELETE")
    return action

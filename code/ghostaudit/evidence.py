"""Parse every evidence format into one normalized list of observations.

An observation says: at `observed_at`, evidence `evidence_id` saw resource
`resource_id` in `system_id` with state PRESENT/ABSENT and these attributes.
Identifiers found in the observation (emails, phones, names, hashes, user ids)
are normalized into `idents` so a case can be matched with a set lookup.
"""
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
RESOURCE_RE = re.compile(
    r"\b(?:account|search|support|analytics|audit_record|backup|data_flow|export|tombstone|"
    r"legal_hold|marketing|object|cache|email_delivery|telemetry)_\d+\b"
)

PREFIX_SYSTEM = [
    ("audit_record_", "security_service"),
    ("data_flow_", "integration_service"),
    ("legal_hold_", "legal_service"),
    ("email_delivery_", "email_delivery_service"),
    ("account_", "account_service"),
    ("search_", "search_service"),
    ("support_", "support_platform"),
    ("analytics_", "analytics_platform"),
    ("backup_", "backup_service"),
    ("export_", "export_service"),
    ("tombstone_", "identity_service"),
    ("marketing_", "marketing_platform"),
    ("object_", "object_storage"),
    ("cache_", "cache_service"),
    ("telemetry_", "telemetry_service"),
]

# Fields whose values are direct identifiers that policy may require removing.
EMAIL_KEYS = {"email", "owner_email", "customer_email", "requester_email", "uploaded_by", "account_email"}
PHONE_KEYS = {"phone", "owner_phone", "requester_phone", "customer_phone"}
NAME_KEYS = {"full_name", "display_name", "requester_name", "name", "customer_name"}
HASH_KEYS = {"email_hash"}
REF_KEYS = {"user_id", "customer_reference", "subject_reference", "subject_selector", "subject_ref"}
# Keys that only carry infrastructure noise; never treated as identifiers.
NOISE_KEYS = {"instance", "pod", "region", "level", "severity", "logger", "attempt", "duration_ms",
              "took_ms", "wait_ms", "latency_ms", "shard", "pool", "cache", "seq", "node"}


def system_for(resource_id: str) -> str:
    for prefix, system in PREFIX_SYSTEM:
        if resource_id.startswith(prefix):
            return system
    return "unknown"


def is_null(v) -> bool:
    return v is None or (isinstance(v, str) and v.strip().lower() in ("", "null", "none", "-", "—"))


def norm_phone(v: str) -> str:
    return "tel:" + re.sub(r"\D", "", v)


def norm_name(v: str) -> str:
    return "name:" + " ".join(v.lower().split())


def idents_from_value(key: str, value) -> set[str]:
    """Normalize every identifier that can be read from one field value."""
    out: set[str] = set()
    if is_null(value) or not isinstance(value, str):
        return out
    v = value.strip()
    for email in EMAIL_RE.findall(v):
        out.add(email.lower())
    for uid in USER_RE.findall(v):
        out.add(uid.lower())
    for h in HASH_RE.findall(v.lower()):
        out.add(h)
    if key in PHONE_KEYS or re.fullmatch(r"\+?[\d\s().-]{7,}", v):
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 7:
            out.add("tel:" + digits)
    if key in NAME_KEYS or key in ("customer", "matched_value"):
        if not EMAIL_RE.search(v) and re.search(r"[A-Za-z]", v):
            out.add(norm_name(v))
    return out


@dataclass
class Obs:
    evidence_id: str
    captured_at: str
    observed_at: str
    system_id: str
    resource_id: str
    state: str | None
    attrs: dict
    source: str
    idents: set = field(default_factory=set)

    def pii(self) -> dict:
        """Direct identifiers still exposed in this record (non-null)."""
        verdict = str(self.attrs.get("result", "")).upper()
        if verdict == "IDENTIFIABLE":
            return {"result": self.attrs.get("subject_reference") or verdict}
        if verdict in ("ANONYMIZED", "REDACTED"):
            return {}
        found = {}
        for k, v in self.attrs.items():
            base = k.split(".")[-1]
            if is_null(v):
                continue
            if base in EMAIL_KEYS | PHONE_KEYS | NAME_KEYS | HASH_KEYS:
                found[base] = v
            elif base == "message_text" and isinstance(v, str) and (EMAIL_RE.search(v) or "[REDACTED]" not in v):
                if EMAIL_RE.search(v):
                    found[base] = v
            elif base == "matched_value" and self.attrs.get("detector", "direct_identifier") == "direct_identifier":
                found[base] = v
            elif base == "direct_identifiers" and str(v) not in ("0",):
                found[base] = v
        return found

    def refs(self) -> set[str]:
        out = set()
        for k, v in self.attrs.items():
            if k.split(".")[-1] in REF_KEYS and not is_null(v):
                out |= {u.lower() for u in USER_RE.findall(str(v))}
        return out


def _finish(obs: Obs) -> Obs:
    for k, v in obs.attrs.items():
        base = k.split(".")[-1]
        if base in NOISE_KEYS:
            continue
        obs.idents |= idents_from_value(base, v)
    return obs


def _state_from(attrs: dict, default: str | None) -> str | None:
    get = lambda k: attrs.get(k)  # noqa: E731
    status = str(get("status_code") or get("http_status") or "")
    if status == "404":
        return "ABSENT"
    if status == "200":
        return "PRESENT"
    result = str(get("result") or "").upper()
    if result in ("NOT_FOUND", "MISS", "ABSENT", "MISSING", "NO_HIT"):
        return "ABSENT"
    if result in ("FOUND", "HIT", "IDENTIFIABLE", "ANONYMIZED", "REDACTED", "PRESENT", "ACTIVE", "RETAINED",
                  "ENABLED", "DISABLED", "RESTORABLE", "BLOCKED"):
        return "PRESENT"
    rows = get("rows")
    if rows is not None and str(rows).isdigit():
        return "ABSENT" if int(rows) == 0 else "PRESENT"
    total = next((attrs[k] for k in ("total", "total_hits", "hits.total") if attrs.get(k) is not None), None)
    if total is not None and str(total).isdigit():
        return "ABSENT" if int(total) == 0 else "PRESENT"
    if str(get("archive_present")).lower() == "false":
        return "ABSENT"
    return default


def _flatten(node: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in node.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            if "resource_id" in v:
                continue
            out.update(_flatten(v, key + "."))
        elif isinstance(v, list):
            if all(not isinstance(x, (dict, list)) for x in v):
                out[key] = v
            else:
                for i, x in enumerate(v):
                    if isinstance(x, dict) and "resource_id" not in x:
                        out.update(_flatten(x, f"{key}.{i}."))
        else:
            out[key] = v
    return out


# ---------------------------------------------------------------- JSON


CTX_KEYS = ("captured_at", "observed_at", "recorded_at", "data_store", "collection", "system")


def parse_json(path: Path, evidence_id: str, captured_at: str) -> list[Obs]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[Obs] = []

    def walk(node, ctx, parent_key):
        if isinstance(node, list):
            for x in node:
                walk(x, ctx, parent_key)
            return
        if not isinstance(node, dict):
            return
        ctx = dict(ctx)
        for k in CTX_KEYS:
            if k in node and isinstance(node[k], str):
                ctx[k] = node[k]
        if parent_key and parent_key not in ("records", "snapshots", "documents"):
            ctx.setdefault("group", parent_key)
        if "resource_id" in node and isinstance(node["resource_id"], str):
            attrs = _flatten(node)
            rid = node["resource_id"]
            system = node.get("system") or ctx.get("data_store") or ctx.get("service") or system_for(rid)
            if system in ("backup_restore_service", "support_storage_service", "privacy_treatment_service"):
                system = system_for(rid)
            # A lookup whose payload is null proves the record was not returned.
            default = "PRESENT"
            if "profile" in node and node["profile"] is None:
                default = "ABSENT"
            when = node.get("observed_at") or node.get("recorded_at") or ctx.get("captured_at") or captured_at
            out.append(_finish(Obs(
                evidence_id=evidence_id, captured_at=captured_at, observed_at=when,
                system_id=system if system != "unknown" else system_for(rid), resource_id=rid,
                state=_state_from(attrs, default), attrs=attrs,
                source="json:" + (ctx.get("collection") or ctx.get("group") or path.stem),
            )))
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                walk(v, ctx, k if k in ("service_exports",) or isinstance(v, list) else parent_key)

    walk(data, {}, "")
    return out


# ---------------------------------------------------------------- SQL


def parse_sql(path: Path, evidence_id: str, captured_at: str) -> list[Obs]:
    text = path.read_text(encoding="utf-8")
    con = sqlite3.connect(":memory:")
    con.executescript(text)
    out: list[Obs] = []
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        scope = dict(con.execute("select origin_system, captured_at from snapshot_scope").fetchall())
    for table in tables:
        if table == "snapshot_scope":
            continue
        cur = con.execute(f'select * from "{table}"')
        cols = [d[0] for d in cur.description]
        for row in cur.fetchall():
            rec = dict(zip(cols, row))
            if "record_json" in rec:
                try:
                    inner = json.loads(rec.pop("record_json"))
                    rec.update(_flatten(inner))
                except json.JSONDecodeError:
                    pass
            rid = rec.get("resource_id")
            if not rid:
                continue
            system = rec.get("origin_system") or system_for(rid)
            out.append(_finish(Obs(
                evidence_id=evidence_id, captured_at=captured_at,
                observed_at=scope.get(system, captured_at), system_id=system, resource_id=rid,
                state="PRESENT", attrs=rec, source="sql:" + table,
            )))
    con.close()
    return out


def sql_tables(path: Path) -> dict[str, set[str]]:
    """Map each table in a snapshot to the resource ids it contains."""
    con = sqlite3.connect(":memory:")
    con.executescript(path.read_text(encoding="utf-8"))
    res = {}
    for (table,) in con.execute("select name from sqlite_master where type='table'").fetchall():
        cols = [r[1] for r in con.execute(f'pragma table_info("{table}")')]
        if "resource_id" in cols:
            res[table] = {r[0] for r in con.execute(f'select resource_id from "{table}"')}
    con.close()
    return res


# ---------------------------------------------------------------- logs

KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _kv(text: str) -> dict:
    out = {}
    for k, v in KV_RE.findall(text):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    if "message" in out and "=" in out["message"]:
        out.update(_kv(out.pop("message")))
    return out


def parse_log_line(line: str) -> dict | None:
    line = line.strip()
    if not line or " " not in line:
        return None
    ts, rest = line.split(" ", 1)
    if not re.match(r"\d{4}-\d{2}-\d{2}T", ts):
        return None
    ev: dict = {"ts": ts}
    if rest.startswith("{"):
        try:
            ev.update({k: v for k, v in json.loads(rest).items()})
        except json.JSONDecodeError:
            return None
    elif rest.startswith("["):
        m = re.match(r"\[(\w+)\] \[([^\]]+)\] \[([^\]]+)\] (\w+): ?(.*)", rest)
        if not m:
            return None
        ev.update(level=m[1], service=m[2], trace_id=m[3], event=m[4])
        ev.update(_kv(m[5]))
    elif rest.startswith("|") or " | " in rest[:40]:
        parts = [p.strip() for p in rest.split(" | ", 4)]
        if len(parts) < 5:
            return None
        ev.update(level=parts[0], service=parts[1], trace_id=parts[2], event=parts[3])
        ev.update(_kv(parts[4]))
    elif rest.startswith("<"):
        m = re.match(r"<\d+>\d+ (\S+) (\S+) (\S+) \S+ \S+ (.*)", rest)
        if not m:
            return None
        ev.update(node=m[1], service=m[2], trace_id=m[3])
        ev.update(_kv(m[4]))
    else:
        ev.update(_kv(rest))
    ev.setdefault("service", ev.get("function") or ev.get("logger"))
    if "requestId" in ev and "trace_id" not in ev:
        ev["trace_id"] = ev.pop("requestId")
    return ev


def parse_log(path: Path, evidence_id: str, captured_at: str) -> list[Obs]:
    events = [e for e in (parse_log_line(l) for l in path.read_text(encoding="utf-8").splitlines()) if e]
    groups: dict[str, list[dict]] = {}
    for i, ev in enumerate(events):
        key = ev.get("trace_id") or f"line{i}"
        groups.setdefault(key, []).append(ev)
    out: list[Obs] = []
    for evs in groups.values():
        group_idents: set[str] = set()
        for ev in evs:
            for k, v in ev.items():
                if k not in NOISE_KEYS and k not in ("ts", "trace_id", "event", "service", "function"):
                    group_idents |= idents_from_value(k, v)
        for ev in evs:
            rid = ev.get("resource_id")
            if not rid or not RESOURCE_RE.fullmatch(rid):
                continue
            # "*_started" lines only announce a lookup; the result line carries the state.
            if str(ev.get("event", "")).endswith("_started"):
                continue
            attrs = {k: v for k, v in ev.items() if k not in NOISE_KEYS}
            system = ev.get("system") or ev.get("service") or system_for(rid)
            if system not in {s for _, s in PREFIX_SYSTEM} or system_for(rid) != system:
                system = system_for(rid)
            obs = Obs(
                evidence_id=evidence_id, captured_at=captured_at, observed_at=ev["ts"],
                system_id=system, resource_id=rid, state=_state_from(attrs, "PRESENT"),
                attrs=attrs, source="log:" + str(ev.get("event")),
            )
            _finish(obs)
            obs.idents |= group_idents
            out.append(obs)
    return out


# ---------------------------------------------------------------- text records

HANDOVER_RE = re.compile(
    r"^-\s*(\S+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(.+?)\s*$"
)


def parse_text(path: Path, evidence_id: str, captured_at: str) -> list[Obs]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = HANDOVER_RE.match(line.strip())
        if not m:
            continue
        ts, system, rid, rtype, result, value = m.groups()
        attrs = {"record_type": rtype, "result": result, "subject_reference": value}
        if result == "IDENTIFIABLE":
            attrs["matched_value"] = value
        out.append(_finish(Obs(
            evidence_id=evidence_id, captured_at=captured_at, observed_at=ts, system_id=system,
            resource_id=rid, state=_state_from(attrs, "PRESENT"), attrs=attrs, source="text:handover",
        )))
    return out


PARSERS = {".json": parse_json, ".sql": parse_sql, ".log": parse_log, ".txt": parse_text}


def declared_scope(path: Path) -> set[str]:
    """Systems a snapshot says it captured, even when it holds no rows for them.

    An empty collection inside a scoped snapshot is positive proof that a
    record was absent at capture time.
    """
    suffix = path.suffix.lower()
    if suffix == ".sql":
        con = sqlite3.connect(":memory:")
        con.executescript(path.read_text(encoding="utf-8"))
        tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        scope = set()
        if "snapshot_scope" in tables:
            scope = {r[0] for r in con.execute("select origin_system from snapshot_scope")}
        if {"customer_profiles_primary", "customer_profiles_failover_replica"} & tables:
            scope.add("account_service")
        con.close()
        return scope
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        scope = set()
        for snap in data.get("snapshots", []):
            scope.add(snap.get("data_store"))
        scope |= set(data.get("service_exports", {}).keys())
        return {s for s in scope if s}
    return set()


def load_observations(dataset_root: Path, manifest: list[dict], extractor=None) -> tuple[list[Obs], dict]:
    """Parse every manifest file. `extractor` handles images and PDFs.

    Returns the observations and, per evidence id, the set of systems the file
    covers (used to prove absence by omission).
    """
    out: list[Obs] = []
    coverage: dict[str, set[str]] = {}
    for m in manifest:
        path = dataset_root / m["file_path"]
        parser = PARSERS.get(path.suffix.lower())
        found: list[Obs] = []
        if parser:
            found = parser(path, m["file_id"], m["captured_at"])
        elif extractor is not None:
            found = extractor(path, m["file_id"], m["captured_at"])
        out.extend(found)
        coverage[m["file_id"]] = declared_scope(path) if parser else set()
    return out, coverage

"""Per-case reasoning: identity, linking, state at audit_at, policy, and planning."""
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .evidence import EMAIL_RE, RESOURCE_RE, Obs, idents_from_value, norm_name, norm_phone, system_for
from .policy import OP_STATE, PHASE_ORDER, TREATMENT, load_rules, treatment_for

FAR_PAST = "0000"
FAR_FUTURE = "9999"

# A workflow's own operations land in a fixed band around reported_at: the
# primary account deletion up to ~1.3h before it, policy actions shortly
# before it, and failed attempts or status checks up to two hours after.
ACCOUNT_WINDOW = (timedelta(hours=-1.3), timedelta(hours=0.25))
ACTION_WINDOW = (timedelta(hours=-0.6), timedelta(hours=2.0))
WORKFLOW_EVENTS = {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
                   "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS"}
# Records that policy keeps; their absence is never inferred from omission.
RETAINED = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}
# The workflow's status claim mirrors the result of its primary account deletion.
CLAIM_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}
# Events of one workflow run are scheduled from a shared start time, so their
# seconds agree modulo 30 once each event kind's fixed offset is removed.
CHAIN_PERIOD = 30
LINK_HORIZON = timedelta(days=7)
CHAIN_TOLERANCE = 1.6


def chain_offset(event: dict) -> float | None:
    details = event["details"]
    if "Target resource:" in details:
        return None  # one-off workflow runs follow no shared schedule
    if "submitted primary profile" in details:
        return 0.0
    if details.startswith("Policy action completed"):
        return 10.0
    return 21.5


def chain_residue(event: dict) -> float | None:
    offset = chain_offset(event)
    if offset is None:
        return None
    return (ts(event["event_time"]).second - offset) % CHAIN_PERIOD


def residue_gap(a: float, b: float) -> float:
    d = abs(a - b) % CHAIN_PERIOD
    return min(d, CHAIN_PERIOD - d)


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def resource_type(rid: str) -> str:
    return rid.rsplit("_", 1)[0]


@dataclass
class CaseContext:
    req: dict
    user_id: str | None
    idents: set
    window_start: str
    window_end: str
    resources: dict = field(default_factory=dict)  # rid -> how it was linked
    primary_evidence: str | None = None


@dataclass
class ResourceView:
    rid: str
    system_id: str
    category: str
    state: str            # PRESENT / ABSENT / UNKNOWN
    exposed: bool         # direct identifiers still visible
    flow_active: bool | None
    restore_open: bool | None
    evidence: str | None  # file that proves the state at audit_at
    links: set


class Auditor:
    def __init__(self, ds, observations: list[Obs], coverage: dict, all_requests: list[dict],
                 non_deletion: set[str] | None = None):
        self.ds = ds
        self.non_deletion = non_deletion or set()
        self.rules = load_rules(ds.rules)
        self.coverage = coverage
        self.manifest = {m["file_id"]: m for m in ds.manifest}
        # Artifacts sometimes print a file name or business reference instead of
        # the internal id; catalog links ("object_19 (delivery_confirmation_19.pdf)")
        # map those references back to resource ids.
        aliases = self._catalog_aliases(ds.activity)
        for o in observations:
            if o.resource_id in aliases:
                o.resource_id = aliases[o.resource_id]
                o.system_id = system_for(o.resource_id)
        self.by_rid: dict[str, list[Obs]] = defaultdict(list)
        self.by_ident: dict[str, list[Obs]] = defaultdict(list)
        self.file_systems: dict[str, set] = defaultdict(set)
        for o in observations:
            self.by_rid[o.resource_id].append(o)
            self.file_systems[o.evidence_id].add(o.system_id)
            for i in o.idents:
                self.by_ident[i].append(o)
        self._build_identity()
        self.contexts = self._build_contexts(all_requests)
        self._link_explicit()
        for ctx in self.contexts.values():
            ctx.primary_evidence = self.primary_evidence(ctx)
        self._link_workflow_activity()

    @staticmethod
    def _catalog_aliases(activity: list[dict]) -> dict[str, str]:
        out = {}
        for a in activity:
            if a["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            m = re.search(r"linked (\S+) \(([^)]+)\)|confirmed (\S+) \(([^)]+)\)", a["details"])
            if not m:
                continue
            rid, ref = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
            if ref != rid:
                out[ref] = rid
        return out

    # ------------------------------------------------------------ identity

    def _build_identity(self):
        self.email_owner: dict[str, str] = {}
        self.user_idents: dict[str, set] = {}
        for uid, r in self.ds.identities.items():
            self.email_owner[r["email"].lower()] = uid
            self.user_idents[uid] = {uid.lower(), r["email"].lower(), r["email_hash"].lower(),
                                     norm_phone(r["phone"]), norm_name(r["name"])}
        for a in self.ds.audit_log:
            uid = a["user_id"]
            ids = self.user_idents.setdefault(uid, {uid.lower()})
            for v in (a["old_value"], a["new_value"]):
                if not v:
                    continue
                if a["field_name"] == "email":
                    ids.add(v.lower())
                    self.email_owner.setdefault(v.lower(), uid)
                elif a["field_name"] == "phone":
                    ids.add(norm_phone(v))
                elif a["field_name"] == "email_hash":
                    ids.add(v.lower())
        # identifier -> owners, to reject observations that belong to someone else
        self.ident_owners: dict[str, set] = defaultdict(set)
        for uid, ids in self.user_idents.items():
            for i in ids:
                self.ident_owners[i].add(uid)

    def resolve_user(self, email: str) -> str | None:
        return self.email_owner.get(email.strip().lower())

    def _belongs_to(self, o: Obs, uid: str, idents: set) -> bool:
        """True when the observation names this user and nobody else."""
        hit = o.idents & idents
        if not hit:
            return False
        strong = {i for i in hit if not i.startswith("name:")}
        others = set()
        for i in o.idents:
            if i.startswith("name:"):
                continue
            others |= self.ident_owners.get(i, set())
        others.discard(uid)
        if others and not strong:
            return False
        if others and strong:
            # A record naming two subjects is attributed to the one it matches strongly.
            return True
        return True

    def _build_contexts(self, requests: list[dict]) -> dict[str, CaseContext]:
        per_user: dict[str, list[dict]] = defaultdict(list)
        out = {}
        for r in requests:
            uid = self.resolve_user(r["email"])
            per_user[uid].append(r)
        for uid, reqs in per_user.items():
            reqs.sort(key=lambda r: r["requested_at"])
            for i, r in enumerate(reqs):
                # Evidence about this request is gathered after it was made and
                # shortly after the audit; older or much later captures describe
                # other workflow runs for the same person.
                start = max(r["requested_at"], reqs[i - 1]["audit_at"] if i > 0 else FAR_PAST)
                horizon = (ts(r["audit_at"]) + LINK_HORIZON).strftime("%Y-%m-%dT%H:%M:%SZ")
                end = min(horizon, reqs[i + 1]["requested_at"] if i + 1 < len(reqs) else FAR_FUTURE)
                idents = set(self.user_idents.get(uid, set())) if uid else {r["email"].lower()}
                out[r["case_id"]] = CaseContext(req=r, user_id=uid, idents=idents, window_start=start, window_end=end)
        return out

    # ------------------------------------------------------------ linking

    def _in_window(self, ctx: CaseContext, when: str) -> bool:
        return ctx.window_start <= when < ctx.window_end

    def _link_explicit(self):
        """Link resources whose evidence names the subject's identifiers."""
        self.explicit_owner: dict[str, set] = defaultdict(set)
        for cid, ctx in self.contexts.items():
            if not ctx.user_id:
                continue
            for ident in ctx.idents:
                for o in self.by_ident.get(ident, []):
                    if self._in_window(ctx, o.observed_at) and self._belongs_to(o, ctx.user_id, ctx.idents):
                        ctx.resources.setdefault(o.resource_id, set()).add("evidence")
            for a in self.ds.activity:
                if a["event_type"] != "LINK_RESOURCE_IDENTITY" or not self._in_window(ctx, a["event_time"]):
                    continue
                found = idents_from_value("details", a["details"])
                if found & ctx.idents:
                    ctx.resources.setdefault(a["resource_id"], set()).add("catalog")
            for rid in ctx.resources:
                self.explicit_owner[rid].add(cid)

    def _link_workflow_activity(self):
        """Attribute workflow operations by timing, resolving overlaps by elimination.

        Several cases can share the same reporting window, so a candidate must
        also be consistent with the case: the primary account deletion's result
        must match the workflow's claim, and a resource that appears in
        evidence must appear in the case's own primary capture.
        """
        events = [a for a in self.ds.activity
                  if a["source_system"] == "deletion_worker" and a["event_type"] in WORKFLOW_EVENTS]
        result_of = {a["resource_id"]: a["reported_result"] for a in events if a["event_type"] == "DELETE_RECORD"}
        reported = {cid: ts(ctx.req["reported_at"]) for cid, ctx in self.contexts.items()
                    if cid not in self.non_deletion}
        candidates: dict[str, set] = defaultdict(set)
        for a in events:
            rid = a["resource_id"]
            if self.explicit_owner.get(rid):
                continue
            t = ts(a["event_time"])
            lo, hi = ACCOUNT_WINDOW if resource_type(rid) == "account" else ACTION_WINDOW
            for cid, rep in reported.items():
                if rep + lo <= t <= rep + hi:
                    candidates[rid].add(cid)
        self.workflow_candidates = candidates
        files_of = {rid: {o.evidence_id for o in self.by_rid.get(rid, [])} for rid in candidates}

        event_of: dict[str, dict] = {}
        for a in events:
            event_of.setdefault(a["resource_id"], a)

        def in_case_window(cid, a):
            rep = reported.get(cid)
            if rep is None:
                return False
            lo, hi = ACCOUNT_WINDOW if resource_type(a["resource_id"]) == "account" else ACTION_WINDOW
            return rep + lo <= ts(a["event_time"]) <= rep + hi

        def case_residue(cid):
            """Residue of the case's workflow run, from events already tied to it."""
            for r in sorted(self.contexts[cid].resources):
                a = event_of.get(r)
                if a is not None and in_case_window(cid, a) and chain_residue(a) is not None:
                    return chain_residue(a)
            return None

        def plausible(cid, rid, strict):
            ctx = self.contexts[cid]
            if strict and resource_type(rid) == "account":
                if CLAIM_RESULT.get(ctx.req["reported_status"]) != result_of.get(rid):
                    return False
            seen_in = {f for f in files_of[rid] if self.manifest[f]["captured_at"] <= ctx.req["audit_at"]}
            if seen_in and ctx.primary_evidence and ctx.primary_evidence not in seen_in:
                return False
            anchor = case_residue(cid)
            own = chain_residue(event_of[rid]) if rid in event_of else None
            if anchor is not None and own is not None:
                if residue_gap(anchor, own) > CHAIN_TOLERANCE:
                    return False
            return True

        def has_type(cid, rtype):
            return any(resource_type(r) == rtype for r in self.contexts[cid].resources)

        assigned: dict[str, str] = {}
        for strict in (True, False):
            changed = True
            while changed:
                changed = False
                open_sets: dict[str, set] = {}
                for rid, cs in candidates.items():
                    if rid in assigned:
                        continue
                    rtype = resource_type(rid)
                    open_sets[rid] = {c for c in cs if not has_type(c, rtype) and plausible(c, rid, strict)}
                for rid, cs in open_sets.items():
                    if len(cs) == 1:
                        self._assign(assigned, rid, next(iter(cs)), "workflow")
                        changed = True
                        break
                if changed:
                    continue
                # Every deletion workflow removes exactly one primary account.
                by_case: dict[str, set] = defaultdict(set)
                for rid, cs in open_sets.items():
                    if resource_type(rid) == "account":
                        for c in cs:
                            by_case[c].add(rid)
                for cid, rids in by_case.items():
                    if len(rids) == 1:
                        self._assign(assigned, next(iter(rids)), cid, "workflow")
                        changed = True
                        break
        self.workflow_assigned = assigned

    def _assign(self, assigned, rid, cid, how):
        assigned[rid] = cid
        self.contexts[cid].resources.setdefault(rid, set()).add(how)

    # ------------------------------------------------------------ state

    def _eligible(self, ctx: CaseContext, o: Obs) -> bool:
        audit = ctx.req["audit_at"]
        return o.captured_at <= audit and ctx.window_start <= o.observed_at <= audit

    def categorize(self, rid: str, observations: list[Obs]) -> str:
        rtype = resource_type(rid)
        sources = {o.source for o in observations}
        attrs = {}
        for o in observations:
            attrs.update(o.attrs)
        rtype_map = {
            "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY", "audit_record": "SECURITY_AUDIT_LOG",
            "legal_hold": "LEGAL_HOLD_RECORD", "data_flow": "DATA_FLOW", "backup": "BACKUP_ARCHIVE",
            "export": "USER_EXPORT", "tombstone": "ACCOUNT_TOMBSTONE", "marketing": "MARKETING_PROFILE",
            "email_delivery": "EMAIL_DELIVERY_LOG", "cache": "CACHE_ENTRY", "telemetry": "PRODUCT_TELEMETRY",
            "object": "SUPPORT_ATTACHMENT",
        }
        if rtype in rtype_map:
            return rtype_map[rtype]
        if rtype == "support":
            declared = {str(o.attrs.get("record_type", "")) for o in observations}
            if "SUPPORT_ATTACHMENT" in declared or any("attachment" in s for s in sources) or "file_name" in attrs:
                return "SUPPORT_ATTACHMENT"
            conversation = ("SUPPORT_MESSAGE" in declared
                            or any(k.split(".")[-1] in ("message_excerpt", "message_text") for k in attrs)
                            or any("message" in s or "ticket" in s or "conversation" in s or "support_records" in s
                                   for s in sources))
            # A bare contact-index entry holds no shared conversation to keep.
            return "SUPPORT_MESSAGE" if conversation else "SECONDARY_IDENTIFIER"
        if rtype == "analytics":
            if any(s == "log:contact_lookup_completed" for s in sources) or "email_opt_in" in attrs:
                return "SECONDARY_IDENTIFIER"
            return "ANALYTICS_PROFILE"
        return "USER_PROFILE"

    def view(self, ctx: CaseContext, rid: str) -> ResourceView:
        all_obs = self.by_rid.get(rid, [])
        category = self.categorize(rid, all_obs)
        eligible = [o for o in all_obs if self._eligible(ctx, o)]
        system = all_obs[0].system_id if all_obs else system_for(rid)
        state, exposed, flow, restore, evidence = "UNKNOWN", False, None, None, None
        if eligible:
            latest_file_time = max(o.captured_at for o in eligible)
            latest = [o for o in eligible if o.captured_at == latest_file_time]
            # Inside one capture a log can hold several readings: keep the last per source.
            per_source: dict[tuple, Obs] = {}
            for o in sorted(latest, key=lambda o: o.observed_at):
                per_source[(o.evidence_id, o.source)] = o
            latest = list(per_source.values())
            evidence = sorted({o.evidence_id for o in latest})[0]
            present = [o for o in latest if o.state != "ABSENT"]
            state = "PRESENT" if present else "ABSENT"
            exposed = any(o.pii() for o in present)
            flow = self._flow_active(present) if present else None
            restore = self._restore_open(present) if present else None
            if present:
                evidence = sorted({o.evidence_id for o in present})[0]
            last_seen = max(o.observed_at for o in eligible)
        else:
            last_seen = FAR_PAST
        # A scoped snapshot taken after the last sighting that does not contain
        # the record proves it was gone by then.
        if category not in RETAINED and category not in ("DATA_FLOW", "BACKUP_ARCHIVE"):
            proof = self._omission_proof(ctx, system, rid, after=last_seen)
            if proof and (state == "UNKNOWN" or (state == "PRESENT" and proof[1] > max(
                    o.captured_at for o in eligible))):
                state, exposed, evidence = "ABSENT", False, proof[0]
        return ResourceView(rid=rid, system_id=system, category=category, state=state, exposed=exposed,
                            flow_active=flow, restore_open=restore, evidence=evidence,
                            links=ctx.resources.get(rid, set()))

    def _omission_proof(self, ctx, system, rid, after) -> tuple[str, str] | None:
        """A scoped snapshot that should list the record but does not.

        Snapshots mix records from many cases, so only the case's own primary
        capture counts; a case without one falls back to the latest capture
        that lists other records of the same system.
        """
        candidates = []
        for fid, systems in self.coverage.items():
            if system not in systems:
                continue
            cap = self.manifest[fid]["captured_at"]
            if not (cap <= ctx.req["audit_at"] and cap > after and cap >= ctx.req["requested_at"]):
                continue
            if any(o.evidence_id == fid for o in self.by_rid.get(rid, [])):
                continue
            candidates.append((fid, cap))
        if ctx.primary_evidence:
            return next((c for c in candidates if c[0] == ctx.primary_evidence), None)
        listed = [c for c in candidates if self.file_systems.get(c[0], set()) & {system}]
        return max(listed, key=lambda c: c[1]) if listed else None

    @staticmethod
    def _truthy(v) -> bool | None:
        if v is None:
            return None
        s = str(v).strip().lower()
        if s in ("1", "true", "yes", "enabled", "active", "allow", "allowed"):
            return True
        if s in ("0", "false", "no", "disabled", "stopped", "deny", "denied", "blocked"):
            return False
        return None

    def _flow_active(self, obs: list[Obs]) -> bool:
        for o in obs:
            for key in ("enabled", "status", "result"):
                v = self._truthy(o.attrs.get(key))
                if v is not None:
                    return v
            if str(o.attrs.get("result", "")).upper() == "ACTIVE":
                return True
        return True

    def _restore_open(self, obs: list[Obs]) -> bool:
        for o in obs:
            a = o.attrs
            v = self._truthy(a.get("restore_allowed"))
            if v is not None:
                return v
            if "decision" in a:
                return self._truthy(a["decision"]) is True
            if "eligible" in a:
                return self._truthy(a["eligible"]) is True and self._truthy(a.get("deletion_block")) is not True
            if str(a.get("result", "")).upper() in ("ACTIVE", "RESTORABLE"):
                return True
            if str(a.get("result", "")).upper() in ("BLOCKED",):
                return False
        return True

    # ------------------------------------------------------------ planning

    def _activity_citation(self, ctx: CaseContext, rid: str) -> str:
        """Last participant-visible activity on the resource before the audit."""
        best = ""
        best_time = ""
        for a in self.ds.activity:
            if a["resource_id"] == rid and a["event_time"] <= ctx.req["audit_at"] and a["event_time"] >= best_time:
                best, best_time = a["activity_id"], a["event_time"]
        return best

    def primary_evidence(self, ctx: CaseContext) -> str | None:
        counts: dict[str, int] = defaultdict(int)
        for rid in ctx.resources:
            for o in self.by_rid.get(rid, []):
                if self._eligible(ctx, o):
                    counts[o.evidence_id] += 1
        if not counts:
            return None
        return max(counts, key=lambda f: (counts[f], self.manifest[f]["captured_at"]))

    def plan(self, case_id: str) -> tuple[str, list[dict], list[ResourceView]]:
        ctx = self.contexts[case_id]
        # Only internal resource ids can be acted on; printed references that
        # no catalog link resolves (file names, order numbers) stay as context.
        views = [self.view(ctx, rid) for rid in sorted(ctx.resources) if RESOURCE_RE.fullmatch(rid)]
        findings, remediation, verification = [], [], []
        for v in views:
            treat = treatment_for(v.category, self.rules)
            finding_op, fix_op, verify_op = TREATMENT.get(treat, TREATMENT["DELETE"])
            violation = False
            if treat == "DATA_FLOW":
                violation = v.state == "PRESENT" and bool(v.flow_active)
            elif treat == "BACKUP":
                violation = v.state == "PRESENT" and bool(v.restore_open)
            elif treat == "DELETE":
                violation = v.state == "PRESENT"
            elif treat in ("REDACT", "ANONYMIZE"):
                violation = v.state == "PRESENT" and v.exposed
            if violation:
                findings.append((finding_op, v, v.evidence))
                remediation.append((fix_op, v, ""))
            verification.append((verify_op, v, v.evidence or ctx.primary_evidence or self._activity_citation(ctx, v.rid)))
        status = "INCOMPLETE" if findings else "COMPLETE"
        if status == "INCOMPLETE":
            verification = [(op, v, "") for op, v, _ in verification]
        steps = []
        for phase, items in (("FINDING", findings), ("REMEDIATION", remediation), ("VERIFICATION", verification)):
            order = PHASE_ORDER[phase]
            items.sort(key=lambda x: (order.index(x[0]), x[1].system_id, x[1].rid))
            for op, v, ev in items:
                steps.append({
                    "step_no": len(steps) + 1, "phase": phase, "system_id": v.system_id,
                    "resource_id": v.rid, "operation": op, "state": OP_STATE[op], "evidence_id": ev or "",
                })
        return status, steps, views

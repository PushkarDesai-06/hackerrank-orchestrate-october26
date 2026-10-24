# Ghost Data Still Exists: Deletion Audit Agent

HackerRank Orchestrate, October 2026. Author: Pushkar Desai (2024eb02433).

For every request in `dataset/deletion_requests.csv` the agent decides whether deletion was actually
requested, finds every copy of the person's data that existed at `audit_at`, applies
`dataset/deletion_rules.csv`, and writes the ordered finding, remediation and verification steps to
`output.csv`. The full challenge contract is in [`problem_statement.md`](./problem_statement.md).

Challenge and submission page:
https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

## Setup

Requirements: Python 3.10 or newer. No third-party packages are needed (only the standard library,
including `sqlite3`).

Optional, for the AI parts (screenshots, PDFs and multilingual request classification), create a
`.env` file in the repository root. It is gitignored and never committed:

```bash
GEMINI_API_KEYS=key_one,key_two,key_three   # one or more keys, rotated round robin
# GEMINI_API_KEY=single_key                  # also accepted
OPENROUTER_API_KEY=...                       # optional last-resort fallback
```

Every model response is cached under `code/cache/llm/`, keyed by a hash of the request. A rerun with the
cache present makes no API calls and reproduces the same `output.csv`.

## Run

```bash
python3 code/main.py              # full run, writes ./output.csv (518 rows)
python3 code/main.py --no-llm     # rules only: no model calls, images and PDFs are not read
python3 code/main.py --provider openrouter   # send uncached model calls straight to OpenRouter
python3 code/evaluation/main.py   # score against the 32 public samples and the custom cases
```

`code/main.py` validates the output contract before writing (row count, case ids, statuses,
consecutive step numbers, phase order, evidence rules) and refuses to write an invalid file. It also
writes the token and cost summary to `code/evaluation/last_run_usage.json`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEYS` / `GEMINI_API_KEY` | none | Gemini keys. Requests start at a random key and rotate on every call. A timeout, 429 or 5xx moves to the next key immediately. |
| `OPENROUTER_API_KEY` | none | Used only after every Gemini key has failed, unless the route is forced. |
| `LLM_PROVIDER` (or `--provider`) | `auto` | `auto` = Gemini keys first, OpenRouter last; `openrouter` or `gemini` forces one route. |
| `GEMINI_VISION_MODEL` | `gemini-3.6-flash` | Reads screenshots and PDFs (thinking level `medium`). |
| `GEMINI_TEXT_MODEL` | `gemini-3.5-flash-lite` | Classifies request texts in batches of 25 (thinking level `minimal`). |
| `OPENROUTER_VISION_MODEL` / `OPENROUTER_TEXT_MODEL` | `google/<gemini model>` | Model ids used on the fallback route. |

## How it works

```
dataset/ ──► evidence parsers ──► observations (one row per sighting of a resource)
                │                        │
                │   Gemini vision ───────┘   (PNG / PDF -> structured records, cached)
                ▼
         identity resolver ──► per-case linking ──► state at audit_at ──► policy ──► step planner ──► output.csv
                ▲                     ▲
   request classifier          workflow activity attribution
   (rules + Gemini)            (timing, claim, co-location, chain signature)
```

Code layout (`code/ghostaudit/`):

| Module | Role |
| --- | --- |
| `evidence.py` | Parses SQL snapshots (executed in in-memory SQLite), JSON exports and bundles, six log formats (key=value, bracketed, pipe, syslog, JSON lines, nested `message=`), and the handover text file into normalized observations with identifiers, state and attributes. Log lines are grouped by trace id so a lookup key joins its result line. |
| `vision.py` | Prompts Gemini to list the records an image or PDF shows (ids, identifiers, enabled/restore flags, timestamps) and converts them into observations. |
| `classify.py` | Decides whether the request authorizes deletion. A multilingual rule baseline runs first and Gemini confirms in batches; disagreements are reported. |
| `auditor.py` | Identity resolution (current plus historical emails, phones and hashes), linking, state reconstruction, policy application and step planning. |
| `policy.py` | Operation vocabulary, phase ordering and the treatment for each data category. |
| `llm.py` | Stdlib REST client: round-robin key rotation, OpenRouter fallback, disk cache, token accounting. |
| `pipeline.py` | End-to-end run, output serialization and contract validation. |

### Investigation approach

1. **Identity.** The request email resolves to a stable `user_id` through the current snapshot or the
   audit log. All historical emails, phones and email hashes are collected, because older systems still
   hold them.
2. **Time window.** Evidence about a request is taken from `requested_at` to 7 days after `audit_at`, and
   is never shared with another request from the same person. This keeps a person's earlier or later
   workflow runs, and late "decoy" captures, out of the case.
3. **Linking.** A resource belongs to the case when its evidence names the person's identifiers (and
   nobody else's strong identifiers), or when a data-catalog link activity says so. Some records carry
   no identifier at all (a 404 lookup, an anonymized analytics row), so the deletion workflow's own
   activity is attributed by:
   - timing relative to `reported_at` (account deletion about an hour before, policy actions just before,
     failures and checks up to two hours after);
   - the workflow claim matching the account deletion result (COMPLETE↔SUCCESS, PARTIALLY_COMPLETE↔PARTIAL,
     NOT_STARTED↔FAILED);
   - co-location (a resource seen in evidence must appear in the case's own primary capture);
   - a chain signature: events of one workflow run share their seconds modulo 30 after removing each event
     kind's fixed offset;
   - elimination, where every deletion workflow removes exactly one primary account. Genuinely ambiguous
     pairs are left out rather than guessed.
4. **State at `audit_at`.** Only evidence captured at or before `audit_at` (and rows observed at or before
   it) can decide state or be cited. Within the latest capture, any copy (primary, read, regional,
   reporting or failover replica) that is still present counts as present. An empty collection in the
   case's own scoped snapshot proves absence by omission. Workflow results are treated as claims only.
5. **Policy.** Profiles, search entries, exports, contact-index entries and attachments that belong only
   to the subject must be **deleted**. Shared support conversations, email logs and account tombstones
   must be **redacted**, keeping the stable `user_id`. Analytics must be **anonymized**. Security audit
   records and legal holds are **retained**. Backups are retained, but restore access must be blocked.
   Connectors must be disabled.
6. **Planning.** Findings cite the capture that proves the violation. Remediation disables flows and
   blocks restores before changing records. Verification covers every relevant resource's final state.
   Steps are ordered by phase, then by operation in the problem statement's table order, then by
   `system_id` and `resource_id`. COMPLETE cases contain only evidence-backed verification steps.

## Evaluation and usage

- `code/evaluation/evaluation_report.md` has the case, step, field and sequence accuracy, the custom cases,
  and the failures found with the improvements made.
- `code/evaluation/usage_report.md` covers models, calls, tokens and cost of the final full run.

## Packaging

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/.DS_Store"
```

`dataset/`, `.env` and any API keys are never included.

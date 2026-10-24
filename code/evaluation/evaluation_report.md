# Evaluation Report: Ghost Data Still Exists

Author: Pushkar Desai (2024eb02433)

Reproduce with `python3 code/evaluation/main.py`. It runs the real pipeline on the 32 public samples and
on 5 custom cases, and writes the per-case differences to `code/evaluation/last_eval.json`.

## How the metrics are computed

| Metric | Definition |
| --- | --- |
| Case-level status accuracy | Share of cases whose `deletion_status` equals the reference. |
| Step precision / recall / F1 | Each step is the tuple (phase, system_id, resource_id, operation, state, evidence_id). Predicted and reference steps of a case are matched as multisets. |
| Field-level accuracy | Steps aligned by position (step 1 with step 1, and so on); share of reference steps whose field matches. Because it is positional, it also penalizes ordering errors. |
| Sequence accuracy | Share of cases whose status and entire ordered step list are exactly right. |

## Results on the 32 public samples (final run)

| Metric | Value |
| --- | --- |
| Status accuracy | **1.000** (32/32) |
| Step precision | **1.000** |
| Step recall | **0.974** |
| Step F1 | **0.987** |
| Field accuracy (all fields) | 0.962 |
| Field accuracy by field | phase 0.974, system_id 0.953, resource_id 0.953, operation 0.953, state 0.953, evidence_id 0.984 |
| Sequence accuracy | **0.875** (28/32) |

The four cases that are not exact:

| Case | What is missing | Why |
| --- | --- | --- |
| case_18, case_20 | One `VERIFY_RECORD_PRESENT` on a security audit record | `audit_record_6645` and `audit_record_5569` do not appear in any participant-facing file, so no evidence can discover them. |
| case_21 | `VERIFY_RECORD_ANONYMIZED` on `analytics_5335` | The anonymized record carries no identifier. Its workflow event fits two cases equally well (same window, same evidence file, chain residues 1 second from each case), so it is left out rather than guessed. |
| case_04 | Account and analytics verifications | Hand-written case: `account_004` has no evidence or activity anywhere. `analytics_901` is ambiguous with three other cases. |

No predicted step is wrong (precision 1.000); every miss is a record we chose not to attribute.

## Results on the 518 evaluation requests (no reference available)

| Item | Count |
| --- | --- |
| COMPLETE / INCOMPLETE / NOT_APPLICABLE | 153 / 355 / 10 |
| Total steps | 3,195 |
| Resource links from evidence identifiers / workflow attribution / catalog links | 1,448 / 301 / 12 |
| Deletion cases with no account step (attribution ambiguous) | 49 |
| Deletion cases with no security audit step (record not in any file) | 92 |

The 10 non-deletion cases are case_533 to case_542 (phone change, marketing opt-out, data export, login
help, name correction, invoice copy, access request). This matches the 10 `CLASSIFY_REQUEST` activities in
the activity stream. All 518 rows pass the contract validator in `ghostaudit/pipeline.py`.

## Custom evaluation cases

`code/evaluation/custom_cases.py` builds a miniature dataset in the real layout (identities, audit log,
activity, rules, a replica SQL snapshot and two JSON exports) with hand-written expected outputs. All people
and identifiers are fictional.

| Case | Scenario | Trap it tests | Expected |
| --- | --- | --- | --- |
| custom_01 | Request arrives under a historical email. The primary is clean but the read replica still holds the profile. | Historical identity resolution and replication drift. | INCOMPLETE: report, delete, verify `account_9001`; keep the audit record. |
| custom_02 | Account 404 and empty search result in the in-window export; an export captured after `audit_at` shows the search entry again. | Later evidence must not change the answer; a profile linked only by the workflow's deletion event. | COMPLETE with three evidence-backed verifications citing the in-window file. |
| custom_03 | Account tombstone still shows name and email; a legal hold record exists. | Tombstone redaction (not deletion) and retention of the legal hold. | INCOMPLETE: redact tombstone, verify legal hold present. |
| custom_04 | "Please do not delete anything. I only want the phone number on my profile corrected." | Deletion vocabulary in a non-deletion request. | NOT_APPLICABLE, `[]`. |
| custom_05 | Enabled connector and restorable backup for the subject. | Recreation risks and remediation order (disable flow, block restore). | INCOMPLETE with both risks reported and fixed in order. |

Result: **5/5 exact** (status 1.000, step F1 1.000, field 1.000, sequence 1.000).

## Failures found and improvements made

Scores are on the 32 public samples unless noted.

| # | Failure found | Fix | Status acc. | Step F1 | Sequence |
| --- | --- | --- | --- | --- | --- |
| 1 | First end-to-end version. | Parsers, identity resolution, state at `audit_at`, policy, ordering. | 0.906 | 0.896 | 0.438 |
| 2 | Accounts that return 404 and anonymized analytics carry no identifier, so they were never linked. | Attribute the deletion workflow's activity by timing around `reported_at`, and require the claimed status to match the account deletion result (COMPLETE with SUCCESS, NOT_STARTED with FAILED, PARTIALLY_COMPLETE with PARTIAL). | 0.906 | 0.912 | 0.500 |
| 3 | A hand-written case's wide window took another case's account. | Separate windows per event kind (account deletion vs. follow-up actions). | 0.906 | 0.918 | 0.531 |
| 4 | An empty account collection in another batch's snapshot made live accounts look deleted; legacy support contact entries were redacted instead of deleted. | Absence by omission only from the case's own primary capture; support records without conversation content are treated as deletable contact-index entries. | 0.969 | 0.951 | 0.625 |
| 5 | Several cases share the same reporting time, so timing alone could not separate them. | Co-location (the resource must appear in the case's own capture) and the chain signature: one workflow run's events share their seconds modulo 30 after removing each event kind's offset. | 0.969 | 0.963 | 0.688 |
| 6 | Non-deletion requests absorbed workflow candidates. | Classify requests first and exclude non-deletion cases from attribution. | 0.969 | 0.974 | 0.844 |
| 7 | A late capture describing users from a different workflow run linked unrelated accounts to the image-based cases. | Link evidence only from `requested_at` up to 7 days after `audit_at`, and never across another request of the same person. | 0.969 | 0.974 | 0.844 |
| 8 | A file captured before the audit contained a row dated after it (a later FOUND), and `IDENTIFIABLE` verdicts were not treated as exposed PII. | Filter on row time as well as file capture time; treat IDENTIFIABLE as exposed and ANONYMIZED/REDACTED as clean. | unchanged on samples, fixes evaluation-set families without samples | | |
| 9 | Custom case 02 failed: a search query with `hits.total = 0` was read as present. | Read nested hit totals. | custom 0.800 to 1.000 | | |
| 10 | The lite model labeled two sample follow-ups ("my old profile still appears in search", "the privacy page still says my request failed") as non-deletion and overrode the rules. | Explicit deletion wording or explicit refusal is decisive; the model settles only texts with neither signal. Disagreements are logged. | 0.906 back to 0.969 | | |
| 11 | Screenshots and PDFs were not read (rate limits). Once read, a support PDF was labeled as a message, a printed business date put the record outside the case window, and file names became resource ids. | Vision records use the capture time, support records read from a PDF are the attachment itself, catalog-link aliases map printed references (`delivery_confirmation_19.pdf` to `object_19`), and only real resource ids become steps. | **1.000** | **0.987** | **0.875** |

## Known limitations

- 49 evaluation cases have no account step: two or more workflow runs share the reporting window, claim,
  capture and chain residue, so the account cannot be attributed with confidence. Guessing would add a wrong
  step as often as a right one.
- Some retained security audit records exist only in the hidden truth (seen in samples 18 and 20) and cannot be
  recovered from participant files.
- Seven of the fifteen screenshots/PDFs were read through OpenRouter's free router because the Gemini key hit its
  quota. Their extractions were spot-checked against the images (ids, emails and states matched), but a free
  router model is less consistent than the primary model.

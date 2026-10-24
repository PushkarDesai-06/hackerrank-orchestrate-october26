"""Decide whether a request text actually authorizes deletion."""
import re

# Explicit refusals of deletion win over any deletion vocabulary in the text.
NEGATIVE = [
    r"not asking for deletion", r"not a request to (erase|delete)", r"(don't|do not) (delete|close|erase|remove)",
    r"leave (the|my) (account|profile)", r"keep the account", r"continue using", r"still (need|want|use)",
    r"without removing", r"marketing lists only", r"stop the promotional", r"(need|send me|want) a copy", r"download my",
    r"correct it", r"change the email", r"resetting the login", r"out of date",
]
POSITIVE = [
    r"delet", r"eras", r"remov", r"\bclose\b", r"closed", r"suppression", r"supprim", r"exclus", r"elimina",
    r"削除", r"삭제", r"löschen", r"lösch", r"cancel", r"\bgone\b", r"cannot identify me",
]


def rule_signals(text: str) -> tuple[bool, bool]:
    """(explicit refusal of deletion, deletion vocabulary present)."""
    t = text.lower()
    return any(re.search(p, t) for p in NEGATIVE), any(re.search(p, t) for p in POSITIVE)


def rule_classify(text: str) -> bool:
    negative, positive = rule_signals(text)
    return positive and not negative


PROMPT = """You review privacy requests sent to an online shop. For each numbered request decide whether the
customer is authorizing DELETION of their account or personal data (erasure, account closure with data
deletion, or follow-up on a deletion they already asked for). Requests for access, a data copy or export,
correction, email/phone changes, login help, or marketing opt-out are NOT deletion, even if they mention
deleting something they want kept. Requests may be in any language.

Return JSON: {"results": [{"id": <number>, "deletion": true|false, "reason": "<short reason>"}]}

Requests:
"""

SCHEMA = {
    "type": "object",
    "properties": {"results": {"type": "array", "items": {
        "type": "object",
        "properties": {"id": {"type": "integer"}, "deletion": {"type": "boolean"}, "reason": {"type": "string"}},
        "required": ["id", "deletion"]}}},
    "required": ["results"],
}


def classify_requests(texts: list[str], client=None, batch_size: int = 25) -> tuple[dict[str, bool], list[str]]:
    """Return text -> authorizes_deletion, plus notes on rule/LLM disagreements."""
    unique = sorted(set(texts))
    decisions = {t: rule_classify(t) for t in unique}
    notes: list[str] = []
    if client is None:
        return decisions, notes
    for start in range(0, len(unique), batch_size):
        batch = unique[start:start + batch_size]
        body = "\n".join(f"{i + 1}. {t}" for i, t in enumerate(batch))
        try:
            reply = client.generate_json("request_classification", PROMPT + body, schema=SCHEMA)
        except RuntimeError as exc:
            notes.append(f"LLM classification unavailable, using rules: {exc}")
            return decisions, notes
        for item in reply.get("results", []):
            idx = int(item["id"]) - 1
            if not 0 <= idx < len(batch):
                continue
            text = batch[idx]
            llm = bool(item["deletion"])
            negative, positive = rule_signals(text)
            # An explicit refusal or explicit deletion wording is decisive; the
            # model settles only texts where the rules see neither signal.
            if negative or positive:
                if llm != decisions[text]:
                    notes.append(f"kept rules={decisions[text]} over llm={llm}: {text[:90]}")
                continue
            decisions[text] = llm
    return decisions, notes

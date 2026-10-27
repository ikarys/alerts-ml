import json, gzip, re; from datetime import datetime, timedelta, timezone; from collections import deque
# Adjust after reading the "log types" section of report.md.
USEFUL_LOG_PATTERNS = re.compile(r"escalat|assign|takeownership|take ownership|addresponder|add responder|addteam|incident|snooze", re.IGNORECASE)
# Ordered regex replacements to normalize messages into templates.
TEMPLATE_RULES = [
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.IGNORECASE), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", re.IGNORECASE), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b", re.IGNORECASE), "<hex>"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+", re.IGNORECASE), "<email>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?", re.IGNORECASE), "<ts>"),
    (re.compile(r"\d+(?:\.\d+)?", re.IGNORECASE), "<n>"),
]

def template(message: str) -> str:
    s = str(message or "")
    for rx, rep in TEMPLATE_RULES: s = rx.sub(rep, s)
    return re.sub(r"\s+", " ", s).strip().lower()[:120]

def parse_ts(s):
    if not isinstance(s, str): return None
    try: dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError: return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def is_human(actor) -> bool: return isinstance(actor, str) and "@" in actor

def label(alert: dict, activity: dict | None, autoclose_min: float, flap_count: int) -> str:
    r = alert.get("report") or {}
    acked = alert.get("acknowledged") or "ackTime" in r
    human_close = is_human(r.get("closedBy"))
    close_min = r["closeTime"] / 60000 if r.get("closeTime") is not None else None
    activity = activity or {}
    if activity.get("notes"): return "useful"
    if any(USEFUL_LOG_PATTERNS.search(f"{log.get('type') or ''} {log.get('log') or ''}") for log in activity.get("logs") or []): return "useful"
    if acked and human_close: return "useful"
    closed = alert.get("status") == "closed" or close_min is not None
    if (alert.get("count") or 1) >= flap_count or (not acked and closed and not human_close) or (not acked and close_min is not None and close_min <= autoclose_min): return "noise"
    return "ambiguous"

class History:
    def __init__(self): self.times = {}
    def add_and_count(self, key, ts):
        if ts is None: return (0, 0)
        dq = self.times.setdefault(key, deque())
        n1 = sum(ts - p <= timedelta(hours=1) for p in dq)
        n24 = sum(ts - p <= timedelta(hours=24) for p in dq)
        while dq and ts - dq[0] > timedelta(hours=24): dq.popleft()
        dq.append(ts)
        return (n1, n24)

def features(alert: dict, hist: History) -> dict:
    integ = alert.get("integration") or {}
    teams = alert.get("teams") or []
    tpl = template(alert.get("message") or "")
    ts = parse_ts(alert.get("createdAt"))
    if ts is not None:
        hour, weekday = ts.hour, ts.weekday()
        business_hours = 1 if weekday < 5 and 8 <= hour < 19 else 0
        alias_1h, alias_24h = hist.add_and_count("a:" + str(alert.get("alias") or alert.get("id") or ""), ts)
        tpl_1h, tpl_24h = hist.add_and_count("t:" + tpl, ts)
    else:
        hour = weekday = -1
        business_hours = 0
        alias_1h = alias_24h = tpl_1h = tpl_24h = 0
    tags = [str(t).lower() for t in alert.get("tags") or []]
    return {"integration": str(integ.get("type") or "none"), "integration_name": str(integ.get("name") or "none"),
            "source": str(alert.get("source") or "none"), "priority": str(alert.get("priority") or "P3"),
            "team": str(teams[0].get("id") or "none") if teams else "none", "template": tpl,
            "hour": hour, "weekday": weekday, "business_hours": business_hours,
            "alias_1h": alias_1h, "alias_24h": alias_24h, "tpl_1h": tpl_1h, "tpl_24h": tpl_24h,
            "n_tags": len(tags), "tags": tags}

def read_jsonl(path):
    try:
        f = gzip.open(path, "rt", encoding="utf-8") if str(path).endswith(".gz") else open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return
    with f:
        for line in f:
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass

def _selftest():
    t = template("Error 42 ip 10.0.0.1:8080 uuid 123e4567-e89b-12d3-a456-426614174000 at 2026-03-01T10:15:30.123Z")
    assert "<uuid>" in t and "<ip>" in t and "<n>" in t and "<ts>" in t
    assert is_human("a@b.com") and not is_human("Prometheus") and not is_human("")
    assert label({"id": "1", "acknowledged": False, "status": "open", "count": 1, "report": {}}, {"notes": [{"note": "x"}], "logs": []}, 5, 3) == "useful"
    assert label({"id": "2", "acknowledged": False, "status": "closed", "count": 1, "report": {"closeTime": 300000, "closedBy": "Prometheus"}}, None, 5, 3) == "noise"
    assert label({"id": "3", "acknowledged": True, "status": "closed", "count": 1, "report": {"ackTime": 1000, "closeTime": 600000, "closedBy": "Integration"}}, None, 5, 3) == "ambiguous"
    h = History(); base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    h.add_and_count("k", base); h.add_and_count("k", base + timedelta(minutes=10))
    assert h.add_and_count("k", base + timedelta(minutes=20)) == (2, 2)
    assert h.add_and_count("k", base + timedelta(hours=25)) == (0, 0)
    f = features({"id": "1", "message": "Disk 91% on 10.0.0.1", "createdAt": "2026-03-02T10:15:30.123Z", "priority": "P2"}, History())
    assert (f["template"], f["hour"], f["weekday"], f["business_hours"], f["alias_24h"]) == ("disk <n>% on <ip>", 10, 0, 1, 0), f

if __name__ == "__main__": _selftest(); print("features selftest OK")

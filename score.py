import argparse, json, sys
from collections import Counter
from datetime import datetime, timezone
from features import features, History, read_jsonl, parse_ts, label
from analyze import matches, state_text

QUESTION = {"useful": {"type": "noul", "instructions": "Is this monitoring alert actionable, i.e. does it require an on-call engineer to act? Answer no for auto-resolving, repetitive, flapping or informational alerts."}}

def normalize(obj):
    # ponytail: webhook field names from Opsgenie docs, check against one real payload
    if isinstance(obj, dict) and isinstance(obj.get("alert"), dict):
        a = dict(obj["alert"])
        a["id"] = a.get("alertId") or a.get("id")
        if isinstance(a.get("createdAt"), int):
            ms = a["createdAt"]
            dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
            a["createdAt"] = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"
        if not a.get("integration"):
            a["integration"] = {"name": obj.get("integrationName"), "type": obj.get("integrationType")}
        teams = a.get("teams")
        if isinstance(teams, list) and all(isinstance(t, str) for t in teams):
            a["teams"] = [{"id": t} for t in teams]
        return a
    return obj

def make_laya(model, threshold):
    try:
        if model:
            import laya
            agent = laya.load(model, device="cpu")
        else:
            from laya import Router
            agent = Router(device="cpu")
    except ImportError:
        sys.exit("pip install laya (Python 3.10+)")

    def laya_fn(state):
        return agent.predict(state, QUESTION)["answers"]["useful"]["noul"]

    laya_fn.threshold = threshold
    return laya_fn

def decide(f, rules, laya_fn, threshold=None):
    for g in rules.get("guards", []):
        if matches(g, f):
            return {"decision": g["label"], "by": g["id"], "confidence": 1.0, "reason": g.get("description", "")}
    for r in rules.get("rules", []):
        if matches(r, f):
            return {"decision": r["label"], "by": r["id"], "confidence": r.get("precision", 0.0), "reason": r.get("description", "")}
    if laya_fn:
        p = laya_fn(state_text(f))
        if threshold is None:
            threshold = getattr(laya_fn, "threshold", 0.5)
        return {"decision": "useful" if p >= threshold else "noise", "by": "laya",
                "confidence": max(p, 1 - p), "reason": f"laya p_useful={p:.2f}"}
    return {"decision": "unknown", "by": "none", "confidence": 0, "reason": "no rule matched"}

def emit(a, f, d):
    print(json.dumps({"id": a.get("id"), "decision": d["decision"], "by": d["by"],
                      "confidence": d["confidence"], "reason": d["reason"], "template": f.get("template", "")}), flush=True)

def score_alert(a, rules, hist, laya_fn):
    a = normalize(a)
    f = features(a, hist)
    d = decide(f, rules, laya_fn)
    emit(a, f, d)
    return a, f, d

def summary(results, rules):
    print("summary:", file=sys.stderr)
    for k, v in sorted(Counter(d["decision"] for _, _, d in results).items()):
        print(f"decision {k}: {v}", file=sys.stderr)
    for k, v in sorted(Counter(d["by"] for _, _, d in results).items()):
        print(f"by {k}: {v}", file=sys.stderr)

    p = rules.get("params", {})
    table = Counter()
    missed = 0
    for a, _, d in results:
        lab = label(a, None, float(p.get("autoclose_min", 20)), int(p.get("flap_count", 10)))
        table[(d["decision"], lab)] += 1
        if d["decision"] == "noise" and lab == "useful":
            missed += 1

    print("agreement decision vs label:", file=sys.stderr)
    for (dec, lab), n in sorted(table.items()):
        print(f"{dec} vs {lab}: {n}", file=sys.stderr)
    print(f"NOISE-BUT-USEFUL (review these): {missed}", file=sys.stderr)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="out/rules.json")
    ap.add_argument("--replay")
    ap.add_argument("--laya", action="store_true")
    ap.add_argument("--laya-model")
    ap.add_argument("--laya-threshold", type=float, default=0.5)
    args = ap.parse_args()

    try:
        with open(args.rules, encoding="utf-8") as f:
            rules = json.load(f)
    except FileNotFoundError:
        sys.exit(f"missing {args.rules}: run analyze.py first")

    laya_fn = make_laya(args.laya_model, args.laya_threshold) if args.laya else None
    hist = History()

    if args.replay:
        alerts = [normalize(a) for a in read_jsonl(args.replay) or [] if isinstance(a, dict)]
        alerts.sort(key=lambda a: parse_ts(a.get("createdAt")) or datetime.min.replace(tzinfo=timezone.utc))
        results = [score_alert(a, rules, hist, laya_fn) for a in alerts]
        summary(results, rules)
    else:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"warning: malformed stdin line: {e}", file=sys.stderr)
                continue
            if not isinstance(obj, dict):
                print("warning: malformed stdin line: not a JSON object", file=sys.stderr)
                continue
            score_alert(obj, rules, hist, laya_fn)

if __name__ == "__main__":
    main()

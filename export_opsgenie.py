import argparse, gzip, json, os, time, threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib import request, parse
BASE = "https://api.eu.opsgenie.com"
LIMIT = 100
MAX_OFFSET = 20000
def http_get(path, key):
    req = request.Request(BASE + path, headers={"Authorization": f"GenieKey {key}"})
    for attempt in range(8):
        try:
            with request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except request.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                if attempt == 7: raise RuntimeError(f"HTTP {e.code} after retries") from None
                ra = e.headers.get("Retry-After")
                try: delay = float(ra)
                except (TypeError, ValueError): delay = min(2 ** attempt, 30)
                time.sleep(delay); continue
            body = e.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"HTTP {e.code}: {body}") from None
        except request.URLError:
            if attempt == 7: raise
            time.sleep(min(2 ** attempt, 30))
    raise RuntimeError("retries exhausted")
def next_offset(page):
    if not page.get("data") or not (page.get("paging") or {}).get("next"): return None
    return page["data"][-1].get("offset")
def _selftest():
    assert next_offset({"data": [{"offset": "a"}, {"offset": "b"}], "paging": {"next": "x"}}) == "b"
    assert next_offset({"data": [{"offset": "a"}], "paging": {}}) is None
    assert next_offset({"data": [], "paging": {"next": "x"}}) is None
def collect_alerts(start, end, key):
    alerts, offset = [], 0
    query = f"createdAt >= {start} AND createdAt < {end}"
    while offset < MAX_OFFSET:
        params = {"query": query, "limit": LIMIT, "offset": offset, "sort": "createdAt", "order": "asc"}
        data = http_get("/v2/alerts?" + parse.urlencode(params), key).get("data") or []
        if not data: break
        alerts.extend(data); offset += len(data)
        if len(data) < LIMIT: break
    return alerts
def write_alerts(f, alerts, seen, ids):
    n = 0
    for a in alerts:
        aid = a.get("id")
        if aid in seen: continue
        seen.add(aid); ids.append(aid)
        f.write(json.dumps(a, separators=(",", ":")) + "\n"); f.flush(); n += 1
    return n
def fetch_window(start, end, key, f, seen, ids):
    alerts = collect_alerts(start, end, key)
    if len(alerts) == MAX_OFFSET and end - start > 1:
        mid = (start + end) // 2
        return fetch_window(start, mid, key, f, seen, ids) + fetch_window(mid, end, key, f, seen, ids)
    return write_alerts(f, alerts, seen, ids)
def export_alerts(key, out_dir, days):
    os.makedirs(out_dir, exist_ok=True)
    final = os.path.join(out_dir, "alerts.jsonl.gz")
    if os.path.exists(final):  # phase 1 already completed, reuse it
        with gzip.open(final, "rt") as f:
            return [json.loads(line)["id"] for line in f]
    seen, ids = set(), []
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    end = now
    with gzip.open(final + ".tmp", "wt") as f:
        while start < end:
            w_end = min(start + timedelta(days=1), end)
            count = fetch_window(int(start.timestamp() * 1000), int(w_end.timestamp() * 1000), key, f, seen, ids)
            os.write(2, f"{start.date().isoformat()} {count}\n".encode())
            start = w_end
    os.replace(final + ".tmp", final)
    return ids
def fetch_activity(aid, key):
    logs, notes = [], []
    for path, out in (("/logs", logs), ("/notes", notes)):
        offset = None
        while True:
            params = {"identifierType": "id", "limit": LIMIT, "order": "asc"}
            if offset is not None: params["offset"] = offset
            page = http_get(f"/v2/alerts/{aid}{path}?" + parse.urlencode(params), key)
            out.extend(page.get("data") or [])
            offset = next_offset(page)
            if offset is None: break
    return {"id": aid, "logs": logs, "notes": notes}
def export_activity(key, out_dir, ids, workers, skip):
    if skip: return
    path = os.path.join(out_dir, "activity.jsonl")
    done = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                try: done.add(json.loads(line)["id"])
                except Exception: pass
    todo = [i for i in ids if i not in done]
    if not todo: return
    lock = threading.Lock(); state = {"done": 0}; t0 = time.time()
    with open(path, "a", encoding="utf-8") as f:
        if f.tell() and open(path, "rb").read()[-1:] != b"\n": f.write("\n")  # close a partial line
        def work(aid):
            try: obj = fetch_activity(aid, key)
            except Exception as e:
                os.write(2, f"skip {aid}: {e}\n".encode()); return
            line = json.dumps(obj, separators=(",", ":")) + "\n"
            with lock:
                f.write(line); f.flush(); state["done"] += 1
                if state["done"] % 500 == 0:
                    elapsed = time.time() - t0
                    rate = state["done"] / elapsed if elapsed else 0.0
                    os.write(2, f"{state['done']}/{len(todo)} {rate:.1f}/s\n".encode())
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(work, todo))
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--out", default="data")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--skip-logs", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        _selftest(); return
    key = os.environ.get("OPSGENIE_API_KEY")
    if not key:
        os.write(2, b"OPSGENIE_API_KEY is not set\n"); raise SystemExit(1)
    ids = export_alerts(key, args.out, args.days)
    export_activity(key, args.out, ids, args.workers, args.skip_logs)
if __name__ == "__main__":
    main()

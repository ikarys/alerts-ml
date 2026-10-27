import gzip, json, os, random, sys, uuid
from datetime import datetime, timedelta

def ts(d): return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond//1000:03d}Z"
def at(d, ms): return d + timedelta(milliseconds=ms)
def log(o, t, m, d): return {"log": m, "type": t, "owner": o, "createdAt": ts(d)}
def note(o, m, d): return {"note": m, "owner": o, "createdAt": ts(d)}

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fake_data"
    os.makedirs(out, exist_ok=True); random.seed(0)
    end = datetime(2026, 10, 1, 23, 59, 59, 999000); start = end - timedelta(days=365)
    alerts = []
    kinds = [1] * 2400 + [2] * 900 + [3] * 1200 + [4] * 900 + [5] * 600; random.shuffle(kinds)
    for k in kinds:
        c = start + timedelta(seconds=random.uniform(0, (end - start).total_seconds()))
        i = uuid.uuid4().hex; team = f"team-{random.randint(1, 5)}"
        if k == 1:
            n = random.randint(1, 20); node = random.randint(1, 100)
            alias, msg = f"cpu-node-{n}", f"CPU high on node-{node} value {random.uniform(80, 100):.2f}"
            prio, tags, src, integ = "P3", ["cpu", "k8s"], "prometheus", {"id": "int-prom", "name": "prom-prod", "type": "Prometheus"}
            ack, cnt, close = False, random.randint(1, 3), random.randint(300_000, 900_000)
            rep = {"closeTime": close, "closedBy": "Prometheus"}
            logs = [log("system", "system", "Alert created", c), log("Prometheus", "close", "Alert closed by Prometheus", at(c, close))]
            notes = []
        elif k == 2:
            a, b = random.randint(0, 255), random.randint(0, 255)
            alias, msg = f"disk-latency-{a}-{b}", f"Disk latency {random.uniform(100, 5000):.1f} ms on 10.0.{a}.{b}"
            prio, tags, src, integ = "P4", ["disk"], "datadog", {"id": "int-dd", "name": "dd-flappy", "type": "Datadog"}
            ack, cnt, close = False, random.randint(12, 40), random.randint(3_600_000, 10_800_000)
            rep = {"closeTime": close, "closedBy": "Datadog"}
            logs = [log("system", "system", "Alert created", c), log("Datadog", "close", "Alert closed by Datadog", at(c, close))]
            notes = []
        elif k == 3:
            db = random.randint(1, 3)
            alias, msg = f"db-repl-lag-{db}", f"Database replication lag {random.randint(30, 300)}s on db-{db}"
            prio, tags, src, integ = "P2", ["database"], "prometheus", {"id": "int-prom", "name": "prom-prod", "type": "Prometheus"}
            ack, cnt = True, random.randint(1, 5)
            ack_ms, close = random.randint(120_000, 600_000), random.randint(1_800_000, 5_400_000)
            rep = {"ackTime": ack_ms, "acknowledgedBy": "alice@corp.com", "closeTime": close, "closedBy": "alice@corp.com"}
            logs = [log("system", "system", "Alert created", c), log("alice@corp.com", "acknowledge", "acked by alice", at(c, ack_ms))]
            if random.random() < .5: logs.append(log("alice@corp.com", "escalate", "Escalated to DBA", at(c, ack_ms + 60_000)))
            logs.append(log("alice@corp.com", "close", "Alert closed by alice", at(c, close)))
            notes = [note("alice@corp.com", "restarted replica", at(c, close + 60_000))] if random.random() < .4 else []
        elif k == 4:
            api = random.randint(1, 20)
            alias, msg = f"http-5xx-api-{api}", f"HTTP 5xx rate {random.uniform(1, 20):.2f}% on api-{api}"
            prio, tags, src, integ = "P3", ["http"], "datadog", {"id": "int-dd-app", "name": "dd-app", "type": "Datadog"}
            ack, cnt = True, random.randint(1, 10)
            ack_ms, close = random.randint(60_000, 300_000), random.randint(600_000, 1_800_000)
            rep = {"ackTime": ack_ms, "acknowledgedBy": "bob@corp.com", "closeTime": close, "closedBy": "Datadog"}
            logs = [log("bob@corp.com", "acknowledge", "acked by bob", at(c, ack_ms)), log("Datadog", "close", "Alert closed by Datadog", at(c, close))]
            notes = []
        else:
            o = uuid.uuid4().hex
            alias, msg = f"payment-timeout-{o[:8]}", f"Payment gateway timeout order {o}"
            prio, tags, src, integ = "P1", ["payments"], "custom", {"id": "int-api", "name": "custom-api", "type": "API"}
            cnt = random.randint(1, 2)
            if random.random() < .5:
                ack = True; ack_ms, close = random.randint(60_000, 600_000), random.randint(900_000, 7_200_000)
                rep = {"ackTime": ack_ms, "acknowledgedBy": "carol@corp.com", "closeTime": close, "closedBy": "carol@corp.com"}
                logs = [log("system", "system", "Alert created", c), log("carol@corp.com", "acknowledge", "acked by carol", at(c, ack_ms)), log("carol@corp.com", "close", "Alert closed by carol", at(c, close))]
                notes = [note("carol@corp.com", "investigating payment gateway", at(c, ack_ms + 120_000))]
            else:
                ack = False; close = 180_000
                rep = {"closeTime": close, "closedBy": "API"}
                logs = [log("system", "system", "Alert created", c), log("API", "close", "Alert closed by API", at(c, close))]
                notes = []
        alerts.append({"id": i, "alias": alias, "message": msg, "tags": tags, "count": cnt, "createdAt": ts(c),
                       "source": src, "priority": prio, "teams": [{"id": team}], "integration": integ,
                       "acknowledged": ack, "status": "closed", "report": rep, "_logs": logs, "_notes": notes})
    random.shuffle(alerts)
    with gzip.open(os.path.join(out, "alerts.jsonl.gz"), "wt", encoding="utf-8") as f:
        for a in alerts: f.write(json.dumps({k: v for k, v in a.items() if not k.startswith("_")}) + "\n")
    with open(os.path.join(out, "activity.jsonl"), "wt", encoding="utf-8") as f:
        for a in random.sample(alerts, int(len(alerts) * .9)): f.write(json.dumps({"id": a["id"], "logs": a["_logs"], "notes": a["_notes"]}) + "\n")
        f.write('{"id": "broken\n')

if __name__ == "__main__": main()

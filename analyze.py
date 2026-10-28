import argparse, itertools, json, os, re, sys
from datetime import datetime, timezone
from collections import Counter
from features import History, features, label, parse_ts, read_jsonl

def state_text(f):
    tags = ",".join(f.get("tags") or [])
    return (f"integration={f.get('integration_name', 'none')} source={f.get('source', 'none')} "
            f"priority={f.get('priority', 'P3')} team={f.get('team', 'none')} hour={f.get('hour', -1)} "
            f"business_hours={f.get('business_hours', 0)} alias_24h={f.get('alias_24h', 0)} "
            f"tpl_24h={f.get('tpl_24h', 0)} tags={tags} message={f.get('template', '')}")

def matches(rule, row):
    for c in rule["when"]:
        f, op, v = c["feature"], c["op"], c.get("value")
        if f == "tag":
            tags = row.get("tags") or []
            if op == "has" and v not in tags: return False
            if op == "not_has" and v in tags: return False
            if op == "eq" and v not in tags: return False
            if op == "ne" and v in tags: return False
            if op == "in" and not any(x in tags for x in v): return False
        else:
            x = row.get(f)
            if op == "eq" and x != v: return False
            if op == "ne" and x == v: return False
            if op == "in" and x not in v: return False
            if op == "regex" and not re.fullmatch(v, str(x or "")): return False
            if op == "le" and not (x is not None and x <= v): return False
            if op == "gt" and not (x is not None and x > v): return False
    return True

def cond_text(c):
    f, op, v = c["feature"], c["op"], c.get("value")
    if f == "tag":
        if op == "has": return f"has tag {v}"
        if op == "not_has": return f"no tag {v}"
        if op == "in": return f"tag in {v}"
    if op == "eq": return f"{f} = {v}"
    if op == "ne": return f"{f} != {v}"
    if op == "in": return f"{f} in {v}"
    if op == "regex": return f"{f} ~= {v}"
    if op == "le": return f"{f} <= {v}"
    if op == "gt": return f"{f} > {v}"
    return f"{f} {op} {v}"

def rule_description(conds):
    return " AND ".join(cond_text(c) for c in conds) if conds else "all"

def simplify(conds):
    eq = {c["feature"] for c in conds if c["op"] == "eq"}
    le, gt, out = {}, {}, []
    for c in conds:
        f = c["feature"]
        if c["op"] == "ne" and f in eq: continue
        if c["op"] == "le": le[f] = min(le.get(f, 1e18), c["value"])
        elif c["op"] == "gt": gt[f] = max(gt.get(f, -1e18), c["value"])
        else: out.append(c)
    out += [{"feature": f, "op": "le", "value": v} for f, v in le.items()]
    out += [{"feature": f, "op": "gt", "value": v} for f, v in gt.items()]
    return out

def to_md(df):
    if df is None or len(df) == 0: return "_none_"
    cols = list(df.columns)
    lines = ["| " + " | ".join(map(str, cols)) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(f"{x:.3f}" if isinstance(x, float) else str(x) for x in r.tolist()) + " |")
    return "\n".join(lines)

def volume_table(df, cols, top=None):
    g = df.groupby(cols, dropna=False).size().reset_index(name="n")
    lab = df[df["label"].isin(["noise", "useful"])].groupby(cols, dropna=False)["label"].apply(
        lambda s: (s == "noise").sum() / len(s) if len(s) else None).reset_index(name="noise_rate")
    t = g.merge(lab, on=cols, how="left").sort_values("n", ascending=False)
    return t.head(top) if top else t

def template_family_candidates(templates, max_vars=2):
    groups = {}
    for tpl in templates:
        parts = str(tpl).split("-")
        if len(parts) < 5: continue
        for nvars in range(1, min(max_vars, len(parts) - 4) + 1):
            for idxs in itertools.combinations(range(len(parts)), nvars):
                key = tuple("<var>" if i in idxs else p for i, p in enumerate(parts))
                groups.setdefault(key, set()).add(tpl)
    out = []
    for key, vals in groups.items():
        if len(vals) < 2: continue
        var_positions = [i for i, p in enumerate(key) if p == "<var>"]
        if any(len({str(v).split("-")[i] for v in vals}) < 2 for i in var_positions): continue
        regex = "-".join("[^-]+" if p == "<var>" else re.escape(p) for p in key)
        out.append((key.count("<var>"), -len(vals), regex, vals))
    return sorted(out)

def _selftest():
    vals = ["azure - platform: sql-deadlocks-detected-sqlserver-prd-commun-primary-rundeck",
            "azure - platform: sql-deadlocks-detected-sqlserver-prp-commun-primary-rundeck"]
    _, _, rx, grouped = template_family_candidates(vals)[0]
    assert set(grouped) == set(vals)
    assert matches({"when": [{"feature": "template", "op": "regex", "value": rx}]}, {"template": vals[0]})

def evaluate_rules(rules, rows):
    assigned = [None] * len(rows)
    metrics = {}
    for rule in rules:
        support = correct = missed = 0
        for i, row in enumerate(rows):
            if assigned[i] is None and matches(rule, row):
                assigned[i] = rule["id"]
                support += 1
                if row["label"] == rule["label"]: correct += 1
                if rule["label"] == "noise" and row["label"] == "useful": missed += 1
        metrics[rule["id"]] = (support, correct / support if support else 0.0, missed)
    return metrics, assigned

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data"); ap.add_argument("--out", default="out")
    ap.add_argument("--autoclose-min", type=float, default=20); ap.add_argument("--flap-count", type=int, default=10)
    ap.add_argument("--test-days", type=int, default=60); ap.add_argument("--min-precision", type=float, default=0.95)
    ap.add_argument("--min-support", type=int, default=30); ap.add_argument("--max-depth", type=int, default=5)
    ap.add_argument("--top-tags", type=int, default=30)
    ap.add_argument("--max-ambiguous", type=float, default=0.3,
                    help="drop rules whose matched train alerts are more than this share ambiguous (acked, then auto-closed)")
    args = ap.parse_args()
    import pandas as pd
    from sklearn.tree import DecisionTreeClassifier

    data, out = args.data, args.out
    activity_path = f"{data}/activity.jsonl"
    activity = {}
    if not os.path.exists(activity_path):
        print(f"warning: {activity_path} missing", file=sys.stderr)
    else:
        for rec in read_jsonl(activity_path) or []:
            if isinstance(rec, dict) and rec.get("id"): activity[rec["id"]] = rec

    alerts = list(read_jsonl(f"{data}/alerts.jsonl.gz") or [])
    if not alerts: sys.exit(f"No alerts found in {data}/alerts.jsonl.gz")
    alerts.sort(key=lambda a: str(a.get("createdAt") or ""))
    hist = History()
    rows = []
    for a in alerts:
        f = features(a, hist)
        rows.append({"id": a.get("id"), "created": parse_ts(a.get("createdAt")),
                     "label": label(a, activity.get(a.get("id")), args.autoclose_min, args.flap_count), **f})
    df = pd.DataFrame(rows)
    df["created"] = pd.to_datetime(df["created"], errors="coerce")
    created = df["created"].dropna()
    max_created = created.max() if not created.empty else None
    if max_created is None:
        test_mask = pd.Series(False, index=df.index)
    else:
        test_mask = df["created"] >= max_created - pd.Timedelta(days=args.test_days)
    labeled = df["label"].isin(["noise", "useful"])
    train = df[labeled & ~test_mask]
    test = df[labeled & test_mask]
    if train.empty: sys.exit("No labeled training alerts")

    guards = [{"id": "G1", "when": [{"feature": "priority", "op": "in", "value": ["P1"]}],
               "label": "useful", "description": "P1 alerts are never classified as noise"}]
    period = df[~test_mask]
    amb_share = (period["label"] == "ambiguous").groupby(period["template"]).mean()
    family_rules = []
    for _, _, pattern, vals in template_family_candidates(train["template"].dropna().unique()):
        rule = {"when": [{"feature": "template", "op": "regex", "value": pattern}]}
        g = train[train.apply(lambda r: matches(rule, r), axis=1)]
        n = len(g)
        if n < args.min_support: continue
        cnt = g["label"].value_counts()
        lab, c = cnt.idxmax(), int(cnt.max())
        amb = period[period.apply(lambda r: matches(rule, r), axis=1)]
        if len(amb) and (amb["label"] == "ambiguous").mean() > args.max_ambiguous: continue
        if c / n >= args.min_precision:
            family_rules.append({"id": f"F{len(family_rules) + 1}", "when": [{"feature": "template", "op": "regex", "value": pattern}],
                                 "label": lab, "precision": c / n, "support": n, "origin": "template_family",
                                 "description": f"template ~= {pattern}"})

    tpl_rules = []
    for tpl, g in train.groupby("template"):
        if amb_share.get(tpl, 0) > args.max_ambiguous: continue
        if any(matches(rule, {"template": tpl}) for rule in family_rules): continue
        n = len(g)
        if n < args.min_support: continue
        cnt = g["label"].value_counts()
        lab, c = cnt.idxmax(), int(cnt.max())
        if c / n >= args.min_precision:
            tpl_rules.append({"id": f"T{len(tpl_rules) + 1}", "when": [{"feature": "template", "op": "eq", "value": tpl}],
                              "label": lab, "precision": c / n, "support": n, "origin": "template",
                              "description": f"template = {tpl}"})

    tree_rules = []
    unmatched = train[~train.apply(lambda r: any(matches(rule, r) for rule in family_rules + tpl_rules), axis=1)]
    if len(unmatched) >= args.min_support:
        top_tpl = unmatched["template"].value_counts().head(200).index
        cat = unmatched[["integration", "integration_name", "source", "priority", "team"]].copy()
        cat["template"] = unmatched["template"].where(unmatched["template"].isin(top_tpl), "<other>")
        X = pd.get_dummies(cat, prefix=["integration", "integration_name", "source", "priority", "team", "template"], prefix_sep="=")
        tag_counts = Counter(t for tags in unmatched["tags"] for t in tags)
        top_tags = [t for t, _ in tag_counts.most_common(args.top_tags)]
        if top_tags:
            tags = pd.DataFrame([{"tag=" + t: 1 if t in tags else 0 for t in top_tags} for tags in unmatched["tags"]],
                                index=unmatched.index)
        else:
            tags = pd.DataFrame(index=unmatched.index)
        num = unmatched[["hour", "weekday", "business_hours", "alias_1h", "alias_24h", "tpl_1h", "tpl_24h", "n_tags"]]
        X = pd.concat([X, tags, num], axis=1).fillna(0).astype(float)
        y = unmatched["label"]
        clf = DecisionTreeClassifier(max_depth=args.max_depth, min_samples_leaf=args.min_support,
                                     class_weight="balanced", random_state=0).fit(X, y)
        t = clf.tree_
        leaf_counts = pd.crosstab(clf.apply(X), y.values)  # raw train counts per leaf
        amb_rows = period[period["label"] == "ambiguous"].to_dict("records")
        stack = [(0, [])]
        while stack:
            node, conds = stack.pop()
            if t.feature[node] == -2:
                counts = leaf_counts.loc[node]
                total = int(counts.sum())
                if total < args.min_support: continue
                lab = str(counts.idxmax())
                prec = float(counts.max() / total)
                if prec < args.min_precision: continue
                conds = simplify(conds)
                n_amb = sum(1 for r in amb_rows if matches({"when": conds}, r))
                if n_amb / (n_amb + total) > args.max_ambiguous: continue
                tree_rules.append({"id": f"R{len(tree_rules) + 1}", "when": conds, "label": lab, "precision": prec,
                                   "support": total, "origin": "tree", "description": rule_description(conds)})
            else:
                name = X.columns[t.feature[node]]
                thr = float(t.threshold[node])
                if name.startswith("tag="):
                    tag = name[4:]
                    left = {"feature": "tag", "op": "not_has", "value": tag}
                    right = {"feature": "tag", "op": "has", "value": tag}
                elif "=" in name:
                    feat, val = name.split("=", 1)
                    left = {"feature": feat, "op": "ne", "value": val}
                    right = {"feature": feat, "op": "eq", "value": val}
                else:
                    left = {"feature": name, "op": "le", "value": thr}
                    right = {"feature": name, "op": "gt", "value": thr}
                stack.append((t.children_left[node], conds + [left]))
                stack.append((t.children_right[node], conds + [right]))

    rules = family_rules + tpl_rules + tree_rules
    test_rows = test.to_dict("records")
    metrics, _ = evaluate_rules(guards + rules, test_rows)
    for r in rules:
        s, p, m = metrics[r["id"]]
        r["test_support"], r["test_precision"], r["test_missed_useful"] = s, p, m
    dropped_ids = {r["id"] for r in rules if r["test_support"] >= 10 and r["test_precision"] < args.min_precision - 0.05}
    for r in rules:
        if r["id"] in dropped_ids: print(f"Dropped {r['id']} {r['description']}")
    final_rules = [r for r in rules if r["id"] not in dropped_ids]
    metrics, assigned = evaluate_rules(guards + final_rules, test_rows)
    for r in final_rules:
        s, p, m = metrics[r["id"]]
        r["test_support"], r["test_precision"], r["test_missed_useful"] = s, p, m

    os.makedirs(out, exist_ok=True)
    rules_path = f"{out}/rules.json"
    with open(rules_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "params": vars(args),
                   "guards": guards, "rules": final_rules}, f, indent=2)

    laya_path = f"{out}/laya_train.jsonl"
    with open(laya_path, "w", encoding="utf-8") as f:
        for _, row in df[labeled].iterrows():
            f.write(json.dumps({"state": state_text(row.to_dict()), "label": row["label"]}) + "\n")

    report = ["# alerts-ml report",
              "How to read this report: labels are learned from alert outcomes, while rules use only creation-time features. "
              "Noise rate is noise divided by noise plus useful. Test coverage shows how many recent labeled alerts the final rules match. "
              "The false-negative table lists useful alerts that a noise rule would suppress, so review those first.",
              "## Volume"]
    min_c = created.min() if not created.empty else None
    report.append(f"- Alerts: {len(df)}")
    report.append(f"- Date range: {min_c} to {max_created}")
    lab_counts = df["label"].value_counts()
    for lab in ["noise", "useful", "ambiguous"]:
        n = int(lab_counts.get(lab, 0))
        report.append(f"- {lab}: {n} ({n / len(df):.1%})")
    report.append(f"- Activity coverage: {df['id'].isin(activity).mean() * 100:.1f}%")

    report += ["## Noise rate by integration", to_md(volume_table(df, "integration_name", 30)),
               "## Noise rate by priority", to_md(volume_table(df, "priority", 30)),
               "## Noise rate by integration x priority", to_md(volume_table(df, ["integration_name", "priority"], 30))]

    tpl_tbl = df.groupby(["template", "integration_name"], dropna=False).agg(n=("id", "count")).reset_index()
    lab = df[df["label"].isin(["noise", "useful"])].groupby(["template", "integration_name"], dropna=False)["label"].apply(
        lambda s: (s == "noise").sum() / len(s) if len(s) else None).reset_index(name="noise_rate")
    amb = df[df["label"] == "ambiguous"].groupby(["template", "integration_name"], dropna=False).size().reset_index(name="amb")
    tpl_tbl = tpl_tbl.merge(lab, on=["template", "integration_name"], how="left").merge(amb, on=["template", "integration_name"], how="left")
    tpl_tbl["amb"] = tpl_tbl["amb"].fillna(0)
    tpl_tbl["ambiguous_share"] = tpl_tbl["amb"] / tpl_tbl["n"]
    tpl_tbl = tpl_tbl.sort_values("n", ascending=False).head(40)
    report += ["## Top templates", to_md(tpl_tbl)]

    log_counts, log_example = Counter(), {}
    for act in activity.values():
        for log in act.get("logs") or []:
            typ = str(log.get("type") or "none")
            log_counts[typ] += 1
            log_example.setdefault(typ, str(log.get("log") or "")[:100])
    log_rows = [{"type": t, "count": c, "example": log_example[t]} for t, c in log_counts.most_common(30)]
    log_tbl = pd.DataFrame(log_rows) if log_rows else pd.DataFrame()
    report += ["## Log types", to_md(log_tbl)]

    rules_tbl = pd.DataFrame(final_rules)
    if not rules_tbl.empty:
        rules_tbl = rules_tbl[["id", "origin", "label", "description", "precision", "support",
                               "test_precision", "test_support", "test_missed_useful"]]
    report += ["## Rules", to_md(rules_tbl)]

    rule_by_id = {r["id"]: r for r in guards + final_rules}
    n_test = len(test_rows)
    noise_matched = sum(1 for rid in assigned if rid and rule_by_id[rid]["label"] == "noise")
    any_matched = sum(1 for rid in assigned if rid)
    total_missed = sum(r.get("test_missed_useful", 0) for r in final_rules)
    fn = [{"id": row.get("id"), "template": row.get("template"), "rule": assigned[i]}
          for i, row in enumerate(test_rows)
          if row["label"] == "useful" and assigned[i] and rule_by_id[assigned[i]]["label"] == "noise"]
    fn_tbl = pd.DataFrame(fn[:20]) if fn else pd.DataFrame()
    report += ["## Test coverage",
               f"- Labeled test alerts: {n_test}",
               f"- Matched by noise rule: {noise_matched / n_test:.1%}" if n_test else "- Matched by noise rule: 0.0%",
               f"- Matched by any rule: {any_matched / n_test:.1%}" if n_test else "- Matched by any rule: 0.0%",
               f"- Total test_missed_useful: {total_missed}",
               "### Useful alerts matched by noise rules", to_md(fn_tbl)]

    report_path = f"{out}/report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report))

    print(f"alerts={len(df)} train={len(train)} test={n_test} ambiguous={int((df['label'] == 'ambiguous').sum())}")
    print(f"rules={len(final_rules)} family={len(family_rules)} template={len(tpl_rules)} tree={len(tree_rules)}")
    if n_test:
        print(f"test coverage any={any_matched / n_test:.1%} noise={noise_matched / n_test:.1%} missed_useful={total_missed}")
    else:
        print("test coverage: no labeled test alerts")
    print(f"wrote {rules_path}, {laya_path}, {report_path}")

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest(); print("analyze selftest OK")
    else:
        main()

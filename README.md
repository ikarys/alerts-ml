# alerts-ml

Classify Opsgenie alert history into noise vs useful and extract simple real-time rules.

## 1. Install

Python 3.10+. Run `pip install -r requirements.txt` (pandas, scikit-learn). Laya optional: `pip install laya`.

## 2. Export

Opsgenie API key with Read access (Settings > API key management), EU domain (`api.eu.opsgenie.com`). Provide via env var `OPSGENIE_API_KEY`, never committed.

Windows PowerShell:

```powershell
$env:OPSGENIE_API_KEY = "..."
```

Linux/macOS:

```bash
export OPSGENIE_API_KEY=...
```

Phase 1 only (fast, gives the volume):

```bash
python export_opsgenie.py --skip-logs
```

Full run (logs + notes, resumable, just re-run after an interruption):

```bash
python export_opsgenie.py --workers 4
```

Options: `--days` (default 365), `--out` (default data), `--workers` (default 4), `--skip-logs`, `--selftest`.

Outputs: `data/alerts.jsonl.gz` (one alert per line: priority, source, integration, tags, teams, report with ack/close times and actors), `data/activity.jsonl` (logs and notes per alert id).

Warning: `data/` contains company data, it is git-ignored and must never be committed or uploaded.

Note: phase 2 makes at least 2 API calls per alert; 429 rate limits are retried with backoff.

## 3. Smoke test

```bash
python make_fake_data.py fake_data
python analyze.py --data fake_data --out out_fake
python score.py --rules out_fake/rules.json --replay fake_data/alerts.jsonl.gz
```

`python features.py` also runs a self-test.

## 4. Analyze

```bash
python analyze.py --data data --out out
```

Writes `out/report.md`, `out/rules.json`, `out/laya_train.jsonl`. All `out/` files contain company data: never commit.

Options:

| Option | Default | Meaning |
|---|---:|---|
| `--autoclose-min` | 20 | Unacked alert closed by source within N minutes is noise |
| `--flap-count` | 10 | Alert count at/above this is flapping noise |
| `--test-days` | 60 | Most recent days held out to test rules |
| `--min-precision` | 0.95 | Minimum rule precision on training data |
| `--min-support` | 30 | Minimum number of alerts for a rule |
| `--max-depth` | 5 | Decision tree max depth |
| `--top-tags` | 30 | Maximum tags considered |
| `--max-ambiguous` | 0.3 | Refuse rules whose alerts are mostly ambiguous |

## 5. Labels

Labels come from alert outcomes:

- Useful: a note exists, a log shows escalation/assignment/responder/incident (`USEFUL_LOG_PATTERNS` in `features.py`), or acked and closed by a human.
- Noise: count >= `--flap-count`, not acked and closed by a non-human (integration/system), or not acked and closed within `--autoclose-min`.
- Ambiguous: everything else, typically acked to silence the pager then auto-closed. Ambiguous alerts are excluded from training.

Rules use only creation-time features: integration, source, priority, team, message template, hour, weekday, business hours, repeats of same alias/template in last 1h/24h, tags. This allows real-time scoring.

## 6. Reading `report.md`

1. Check label shares and activity coverage.
2. Read "Log types". If real human actions are missed, adjust `USEFUL_LOG_PATTERNS` in `features.py`, then re-run `analyze.py`.
3. Noise rate by integration/priority shows where noise comes from. Worst templates are candidates to fix at the source (thresholds, alert definitions), which beats filtering.
4. Rules table shows precision/support on train and `test_precision`/`test_support`/`test_missed_useful` on held-out recent period.
5. "Useful alerts matched by noise rules" are false negatives. Review every one and tighten parameters (raise `--min-precision`, lower `--max-ambiguous`) until acceptable.

## 7. Scoring

`score.py` decision order:

1. Guards: G1: P1 always useful.
2. Rules in order; first match wins.
3. Optional Laya for alerts no rule matches.
4. Otherwise `unknown`.

Input: stdin JSON lines, either exported alerts or Opsgenie webhook payloads; or `--replay FILE`.

Output: one JSON line per alert: `{id, decision, by, confidence, reason, template}` where `decision` is `noise`, `useful`, or `unknown`, and `by` is rule id, `G1`, `laya`, or `none`.

`score.py` keeps repeat counters in memory, so run it as one long-lived process (stdin pipe) for real-time use.

Replaying the training period gives optimistic numbers; replay a recent period exported after the analysis. Webhook field names are unverified: check against one real Opsgenie webhook payload first.

## 8. Laya

Rules first: `rules.json` is deterministic, auditable, microsecond-fast, and measured on held-out data. Laya is a classifier (ModernBERT, single forward pass, returns a probability), not an instruction-following LLM. You do not give it the rules as a prompt. Its docs report near-chance zero-shot accuracy on custom decisions and recommend fine-tuning. Rules decide what they cover; Laya only scores the remainder (`unknown`).

Laya runs on CPU. Its README reports ~450 ms for 4 questions on a 28-thread CPU; expect roughly 0.1-1 s per alert on a laptop CPU, around 2 GB RAM per 421M-parameter checkpoint, Python 3.10+. First use downloads the checkpoint from Hugging Face (needs network access), or point `--laya-model` to a local checkpoint directory for offline use.

Usage: `python score.py --rules out/rules.json --laya` (base model) or `python score.py --rules out/rules.json --laya-model PATH --laya-threshold 0.5` (fine-tuned).

Fine-tuning: `out/laya_train.jsonl` contains one `{"state", "label"}` per labeled alert in the same text format `score.py` sends to Laya. Fine-tuning needs a GPU (Laya's notebook: hours on 2x T4) and data must stay inside the company, so do it only on an internal GPU machine. Until then, run Laya zero-shot in shadow mode only and compare with labels.

## 9. Rollout

Recommended:

1. Shadow mode: score and log, change nothing, for 2-4 weeks.
2. Count NOISE-BUT-USEFUL cases.
3. Act softly first: tag or lower priority in Opsgenie, never delete.
4. Suppress only with rules whose `test_precision >= 0.99` and real-world shadow results agree.
5. Re-run `analyze.py` monthly, since noise drifts with deployments. Never suppress P1.

## 10. Files

- `export_opsgenie.py`: export alerts and activity from Opsgenie.
- `features.py`: creation-time features and label patterns.
- `analyze.py`: label alerts, measure noise, extract rules.
- `score.py`: score alerts in real time or replay mode.
- `make_fake_data.py`: generate fake data for smoke tests.
- `requirements.txt`: Python dependencies.- `requirements.txt`: pandas, scikit-learn (laya optional).

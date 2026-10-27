# alerts-ml

Classify 12 months of Opsgenie alert history into noise vs useful, then extract simple rules for a real-time scoring system.

Current content: one script `export_opsgenie.py` (Python 3.8+, standard library only, no pip install needed).

## Next steps

- Label alerts from activity logs
- Noise rate by integration/priority/message template
- Rule extraction

## Usage

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

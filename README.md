# AI-Driven Cloud SOC — Data Generation Pipeline

**Region:** ap-south-1 (Mumbai) | **Account:** 911234567890 (simulated)  
**Date range:** 2026-02-15 → 2026-03-01 (14 days)

---

## Project Structure

```
soc-project/
├── config/
│   └── simulation_config.yaml     ← All tunable parameters
├── data_generation/
│   ├── event_templates.py         ← CloudTrail JSON templates (per AWS docs)
│   ├── temporal_engine.py         ← IST business hours timestamp generation
│   ├── normal_traffic_generator.py← Per-persona realistic traffic
│   ├── attack_injector.py         ← 5 attack scenarios
│   └── log_writer.py              ← Gzip CloudTrail file writer
├── data_ingestion/
│   ├── log_reader.py              ← Read local .json.gz files
│   ├── normalizer.py              ← Flatten nested CloudTrail JSON → DataFrame
│   └── parquet_store.py           ← Read/write Parquet files
├── feature_engineering/
│   ├── window_aggregator.py       ← 5-min, 1-hr, daily rolling features
│   ├── feature_builder.py         ← Final ML feature matrix
│   └── label_generator.py         ← Ground truth label files
├── models/                        ← (next phase) IF, LOF, Autoencoder
├── rag_ingestion/
│   └── parquet_to_rag.py          ← ChromaDB + Neo4j ingestion
├── aws_connector/
│   └── s3_cloudtrail_reader.py    ← Real AWS S3 drop-in adapter
├── data/
│   ├── raw/                       ← Generated .json.gz CloudTrail files
│   ├── normalized/                ← events.parquet, events_labeled.parquet
│   ├── features/                  ← feature_matrix.parquet
│   └── labels/                    ← event_labels.jsonl, window_labels.csv
├── ground_truth/
│   └── attack_manifest.json       ← Attack scenario metadata + timestamps
├── requirements.txt
└── run_pipeline.py                ← Master orchestrator
```

---

## Setup

```bash
# 1. Clone / navigate to project
cd soc-project

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux/Mac
# venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Run Order

### Full pipeline (recommended first run)
```bash
python run_pipeline.py
```

This runs all 3 stages sequentially:
1. **Generate** — creates ~18,000 CloudTrail events across 14 days, injects 5 attacks, writes gzip log files
2. **Ingest** — reads gzip files, flattens JSON, writes Parquet
3. **Features** — computes 5-min and 1-hour window features, builds ML matrix

### Individual stages
```bash
python run_pipeline.py --stage generate   # Only raw log generation
python run_pipeline.py --stage ingest     # Only normalization
python run_pipeline.py --stage features   # Only feature engineering
```

### Dry run (inspect config)
```bash
python run_pipeline.py --dry-run
```

---

## Output Files

| File | Description | Used By |
|------|-------------|---------|
| `data/raw/AWSLogs/.../*.json.gz` | Native CloudTrail format | Log reader |
| `data/normalized/events.parquet` | Flat normalized events | Feature engineering |
| `data/normalized/events_labeled.parquet` | Events + attack labels | Model evaluation |
| `data/features/feature_matrix.parquet` | ML-ready feature matrix (43 features) | Models |
| `data/labels/window_labels.csv` | Per-window ground truth labels | Evaluation |
| `data/labels/event_labels.jsonl` | Per-event attack labels | RAG, analysis |
| `ground_truth/attack_manifest.json` | Attack scenario timestamps | Paper, analysis |

---

## Attack Scenarios

| # | Name | Actor | When (IST) | Pattern |
|---|------|-------|------------|---------|
| 1 | Privilege Escalation | alice-dev | 2026-02-17 02:00 AM | IAM write burst at 2 AM |
| 2 | Data Exfiltration | eve-analyst | 2026-02-23 to 2026-02-25 | Gradual S3 volume ramp (50%→100%→200%) |
| 3 | Insider Threat | bob-devops | 2026-02-27 04:45 PM | Mass DeleteObjects + DeleteBucket |
| 4 | Reconnaissance | eve-analyst | 2026-02-18 to 2026-02-20 | IAM List* from non-IAM user |
| 5 | Backdoor Creation | eve-analyst | 2026-02-25 03:15 AM | CreateLoginProfile + CreateAccessKey for admin |

---

## Features (43 total)

**5-minute raw counts:** total_events, iam_events, s3_events, write_events, s3_get_events, s3_delete_events, iam_write_events, iam_list_events, error_events, bytes_out_total, unique_resources, unique_ips, unique_event_types

**Ratios:** iam_ratio, s3_ratio, write_ratio, error_rate, iam_write_ratio, delete_ratio, after_hours_ratio

**Z-scores vs user baseline:** total_events_zscore, iam_events_zscore, s3_events_zscore, s3_get_events_zscore, s3_delete_events_zscore, iam_write_events_zscore, iam_list_events_zscore, bytes_out_zscore

**1-hour context:** h1_total_events, h1_iam_events, h1_s3_events, h1_s3_get_events, h1_s3_delete_events, h1_iam_write_events, h1_iam_list_events, h1_error_events, h1_write_ratio

**Daily slopes (exfiltration detection):** s3_get_slope_3d, s3_get_pct_change_1d

**Temporal:** window_hour, window_day_of_week, window_is_weekend, window_is_business_hours

---

## Switching to Real AWS (Demo)

Replace the log reader in `run_pipeline.py`:

```python
# In stage_ingest(), replace:
from data_ingestion.log_reader import load_all_events
raw_events = load_all_events(raw_dir)

# With:
from aws_connector.s3_cloudtrail_reader import load_all_events_from_s3
raw_events = load_all_events_from_s3(
    bucket="your-cloudtrail-bucket",
    prefix="AWSLogs/YOUR_ACCOUNT_ID/CloudTrail/ap-south-1/",
    start_date="2026-02-15",
    end_date="2026-03-01",
)
```

Everything downstream (normalizer, features, models) works identically.

---

## Paper Citation

Schema sourced from:
- AWS CloudTrail Log Event Reference (Amazon Web Services, 2024)
- Flaws.cloud CloudTrail attack samples (Scott Piper, summitroute.com)
- MITRE ATT&CK Cloud Matrix v14 (MITRE Corporation, 2024)
- Rhino Security Labs: "AWS IAM Privilege Escalation Methods" (2023)

"""
run_pipeline.py
================
Master orchestrator. Runs the full data generation and normalization
pipeline end-to-end.

Run this file first. Subsequent steps (model training, RAG ingestion)
read from the outputs this produces.

Usage:
    python run_pipeline.py                    # Full pipeline
    python run_pipeline.py --stage generate   # Only generate logs
    python run_pipeline.py --stage ingest     # Only normalize + parquet
    python run_pipeline.py --stage features   # Only feature engineering
    python run_pipeline.py --dry-run          # Show config, don't run

Output files produced:
    data/raw/                          — gzipped CloudTrail JSON files
    data/normalized/events.parquet     — flat normalized events
    data/normalized/events_labeled.parquet  — events with attack labels
    data/features/feature_matrix.parquet   — ML-ready feature matrix
    data/labels/window_labels.csv          — per-window ground truth
    ground_truth/attack_manifest.json      — attack scenario metadata
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import yaml

# ── Logging setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pipeline")


def load_config(path: str = "config/simulation_config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Stage 1: Generate raw CloudTrail logs ────────────────────────────────────

def stage_generate(config: dict) -> None:
    log.info("=" * 55)
    log.info("STAGE 1: Generating raw CloudTrail logs")
    log.info("=" * 55)

    from data_generation.temporal_engine import TemporalEngine
    from data_generation.normal_traffic_generator import generate_normal_traffic
    from data_generation.attack_injector import inject_all_attacks
    from data_generation.log_writer import (
        write_cloudtrail_logs,
        write_attack_manifest,
        write_label_jsonl,
        summarize_output,
    )

    t0 = time.time()
    engine = TemporalEngine(config)

    # How many normal events (attack events are additional on top)
    target_normal = config["simulation"]["target_total_events"]
    log.info(f"Target normal events: {target_normal:,}")

    # Generate normal traffic
    log.info("Generating normal traffic...")
    normal_events = generate_normal_traffic(config, engine, target_normal)
    log.info(f"Generated {len(normal_events):,} normal events in {time.time()-t0:.1f}s")

    # Inject attacks
    log.info("Injecting attack scenarios...")
    attack_events, attack_labels, manifest = inject_all_attacks(config, engine, normal_events)
    log.info(f"Injected {len(attack_events):,} attack events across 5 scenarios")

    # Merge and sort
    all_events = normal_events + attack_events
    all_events.sort(key=lambda e: e["eventTime"])
    log.info(f"Total events: {len(all_events):,}")

    # Write gzipped CloudTrail files
    written = write_cloudtrail_logs(all_events, config)
    log.info(f"Written {len(written)} log files")

    # Write ground truth
    manifest_path = config["output"]["ground_truth_file"]
    write_attack_manifest(manifest, manifest_path)

    label_path = str(Path(config["output"]["labels_dir"]) / "event_labels.jsonl")
    write_label_jsonl(attack_labels, label_path)

    summarize_output(all_events, written)
    log.info(f"Stage 1 complete in {time.time()-t0:.1f}s")


# ── Stage 2: Normalize and write Parquet ──────────────────────────────────────

def stage_ingest(config: dict) -> None:
    log.info("=" * 55)
    log.info("STAGE 2: Normalizing events → Parquet")
    log.info("=" * 55)

    import pandas as pd
    from data_ingestion.log_reader import load_all_events
    from data_ingestion.normalizer import normalize_events, add_attack_labels
    from data_ingestion.parquet_store import write_parquet

    t0 = time.time()
    raw_dir = config["output"]["raw_log_dir"]
    norm_dir = config["output"]["normalized_dir"]
    label_path = str(Path(config["output"]["labels_dir"]) / "event_labels.jsonl")

    # Load raw events
    log.info(f"Loading events from {raw_dir}/...")
    raw_events = load_all_events(raw_dir)
    log.info(f"Loaded {len(raw_events):,} events")

    # Normalize
    df = normalize_events(raw_events)

    # Save without labels
    events_path = str(Path(norm_dir) / "events.parquet")
    write_parquet(df, events_path)

    # Add labels and save
    df_labeled = add_attack_labels(df, label_path)
    labeled_path = str(Path(norm_dir) / "events_labeled.parquet")
    write_parquet(df_labeled, labeled_path)

    log.info(f"Stage 2 complete in {time.time()-t0:.1f}s")
    log.info(f"  events.parquet:         {events_path}")
    log.info(f"  events_labeled.parquet: {labeled_path}")


# ── Stage 3: Feature engineering ──────────────────────────────────────────────

def stage_features(config: dict) -> None:
    log.info("=" * 55)
    log.info("STAGE 3: Feature engineering")
    log.info("=" * 55)

    from data_ingestion.parquet_store import read_parquet, write_parquet
    from feature_engineering.window_aggregator import compute_all_windows
    from feature_engineering.feature_builder import build_feature_matrix, add_labels_to_features
    from feature_engineering.label_generator import (
        save_feature_matrix,
        save_window_labels,
        print_label_summary,
    )

    t0 = time.time()
    norm_dir = config["output"]["normalized_dir"]
    feat_dir = config["output"]["features_dir"]
    labels_dir = config["output"]["labels_dir"]

    # Load labeled normalized events
    labeled_path = str(Path(norm_dir) / "events_labeled.parquet")
    log.info(f"Loading normalized events from {labeled_path}...")
    df = read_parquet(labeled_path)
    log.info(f"Loaded {len(df):,} events")

    # Compute all window aggregations
    windows = compute_all_windows(df)

    # Build feature matrix
    feat_df = build_feature_matrix(
        w5=windows["w5"],
        w60=windows["w60"],
        daily=windows["daily"],
        baselines=windows["baselines"],
    )

    # Add labels
    feat_df = add_labels_to_features(feat_df, df)

    # Save
    feature_path = str(Path(feat_dir) / "feature_matrix.parquet")
    save_feature_matrix(feat_df, feature_path)

    label_csv_path = str(Path(labels_dir) / "window_labels.csv")
    save_window_labels(feat_df, label_csv_path)

    print_label_summary(feat_df)
    log.info(f"Stage 3 complete in {time.time()-t0:.1f}s")
    log.info(f"  feature_matrix.parquet: {feature_path}")
    log.info(f"  window_labels.csv:      {label_csv_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC CloudTrail Pipeline")
    parser.add_argument(
        "--stage",
        choices=["generate", "ingest", "features", "all"],
        default="all",
        help="Which pipeline stage to run"
    )
    parser.add_argument(
        "--config",
        default="config/simulation_config.yaml",
        help="Path to simulation config YAML"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print config and exit without running"
    )
    args = parser.parse_args()

    # Always run from project root
    project_root = Path(__file__).parent
    os.chdir(project_root)
    sys.path.insert(0, str(project_root))

    config = load_config(args.config)

    if args.dry_run:
        print("\nConfiguration:")
        print(yaml.dump(config, default_flow_style=False))
        print("\nWould run stages:", args.stage)
        return

    log.info("SOC CloudTrail Pipeline starting")
    log.info(f"Date range: {config['simulation']['start_date']} → {config['simulation']['end_date']}")
    log.info(f"Target events: {config['simulation']['target_total_events']:,}")
    log.info(f"Region: {config['aws']['region']}")

    t_total = time.time()

    if args.stage in ("generate", "all"):
        stage_generate(config)

    if args.stage in ("ingest", "all"):
        stage_ingest(config)

    if args.stage in ("features", "all"):
        stage_features(config)

    log.info(f"\nPipeline complete. Total time: {time.time()-t_total:.1f}s")
    log.info("\nNext steps:")
    log.info("  1. Train models: python models/isolation_forest.py")
    log.info("  2. RAG ingestion: python rag_ingestion/parquet_to_rag.py")
    log.info("  3. Real AWS demo: edit aws_connector/s3_cloudtrail_reader.py")


if __name__ == "__main__":
    main()

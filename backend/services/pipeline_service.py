"""
backend/services/pipeline_service.py
======================================
Production pipeline orchestrator for Cloud SOC.

Instead of generating synthetic data, this:
1. Reads real CloudTrail logs from S3 (via aws_connector)
2. Normalizes events
3. Builds features
4. Runs ML models
5. Updates alerts database
6. Optionally runs RAG ingestion

Can be triggered:
- Manually via API endpoint
- On backend startup (if configured)
- On a schedule (e.g., hourly)
"""

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading

import pandas as pd
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

PROJECT_ROOT = Path(__file__).parent.parent.parent

log = logging.getLogger(__name__)


class PipelineStatus(str, Enum):
    """Pipeline execution status"""
    IDLE = "idle"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


class PipelineRun:
    """Track a single pipeline execution"""

    def __init__(self):
        self.run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.status = PipelineStatus.IDLE
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.stages_completed: List[str] = []
        self.stages_failed: List[str] = []
        self.error_message: Optional[str] = None
        self.events_ingested: int = 0
        self.alerts_generated: int = 0
        self.logs: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": (
                (self.completed_at - self.started_at).total_seconds()
                if self.started_at and self.completed_at
                else None
            ),
            "stages_completed": self.stages_completed,
            "stages_failed": self.stages_failed,
            "error_message": self.error_message,
            "events_ingested": self.events_ingested,
            "alerts_generated": self.alerts_generated,
            "logs": self.logs[-50:],  # Last 50 log lines
        }


class PipelineOrchestrator:
    """
    Orchestrates the full SOC data pipeline.

    Production flow:
    1. Read CloudTrail logs from S3 → raw events
    2. Normalize → events.parquet
    3. Build features → feature_matrix.parquet
    4. Run ML models → ensemble_alerts.csv
    5. (Optional) Update RAG collections
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or str(PROJECT_ROOT / "config" / "simulation_config.yaml")
        self.config = self._load_config()
        self.current_run: Optional[PipelineRun] = None
        self.run_history: List[PipelineRun] = []
        self._is_running = False
        self._lock = threading.Lock()

    def _load_config(self) -> dict:
        """Load pipeline configuration"""
        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def is_running(self) -> bool:
        """Check if pipeline is currently running"""
        return self._is_running

    def get_current_run(self) -> Optional[Dict[str, Any]]:
        """Get current pipeline run status"""
        if self.current_run:
            return self.current_run.to_dict()
        return None

    def get_run_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent pipeline runs"""
        return [run.to_dict() for run in self.run_history[-limit:]]

    def run_pipeline(
        self,
        s3_bucket: Optional[str] = None,
        s3_prefix: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        aws_profile: Optional[str] = None,
        stages: Optional[List[str]] = None,
        run_async: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute the full pipeline or specific stages.

        Args:
            s3_bucket: S3 bucket with CloudTrail logs (required for production)
            s3_prefix: S3 prefix (e.g., 'AWSLogs/123456789/CloudTrail/ap-south-1/')
            start_date: Start date YYYY-MM-DD (defaults to 7 days ago)
            end_date: End date YYYY-MM-DD (defaults to today)
            aws_profile: AWS CLI profile name
            stages: List of stages to run ['ingest', 'features', 'models', 'rag']
            run_async: Run in background thread

        Returns:
            Pipeline run status dict
        """
        if self._is_running:
            return {
                "success": False,
                "message": "Pipeline is already running",
                "current_run": self.current_run.to_dict() if self.current_run else None,
            }

        if run_async:
            # Run in background thread
            thread = threading.Thread(
                target=self._execute_pipeline,
                args=(s3_bucket, s3_prefix, start_date, end_date, aws_profile, stages),
            )
            thread.start()
            return {
                "success": True,
                "message": "Pipeline started in background",
                "run_id": self.current_run.run_id if self.current_run else None,
            }
        else:
            # Run synchronously
            return self._execute_pipeline(
                s3_bucket, s3_prefix, start_date, end_date, aws_profile, stages
            )

    def _execute_pipeline(
        self,
        s3_bucket: Optional[str],
        s3_prefix: Optional[str],
        start_date: Optional[str],
        end_date: Optional[str],
        aws_profile: Optional[str],
        stages: Optional[List[str]],
    ) -> Dict[str, Any]:
        """Internal pipeline execution"""
        with self._lock:
            self._is_running = True
            self.current_run = PipelineRun()
            self.current_run.status = PipelineStatus.RUNNING
            self.current_run.started_at = datetime.utcnow()

        run = self.current_run

        try:
            # Default stages
            if not stages:
                stages = ["ingest", "features", "models"]

            # Default date range (last 7 days)
            if not end_date:
                end_date = datetime.utcnow().strftime("%Y-%m-%d")
            if not start_date:
                start_dt = datetime.utcnow() - timedelta(days=7)
                start_date = start_dt.strftime("%Y-%m-%d")

            run.logs.append(f"Starting pipeline run {run.run_id}")
            run.logs.append(f"Date range: {start_date} to {end_date}")
            run.logs.append(f"Stages: {', '.join(stages)}")

            # Stage 1: Ingest from S3
            if "ingest" in stages:
                self._stage_ingest(run, s3_bucket, s3_prefix, start_date, end_date, aws_profile)

            # Stage 2: Feature engineering
            if "features" in stages:
                self._stage_features(run)

            # Stage 3: Run ML models
            if "models" in stages:
                self._stage_models(run)

            # Stage 4: RAG ingestion (optional)
            if "rag" in stages:
                self._stage_rag(run)

            # Success
            run.status = PipelineStatus.SUCCESS if not run.stages_failed else PipelineStatus.PARTIAL
            run.completed_at = datetime.utcnow()
            run.logs.append(f"Pipeline completed: {run.status}")

            return {
                "success": True,
                "run": run.to_dict(),
            }

        except Exception as e:
            log.error(f"Pipeline failed: {e}", exc_info=True)
            run.status = PipelineStatus.FAILED
            run.error_message = str(e)
            run.completed_at = datetime.utcnow()
            run.logs.append(f"ERROR: {str(e)}")

            return {
                "success": False,
                "error": str(e),
                "run": run.to_dict(),
            }

        finally:
            self._is_running = False
            self.run_history.append(run)
            # Keep only last 50 runs
            if len(self.run_history) > 50:
                self.run_history = self.run_history[-50:]

    def _stage_ingest(
        self,
        run: PipelineRun,
        s3_bucket: Optional[str],
        s3_prefix: Optional[str],
        start_date: str,
        end_date: str,
        aws_profile: Optional[str],
    ):
        """Stage 1: Ingest CloudTrail logs from S3"""
        run.logs.append("Stage 1: Ingesting CloudTrail logs from S3...")
        stage_start = time.time()

        try:
            # Use aws_connector to read from S3
            from aws_connector.s3_cloudtrail_reader import load_all_events_from_s3
            from data_ingestion.normalizer import normalize_events, add_attack_labels
            from data_ingestion.parquet_store import write_parquet

            if not s3_bucket:
                raise ValueError("s3_bucket is required for production pipeline")

            if not s3_prefix:
                # Default prefix structure
                account_id = self.config["aws"]["account_id"]
                region = self.config["aws"]["region"]
                s3_prefix = f"AWSLogs/{account_id}/CloudTrail/{region}/"

            run.logs.append(f"Reading from s3://{s3_bucket}/{s3_prefix}")

            # Load events from S3
            raw_events = load_all_events_from_s3(
                bucket=s3_bucket,
                prefix=s3_prefix,
                start_date=start_date,
                end_date=end_date,
                profile_name=aws_profile,
            )

            run.events_ingested = len(raw_events)
            run.logs.append(f"Loaded {len(raw_events):,} events from S3")

            if len(raw_events) == 0:
                raise ValueError("No events found in specified S3 location/date range")

            # Normalize
            df = normalize_events(raw_events)
            run.logs.append(f"Normalized {len(df):,} events")

            # Save normalized events
            norm_dir = PROJECT_ROOT / "data" / "normalized"
            norm_dir.mkdir(parents=True, exist_ok=True)

            events_path = norm_dir / "events.parquet"
            write_parquet(df, str(events_path))
            run.logs.append(f"Saved to {events_path}")

            # For production, we don't have attack labels (real data)
            # But we'll create the labeled version for compatibility
            df["is_attack"] = False
            df["attack_name"] = "normal"
            labeled_path = norm_dir / "events_labeled.parquet"
            write_parquet(df, str(labeled_path))

            run.stages_completed.append("ingest")
            elapsed = time.time() - stage_start
            run.logs.append(f"Stage 1 complete in {elapsed:.1f}s")

        except Exception as e:
            run.stages_failed.append("ingest")
            run.logs.append(f"Stage 1 FAILED: {str(e)}")
            raise

    def _stage_features(self, run: PipelineRun):
        """Stage 2: Build feature matrix"""
        run.logs.append("Stage 2: Building feature matrix...")
        stage_start = time.time()

        try:
            from data_ingestion.parquet_store import read_parquet, write_parquet
            from feature_engineering.window_aggregator import compute_all_windows
            from feature_engineering.feature_builder import build_feature_matrix, add_labels_to_features
            from feature_engineering.label_generator import save_feature_matrix, save_window_labels

            # Load normalized events
            norm_dir = PROJECT_ROOT / "data" / "normalized"
            labeled_path = norm_dir / "events_labeled.parquet"

            df = read_parquet(str(labeled_path))
            run.logs.append(f"Loaded {len(df):,} events")

            # Compute windows
            windows = compute_all_windows(df)
            run.logs.append("Computed window aggregations")

            # Build features
            feat_df = build_feature_matrix(
                w5=windows["w5"],
                w60=windows["w60"],
                daily=windows["daily"],
                baselines=windows["baselines"],
            )

            # Add labels
            feat_df = add_labels_to_features(feat_df, df)

            # Save
            feat_dir = PROJECT_ROOT / "data" / "features"
            feat_dir.mkdir(parents=True, exist_ok=True)

            feature_path = feat_dir / "feature_matrix.parquet"
            save_feature_matrix(feat_df, str(feature_path))

            labels_dir = PROJECT_ROOT / "data" / "labels"
            labels_dir.mkdir(parents=True, exist_ok=True)
            label_csv_path = labels_dir / "window_labels.csv"
            save_window_labels(feat_df, str(label_csv_path))

            run.stages_completed.append("features")
            elapsed = time.time() - stage_start
            run.logs.append(f"Stage 2 complete in {elapsed:.1f}s")
            run.logs.append(f"Generated {len(feat_df):,} feature windows")

        except Exception as e:
            run.stages_failed.append("features")
            run.logs.append(f"Stage 2 FAILED: {str(e)}")
            raise

    def _stage_models(self, run: PipelineRun):
        """Stage 3: Run ML models"""
        run.logs.append("Stage 3: Running ML models...")
        stage_start = time.time()

        model_scripts = [
            "models/isolation_forest.py",
            "models/lof_model.py",
            "models/autoencoder.py",
            "models/ensemble.py",
        ]

        try:
            for script in model_scripts:
                model_name = Path(script).stem
                run.logs.append(f"Running {model_name}...")

                result = subprocess.run(
                    [sys.executable, str(PROJECT_ROOT / script)],
                    cwd=str(PROJECT_ROOT),
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minute timeout per model
                )

                if result.returncode != 0:
                    error_msg = result.stderr[-500:] if result.stderr else "Unknown error"
                    run.logs.append(f"{model_name} FAILED: {error_msg}")
                    run.stages_failed.append(f"model_{model_name}")
                else:
                    run.logs.append(f"{model_name} ✓")

            # Count alerts generated
            alerts_path = PROJECT_ROOT / "data" / "results" / "ensemble_alerts.csv"
            if alerts_path.exists():
                alerts_df = pd.read_csv(alerts_path)
                run.alerts_generated = len(alerts_df)
                run.logs.append(f"Generated {run.alerts_generated} alerts")

            if not run.stages_failed or all("model_" not in s for s in run.stages_failed):
                run.stages_completed.append("models")

            elapsed = time.time() - stage_start
            run.logs.append(f"Stage 3 complete in {elapsed:.1f}s")

        except Exception as e:
            run.stages_failed.append("models")
            run.logs.append(f"Stage 3 FAILED: {str(e)}")
            raise

    def _stage_rag(self, run: PipelineRun):
        """Stage 4: RAG ingestion (optional)"""
        run.logs.append("Stage 4: RAG ingestion...")
        stage_start = time.time()

        try:
            rag_scripts = [
                "rag_ingestion/ingest_vector_db.py",
                # "rag_ingestion/ingest_knowledge_graph.py",  # Requires Neo4j
            ]

            for script in rag_scripts:
                script_name = Path(script).stem
                run.logs.append(f"Running {script_name}...")

                result = subprocess.run(
                    [sys.executable, str(PROJECT_ROOT / script)],
                    cwd=str(PROJECT_ROOT),
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if result.returncode != 0:
                    run.logs.append(f"{script_name} FAILED (optional, continuing...)")
                else:
                    run.logs.append(f"{script_name} ✓")

            run.stages_completed.append("rag")
            elapsed = time.time() - stage_start
            run.logs.append(f"Stage 4 complete in {elapsed:.1f}s")

        except Exception as e:
            # RAG is optional, don't fail the whole pipeline
            run.logs.append(f"Stage 4 WARNING: {str(e)} (continuing...)")


# Singleton instance
_orchestrator = None


def get_orchestrator() -> PipelineOrchestrator:
    """Get or create PipelineOrchestrator singleton"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = PipelineOrchestrator()
    return _orchestrator

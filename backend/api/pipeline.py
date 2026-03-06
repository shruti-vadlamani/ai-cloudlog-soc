"""
backend/api/pipeline.py
========================
API endpoints for pipeline orchestration
"""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel, Field

from backend.services.pipeline_service import get_orchestrator, PipelineStatus

router = APIRouter()


class PipelineRunRequest(BaseModel):
    """Request to trigger pipeline run"""
    s3_bucket: Optional[str] = Field(None, description="S3 bucket with CloudTrail logs")
    s3_prefix: Optional[str] = Field(None, description="S3 prefix (e.g., 'AWSLogs/123/.../CloudTrail/')")
    start_date: Optional[str] = Field(None, description="Start date YYYY-MM-DD (default: 7 days ago)")
    end_date: Optional[str] = Field(None, description="End date YYYY-MM-DD (default: today)")
    aws_profile: Optional[str] = Field(None, description="AWS CLI profile name")
    stages: Optional[List[str]] = Field(None, description="Stages to run: ingest, features, models, rag")
    run_async: bool = Field(True, description="Run in background (recommended)")

    class Config:
        json_schema_extra = {
            "example": {
                "s3_bucket": "my-cloudtrail-logs",
                "s3_prefix": "AWSLogs/911234567890/CloudTrail/ap-south-1/",
                "start_date": "2026-02-25",
                "end_date": "2026-03-04",
                "aws_profile": "default",
                "stages": ["ingest", "features", "models"],
                "run_async": True
            }
        }


@router.post("/run", response_model=dict)
def trigger_pipeline(
    request: PipelineRunRequest = Body(...),
):
    """
    Trigger a pipeline run to ingest and process CloudTrail logs.

    Pipeline stages:
    1. **ingest**: Read CloudTrail logs from S3, normalize to Parquet
    2. **features**: Build feature matrix from normalized events
    3. **models**: Run ML models (IF, LOF, Autoencoder, Ensemble)
    4. **rag**: Update RAG vector store (optional)

    Production workflow:
    - Schedule this endpoint to run hourly/daily
    - Point to your real CloudTrail S3 bucket
    - Alerts will be automatically updated in `data/results/ensemble_alerts.csv`
    - The alert API endpoints will serve the latest data

    Example:
    ```bash
    curl -X POST http://localhost:8000/api/pipeline/run \\
      -H "Content-Type: application/json" \\
      -d '{
        "s3_bucket": "my-cloudtrail-logs",
        "start_date": "2026-03-01",
        "end_date": "2026-03-04",
        "run_async": true
      }'
    ```
    """
    orchestrator = get_orchestrator()

    result = orchestrator.run_pipeline(
        s3_bucket=request.s3_bucket,
        s3_prefix=request.s3_prefix,
        start_date=request.start_date,
        end_date=request.end_date,
        aws_profile=request.aws_profile,
        stages=request.stages,
        run_async=request.run_async,
    )

    return result


@router.get("/status", response_model=dict)
def get_pipeline_status():
    """
    Get current pipeline execution status.

    Returns:
    - Whether pipeline is currently running
    - Current run details (if running)
    - Progress through stages
    - Recent logs
    """
    orchestrator = get_orchestrator()

    current_run = orchestrator.get_current_run()
    is_running = orchestrator.is_running()

    return {
        "is_running": is_running,
        "current_run": current_run,
    }


@router.get("/history", response_model=dict)
def get_pipeline_history(
    limit: int = Query(10, ge=1, le=50, description="Number of recent runs to return"),
):
    """
    Get recent pipeline execution history.

    Shows:
    - Past pipeline runs
    - Success/failure status
    - Duration
    - Events ingested and alerts generated
    - Error messages (if any)
    """
    orchestrator = get_orchestrator()
    history = orchestrator.get_run_history(limit=limit)

    return {
        "runs": history,
        "count": len(history),
    }


@router.post("/stop", response_model=dict)
def stop_pipeline():
    """
    Stop the currently running pipeline (if any).

    Note: This is a graceful stop request. The pipeline will complete
    its current stage and then halt.
    """
    orchestrator = get_orchestrator()

    if not orchestrator.is_running():
        raise HTTPException(status_code=400, detail="No pipeline is currently running")

    # TODO: Implement graceful stop mechanism
    return {
        "success": False,
        "message": "Pipeline stop not yet implemented. Let current run complete.",
    }


@router.get("/config", response_model=dict)
def get_pipeline_config():
    """
    Get current pipeline configuration.

    Returns settings from `config/simulation_config.yaml`.
    """
    orchestrator = get_orchestrator()
    return orchestrator.config


@router.get("/data-status", response_model=dict)
def get_data_status():
    """
    Check status of data files required by the pipeline.

    Returns:
    - Which data files exist
    - File sizes
    - Last modified timestamps
    - Row counts (for CSV/Parquet)

    Useful for determining if pipeline needs to run.
    """
    from pathlib import Path
    import pandas as pd
    from datetime import datetime

    PROJECT_ROOT = Path(__file__).parent.parent.parent

    files_to_check = {
        "normalized_events": PROJECT_ROOT / "data" / "normalized" / "events_labeled.parquet",
        "feature_matrix": PROJECT_ROOT / "data" / "features" / "feature_matrix.parquet",
        "ensemble_alerts": PROJECT_ROOT / "data" / "results" / "ensemble_alerts.csv",
        "if_scores": PROJECT_ROOT / "data" / "models" / "if_scores.csv",
        "lof_scores": PROJECT_ROOT / "data" / "models" / "lof_scores.csv",
        "ae_scores": PROJECT_ROOT / "data" / "models" / "ae_scores.csv",
    }

    status = {}

    for name, path in files_to_check.items():
        if path.exists():
            stat = path.stat()
            info = {
                "exists": True,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }

            # Try to get row count
            try:
                if path.suffix == ".csv":
                    df = pd.read_csv(path, nrows=0)
                    # Get line count without loading whole file
                    with open(path) as f:
                        info["row_count"] = sum(1 for _ in f) - 1  # -1 for header
                elif path.suffix == ".parquet":
                    df = pd.read_parquet(path)
                    info["row_count"] = len(df)
            except Exception:
                pass

            status[name] = info
        else:
            status[name] = {"exists": False}

    # Overall assessment
    required_files = ["normalized_events", "feature_matrix", "ensemble_alerts"]
    all_required_exist = all(status.get(f, {}).get("exists", False) for f in required_files)

    return {
        "files": status,
        "ready": all_required_exist,
        "message": "All required files exist" if all_required_exist else "Pipeline needs to run",
    }

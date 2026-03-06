"""
backend/main.py
===============
FastAPI backend for AI-Driven Cloud SOC dashboard.

Provides REST API endpoints for:
  - Alert retrieval and filtering
  - RAG-powered incident enrichment
  - Statistics and metrics
  - Interactive knowledge base queries
  - Pipeline orchestration (ingest CloudTrail logs, run ML models)

Run:
    uvicorn backend.main:app --reload --port 8000
    
Configuration:
    Edit backend/config.yaml to configure:
    - AWS S3 bucket for CloudTrail logs
    - Pipeline auto-run on startup
    - Scheduled pipeline runs
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import yaml

from backend.api import alerts, rag, stats, pipeline
from backend.services.pipeline_service import get_orchestrator

PROJECT_ROOT = Path(__file__).parent.parent
BACKEND_CONFIG_PATH = PROJECT_ROOT / "backend" / "config.yaml"

# Load backend configuration
backend_config = {}
if BACKEND_CONFIG_PATH.exists():
    with open(BACKEND_CONFIG_PATH) as f:
        backend_config = yaml.safe_load(f)

# Configure logging
log_config = backend_config.get("logging", {})
logging.basicConfig(
    level=getattr(logging, log_config.get("level", "INFO")),
    format=log_config.get("format", "%(asctime)s [%(levelname)s] %(name)s: %(message)s"),
    datefmt="%H:%M:%S",
)

log = logging.getLogger(__name__)


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup
    log.info("Cloud SOC Backend starting...")
    
    # Check if pipeline should auto-run on startup
    pipeline_config = backend_config.get("pipeline", {})
    if pipeline_config.get("run_on_startup", False):
        log.info("Running pipeline on startup (configured in backend/config.yaml)...")
        orchestrator = get_orchestrator()
        
        aws_config = backend_config.get("aws", {})
        orchestrator.run_pipeline(
            s3_bucket=aws_config.get("s3_bucket"),
            s3_prefix=aws_config.get("s3_prefix"),
            aws_profile=aws_config.get("profile"),
            stages=pipeline_config.get("default_stages", ["ingest", "features", "models"]),
            run_async=True,  # Always async on startup
        )
    
    # Initialize scheduler if configured
    scheduler = None
    if pipeline_config.get("schedule", {}).get("enabled", False):
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            from apscheduler.triggers.cron import CronTrigger
            
            scheduler = AsyncIOScheduler()
            
            cron_expr = pipeline_config["schedule"]["cron"]
            log.info(f"Scheduling pipeline runs: {cron_expr}")
            
            # Parse cron expression (minute hour day month day_of_week)
            parts = cron_expr.split()
            trigger = CronTrigger(
                minute=parts[0] if len(parts) > 0 else "0",
                hour=parts[1] if len(parts) > 1 else "*",
                day=parts[2] if len(parts) > 2 else "*",
                month=parts[3] if len(parts) > 3 else "*",
                day_of_week=parts[4] if len(parts) > 4 else "*",
            )
            
            def scheduled_pipeline_run():
                orchestrator = get_orchestrator()
                aws_config = backend_config.get("aws", {})
                orchestrator.run_pipeline(
                    s3_bucket=aws_config.get("s3_bucket"),
                    s3_prefix=aws_config.get("s3_prefix"),
                    aws_profile=aws_config.get("profile"),
                    stages=pipeline_config.get("default_stages", ["ingest", "features", "models"]),
                    run_async=True,
                )
            
            scheduler.add_job(scheduled_pipeline_run, trigger)
            scheduler.start()
            log.info("Pipeline scheduler started")
            
        except ImportError:
            log.warning("APScheduler not installed. Scheduled runs disabled. Install: pip install apscheduler")
        except Exception as e:
            log.error(f"Failed to initialize scheduler: {e}")
    
    yield  # Server is running
    
    # Shutdown
    log.info("Cloud SOC Backend shutting down...")
    if scheduler:
        scheduler.shutdown()


app = FastAPI(
    title="Cloud SOC API",
    description="AI-Driven Security Operations Center for AWS CloudTrail",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS - allow frontend access
cors_origins = backend_config.get("api", {}).get("cors_origins", ["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(rag.router, prefix="/api/rag", tags=["RAG"])
app.include_router(stats.router, prefix="/api/stats", tags=["Statistics"])
app.include_router(pipeline.router, prefix="/api/pipeline", tags=["Pipeline"])


@app.get("/")
def root():
    return {
        "service": "Cloud SOC API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}

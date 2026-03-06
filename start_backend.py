#!/usr/bin/env python3
"""
start_backend.py
================
Convenience script to start the FastAPI backend server.

Usage:
    python start_backend.py
    python start_backend.py --port 8080
    python start_backend.py --host 0.0.0.0 --port 80
"""

import argparse
import sys
from pathlib import Path

# Ensure we're in the project root
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def main():
    parser = argparse.ArgumentParser(description="Start Cloud SOC API backend")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    import uvicorn

    print(f"""
╔══════════════════════════════════════════════════════════╗
║           Cloud SOC API Backend                          ║
╚══════════════════════════════════════════════════════════╝

Starting server...
  → API: http://{args.host}:{args.port}
  → Docs: http://{args.host}:{args.port}/docs
  → ReDoc: http://{args.host}:{args.port}/redoc

Press CTRL+C to stop.
""")

    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()

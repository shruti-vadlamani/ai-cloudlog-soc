"""
Shared Neo4j environment configuration loader for local scripts and services.
"""

from pathlib import Path
import os

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _first_non_empty(keys, default=None):
    for key in keys:
        value = os.getenv(key)
        if value is not None and str(value).strip() != "":
            return value
    return default


def get_neo4j_config(require_credentials=True):
    """Load and return Neo4j connection settings from .env.

    Supports both upper/lower case variable names and user/username variants.
    """
    load_dotenv(PROJECT_ROOT / ".env")

    uri = _first_non_empty(["NEO4J_URI", "neo4j_uri"])
    username = _first_non_empty(["NEO4J_USERNAME", "neo4j_username", "NEO4J_USER", "neo4j_user"])
    password = _first_non_empty(["NEO4J_PASSWORD", "neo4j_password"])
    database = _first_non_empty(["NEO4J_DATABASE", "neo4j_database"])

    if require_credentials:
        missing = []
        if not uri:
            missing.append("neo4j_uri")
        if not username:
            missing.append("neo4j_username")
        if not password:
            missing.append("neo4j_password")
        if missing:
            raise ValueError(
                "Missing Neo4j env vars in .env: " + ", ".join(missing)
            )

    return {
        "uri": uri,
        "username": username,
        "password": password,
        "database": database,
    }

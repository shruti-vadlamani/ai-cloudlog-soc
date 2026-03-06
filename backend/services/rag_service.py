"""
backend/services/rag_service.py
=================================
Service layer for RAG queries and alert enrichment
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.models.schemas import (
    EnrichedAlert,
    Alert,
    RAGQueryResponse,
    RAGQueryResult,
)

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent


class RAGService:
    """Service for RAG-powered queries and alert enrichment"""

    def __init__(self):
        self.chroma_client = None
        self.neo4j_driver = None
        self.alert_enricher = None
        self.embedder = None
        self._init_rag()

    def _init_rag(self):
        """Initialize RAG components (ChromaDB, Neo4j, AlertEnricher)"""
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer

            chroma_path = str(PROJECT_ROOT / "chroma_db")
            self.chroma_client = chromadb.PersistentClient(path=chroma_path)
            self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
            log.info("ChromaDB initialized")
        except ImportError:
            log.warning("ChromaDB or sentence-transformers not installed")
        except Exception as e:
            log.warning(f"Failed to initialize ChromaDB: {e}")

        # Neo4j is optional for basic queries
        try:
            from neo4j import GraphDatabase
            from rag_ingestion.alert_enrichment import AlertEnricher

            # Try to connect to Neo4j
            uri = "bolt://localhost:7687"
            auth = ("neo4j", "password")  # Default, should be in config
            self.neo4j_driver = GraphDatabase.driver(uri, auth=auth)
            
            if self.chroma_client and self.embedder:
                self.alert_enricher = AlertEnricher(
                    self.neo4j_driver, self.chroma_client, self.embedder
                )
                log.info("Alert enricher initialized with Neo4j")
        except ImportError:
            log.warning("neo4j driver not installed")
        except Exception as e:
            log.warning(f"Neo4j connection failed: {e}")
            log.warning("Alert enrichment will be limited without Neo4j")

    def query_knowledge_base(
        self,
        query: str,
        max_results: int = 5,
        collection: Optional[str] = None,
    ) -> RAGQueryResponse:
        """
        Query ChromaDB for relevant knowledge.

        Args:
            query: Natural language query
            max_results: Number of results to return
            collection: Specific collection to query (behavioral_incidents, threat_intelligence)
        """
        if not self.chroma_client or not self.embedder:
            return RAGQueryResponse(
                query=query,
                results=[],
                collection=collection or "none",
            )

        results = []

        # Determine which collections to query
        collections_to_query = []
        if collection:
            collections_to_query = [collection]
        else:
            # Query both collections
            collections_to_query = ["behavioral_incidents", "threat_intelligence"]

        for col_name in collections_to_query:
            try:
                col = self.chroma_client.get_collection(col_name)
                
                # Generate query embedding
                query_embedding = self.embedder.encode(query).tolist()

                # Query collection
                query_results = col.query(
                    query_embeddings=[query_embedding],
                    n_results=max_results,
                )

                # Process results
                if query_results["documents"] and len(query_results["documents"]) > 0:
                    for i, doc in enumerate(query_results["documents"][0]):
                        metadata = query_results["metadatas"][0][i] if query_results["metadatas"] else {}
                        distance = query_results["distances"][0][i] if query_results["distances"] else 1.0
                        
                        # Convert distance to similarity (ChromaDB uses L2 distance)
                        similarity = 1.0 / (1.0 + distance)

                        result = RAGQueryResult(
                            content=doc,
                            metadata=metadata,
                            similarity=round(similarity, 3),
                        )
                        results.append(result)

            except Exception as e:
                log.warning(f"Failed to query collection {col_name}: {e}")

        # Sort by similarity and limit
        results.sort(key=lambda x: x.similarity, reverse=True)
        results = results[:max_results]

        return RAGQueryResponse(
            query=query,
            results=results,
            collection=collection or "all",
        )

    def enrich_alert(
        self,
        alert: Alert,
    ) -> EnrichedAlert:
        """
        Enrich an alert with full RAG context.

        Falls back to basic enrichment if Neo4j is unavailable.
        """
        # Try full enrichment with AlertEnricher
        if self.alert_enricher:
            try:
                # Load feature matrix and normalized events
                feature_path = PROJECT_ROOT / "data" / "features" / "feature_matrix.parquet"
                normalized_path = PROJECT_ROOT / "data" / "normalized" / "events_labeled.parquet"

                if not feature_path.exists() or not normalized_path.exists():
                    log.warning("Feature matrix or normalized events not found")
                    return self._basic_enrichment(alert)

                feature_df = pd.read_parquet(feature_path)
                feature_df["window"] = pd.to_datetime(feature_df["window"], utc=True)
                
                normalized_df = pd.read_parquet(normalized_path)
                normalized_df["event_time"] = pd.to_datetime(normalized_df["event_time"], utc=True)

                # Convert alert to Series for enricher
                alert_series = pd.Series({
                    "user_name": alert.user_name,
                    "window": alert.window,
                    "ensemble_score": alert.ensemble_score,
                    "if_norm": alert.if_norm,
                    "lof_norm": alert.lof_norm,
                    "ae_norm": alert.ae_norm,
                    "vote_count": alert.vote_count,
                    "attack_name": alert.attack_name,
                    "is_attack": alert.is_attack,
                })

                # Get enrichment payload
                payload = self.alert_enricher.enrich(
                    alert_series, feature_df, normalized_df
                )

                return EnrichedAlert(
                    alert=alert,
                    detection=payload.get("detection", {}),
                    rag_retrieval=payload.get("rag_retrieval", {}),
                    behavioral_context=payload.get("behavioral_context", {}),
                    llm_analysis=payload.get("llm_analysis"),
                )

            except Exception as e:
                log.error(f"Full enrichment failed: {e}")
                return self._basic_enrichment(alert)

        # Fallback to basic enrichment without Neo4j
        return self._basic_enrichment(alert)

    def _basic_enrichment(self, alert: Alert) -> EnrichedAlert:
        """
        Basic enrichment without Neo4j (uses only ChromaDB).
        """
        detection = {
            "techniques": [],
            "matched_patterns": [],
            "primary_playbooks": [],
        }

        rag_retrieval = {
            "similar_past_incidents": [],
            "threat_context": [],
        }

        behavioral_context = {
            "ensemble_score": alert.ensemble_score,
            "model_scores": {
                "isolation_forest": alert.if_norm,
                "lof": alert.lof_norm,
                "autoencoder": alert.ae_norm,
            },
            "vote_count": alert.vote_count,
        }

        # Try to get similar incidents from ChromaDB
        if self.chroma_client and self.embedder:
            try:
                col = self.chroma_client.get_collection("behavioral_incidents")
                
                # Create query based on alert
                query = f"User {alert.user_name} at {alert.window} with score {alert.ensemble_score:.2f}"
                query_embedding = self.embedder.encode(query).tolist()

                results = col.query(
                    query_embeddings=[query_embedding],
                    n_results=3,
                )

                if results["documents"] and len(results["documents"]) > 0:
                    for i, doc in enumerate(results["documents"][0]):
                        metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                        distance = results["distances"][0][i] if results["distances"] else 1.0
                        similarity = 1.0 / (1.0 + distance)

                        rag_retrieval["similar_past_incidents"].append({
                            "content": doc,
                            "metadata": metadata,
                            "similarity": round(similarity, 3),
                        })

            except Exception as e:
                log.warning(f"Failed to get similar incidents: {e}")

        return EnrichedAlert(
            alert=alert,
            detection=detection,
            rag_retrieval=rag_retrieval,
            behavioral_context=behavioral_context,
            llm_analysis=None,
        )

    def get_playbooks(self) -> List[Dict[str, Any]]:
        """Load all playbooks from knowledge base"""
        playbook_path = PROJECT_ROOT / "knowledge_base" / "playbooks.json"
        
        if not playbook_path.exists():
            return []

        try:
            with open(playbook_path, "r") as f:
                playbooks = json.load(f)
            return playbooks
        except Exception as e:
            log.error(f"Failed to load playbooks: {e}")
            return []

    def get_techniques(self) -> List[Dict[str, Any]]:
        """Load MITRE ATT&CK techniques"""
        technique_path = PROJECT_ROOT / "knowledge_base" / "mitre_techniques.json"
        
        if not technique_path.exists():
            return []

        try:
            with open(technique_path, "r") as f:
                techniques = json.load(f)
            return techniques
        except Exception as e:
            log.error(f"Failed to load techniques: {e}")
            return []


# Singleton instance
_rag_service = None


def get_rag_service() -> RAGService:
    """Get or create RAGService singleton"""
    global _rag_service
    if _rag_service is None:
        _rag_service = RAGService()
    return _rag_service

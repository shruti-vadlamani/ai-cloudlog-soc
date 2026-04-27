"""
backend/services/rag_service.py
=================================
Service layer for RAG queries and alert enrichment
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
from rag_ingestion.neo4j_env import get_neo4j_config

from backend.models.schemas import (
    EnrichedAlert,
    Alert,
    RAGQueryResponse,
    RAGQueryResult,
)
from backend.services.vertex_ai_client import get_vertex_ai_client

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# ADD THIS — static system prompt for the SOC AI
# ─────────────────────────────────────────────
SOC_SYSTEM_PROMPT = """You are an expert AI Security Analyst embedded in a 
cloud-based Security Operations Center (SOC) monitoring AWS environments. 
You have deep knowledge of:
- AWS CloudTrail log analysis and event interpretation
- MITRE ATT&CK framework techniques, tactics, and procedures (TTPs)
- Anomaly detection using Isolation Forest, LOF, and Autoencoder models
- IAM privilege escalation, lateral movement, data exfiltration patterns
- Incident response playbooks for cloud environments
- Threat intelligence and behavioral analytics

Your job is to help SOC analysts investigate alerts, understand attack patterns, 
and take decisive action. Always be specific, technical, and actionable.

RULES:
- Use ONLY the retrieved context provided below to answer. Do not hallucinate.
- If the context does not contain enough information, say so clearly.
- Always reference the MITRE ATT&CK technique ID when relevant (e.g., T1078).
- Structure your answers clearly for a security analyst reading under time pressure.
- Never give vague answers like "it depends" — always give concrete next steps.
"""

# ─────────────────────────────────────────────
# QUERY-TYPE SPECIFIC PROMPT TEMPLATES
# ─────────────────────────────────────────────
PROMPT_TEMPLATES = {

    "technique_lookup": """
{system}

## RETRIEVED CONTEXT:
{context}

## ANALYST QUESTION:
{query}

## YOUR RESPONSE FORMAT:
**MITRE Technique:** [ID and Name]
**Tactic:** [Which tactic this belongs to]
**What it means in AWS:** [2-3 sentence explanation]
**CloudTrail Events to Watch:** [Specific API calls]
**Detection Signals:** [Concrete indicators]
**Immediate Response Steps:**
1. [Step 1]
2. [Step 2]
3. [Step 3]
**Severity:** [CRITICAL / HIGH / MEDIUM / LOW]
""",

    "alert_investigation": """
{system}

## RETRIEVED CONTEXT FROM KNOWLEDGE BASE:
{context}

## ALERT DETAILS:
{query}

## YOUR RESPONSE FORMAT:
**Likely Attack Pattern:** [Name and MITRE ID]
**Why This Is Suspicious:** [Explain what the anomaly models detected]
**Blast Radius:** [What could the attacker do if this is real]
**Investigation Steps:**
1. [What to check first in CloudTrail]
2. [What to check second]
3. [Pivoting steps]
**Containment Actions:**
1. [Immediate containment]
2. [Secondary containment]
**False Positive Check:** [How to rule out a false positive]
**Severity Assessment:** [CRITICAL / HIGH / MEDIUM / LOW with reason]
""",

    "playbook_lookup": """
{system}

## RETRIEVED PLAYBOOK CONTEXT:
{context}

## ANALYST REQUEST:
{query}

## YOUR RESPONSE FORMAT:
**Playbook:** [Name]
**Trigger Condition:** [When to use this playbook]
**Phase 1 — Immediate (0-15 min):**
- [Action 1]
- [Action 2]
**Phase 2 — Investigation (15-60 min):**
- [Action 1]
- [Action 2]
**Phase 3 — Containment & Recovery:**
- [Action 1]
- [Action 2]
**AWS CLI Commands:**
```bash
[Relevant AWS CLI commands for this scenario]
```
**Escalation Criteria:** [When to escalate to senior analyst or management]
""",

    "detection_explanation": """
{system}

## RETRIEVED CONTEXT:
{context}

## ANALYST QUESTION:
{query}

## YOUR RESPONSE FORMAT:
**Detection Model Triggered:** [Isolation Forest / LOF / Autoencoder / Ensemble]
**What the Model Detected:** [Plain English explanation of why this scored high]
**Ensemble Score Interpretation:** [What the score range means]
**Key Features That Drove This Alert:** [Feature names and why they matter]
**Historical Baseline Context:** [What normal looks like vs what was seen]
**Recommended Threshold Tuning:** [If this looks like a false positive pattern]
""",

    "general_soc": """
{system}

## RETRIEVED CONTEXT:
{context}

## ANALYST QUESTION:
{query}

## YOUR RESPONSE:
Provide a clear, technical, and actionable answer. 
Reference specific MITRE techniques, AWS services, or detection signals where relevant.
End with 2-3 concrete next steps the analyst should take right now.
""",
}

def _detect_query_type(query: str) -> str:
    """
    Classify the query to select the right prompt template.
    Simple keyword-based routing — no ML needed here.
    """
    q = query.lower()
    if any(w in q for w in ["t1", "t2", "technique", "mitre", "ttp", "tactic"]):
        return "technique_lookup"
    if any(w in q for w in ["alert", "anomaly", "score", "flagged", "detected", "suspicious user"]):
        return "alert_investigation"
    if any(w in q for w in ["playbook", "response", "contain", "remediate", "steps", "what should i do"]):
        return "playbook_lookup"
    if any(w in q for w in ["isolation forest", "lof", "autoencoder", "ensemble", "model", "why did", "false positive"]):
        return "detection_explanation"
    return "general_soc"

PROJECT_ROOT = Path(__file__).parent.parent.parent


class RAGService:
    """Service for RAG-powered queries and alert enrichment"""

    def __init__(self):
        self.chroma_client = None
        self.neo4j_driver = None
        self.alert_enricher = None
        self.embedder = None
        self.llm_handler = None
        self._init_rag()
    
    def _init_rag(self):
        """Initialize RAG components (ChromaDB, Neo4j, AlertEnricher, Vertex AI)"""
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer

            chroma_path = os.getenv("CHROMA_PATH", str(PROJECT_ROOT / "chroma_db"))
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

            neo4j_cfg = get_neo4j_config(require_credentials=True)
            uri = neo4j_cfg["uri"]
            auth = (neo4j_cfg["username"], neo4j_cfg["password"])
            neo4j_db = neo4j_cfg.get("database")
            self.neo4j_driver = GraphDatabase.driver(uri, auth=auth)
            
            if self.chroma_client and self.embedder:
                self.alert_enricher = AlertEnricher(
                    self.neo4j_driver,
                    self.chroma_client,
                    self.embedder,
                    neo4j_database=neo4j_db,
                )
                log.info("Alert enricher initialized with Neo4j")
        except ImportError:
            log.warning("neo4j driver not installed")
        except Exception as e:
            log.warning(f"Neo4j connection failed: {e}")
            log.warning("Alert enrichment will be limited without Neo4j")
        
        # Initialize Vertex AI for LLM
        try:
            self.llm_handler = get_vertex_ai_client()
            if self.llm_handler:
                log.info("Vertex AI (Gemini) LLM initialized successfully")
            else:
                log.warning("Failed to initialize Vertex AI - LLM features will be disabled")
        except Exception as e:
            log.warning(f"Vertex AI initialization failed: {e}. LLM features will be disabled.")
            self.llm_handler = None

    def query_knowledge_base(
        self,
        query: str,
        max_results: int = 5,
        collection: Optional[str] = None,
        use_llm: bool = True,
    ) -> RAGQueryResponse:
        """
        Query ChromaDB for relevant knowledge and optionally synthesize with LLM.

        Args:
            query: Natural language query
            max_results: Number of results to return
            collection: Specific collection to query (behavioral_incidents, threat_intelligence)
            use_llm: Whether to use LLM to generate synthesis/explanation
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
        
        # Generate LLM explanation if available and requested
        explanation = None
        if use_llm and results and self.llm_handler:
            explanation = self._generate_explanation(query, results)

        return RAGQueryResponse(
            query=query,
            results=results,
            collection=collection or "all",
            explanation=explanation,
        )
    
    def _generate_explanation(self, query: str, results: List[RAGQueryResult]) -> Optional[str]:
        """
        Use Vertex AI (Gemini) to synthesize query results into a detailed explanation.
        Uses query-type-specific prompt templates for structured SOC responses.
        """
        if not self.llm_handler:
            return None

        try:
            # Build rich context from top results
            context_parts = []
            for i, result in enumerate(results[:5], 1):  # increased to top 5
                source = result.metadata.get("source", "knowledge base")
                technique = result.metadata.get("technique_id", "")
                header = f"[Source {i}: {source}" + (f" | {technique}]" if technique else "]")
                context_parts.append(f"{header}\n{result.content[:600]}")

            context = "\n\n".join(context_parts)

            # Pick the right prompt template based on query type
            query_type = _detect_query_type(query)
            template = PROMPT_TEMPLATES[query_type]

            prompt = template.format(
                system=SOC_SYSTEM_PROMPT,
                context=context,
                query=query,
            )

            log.info(f"Using prompt template: {query_type} for query: {query[:60]}")

            explanation = self.llm_handler.generate_text_sync(
                prompt=prompt,
                temperature=0.2,   # lower = more factual, less creative
                max_tokens=3000,   # increased to ensure complete response without truncation
                top_p=0.85,
            )

            return explanation if explanation else None

        except Exception as e:
            log.warning(f"LLM synthesis failed: {e}")
            return None
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
            with open(playbook_path, "r", encoding="utf-8") as f:
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
            with open(technique_path, "r", encoding="utf-8") as f:
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

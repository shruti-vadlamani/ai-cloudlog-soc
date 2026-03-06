"""
backend/api/rag.py
===================
API endpoints for RAG-powered queries
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends, Body

from backend.models.schemas import (
    RAGQueryRequest,
    RAGQueryResponse,
    Playbook,
)
from backend.services.rag_service import get_rag_service, RAGService

router = APIRouter()


@router.post("/query", response_model=RAGQueryResponse)
def query_knowledge_base(
    request: RAGQueryRequest = Body(...),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Query the RAG knowledge base.

    Searches ChromaDB collections for relevant information:
    - **behavioral_incidents**: Past alert windows with behavioral context
    - **threat_intelligence**: MITRE techniques, AWS-specific indicators

    Example request:
    ```json
    {
        "query": "What are indicators of privilege escalation in AWS?",
        "max_results": 5,
        "collection": "threat_intelligence"
    }
    ```

    Returns semantically similar documents with metadata and similarity scores.
    """
    if not rag_service.chroma_client:
        raise HTTPException(
            status_code=503,
            detail="RAG system not available. Run: python rag_ingestion/ingest_vector_db.py"
        )

    return rag_service.query_knowledge_base(
        query=request.query,
        max_results=request.max_results,
        collection=request.collection,
    )


@router.get("/query", response_model=RAGQueryResponse)
def query_knowledge_base_get(
    q: str = Query(..., min_length=3, description="Search query"),
    max_results: int = Query(5, ge=1, le=20, description="Maximum results"),
    collection: Optional[str] = Query(None, description="Collection to search"),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Query knowledge base via GET request (alternative to POST).

    Example:
    `/api/rag/query?q=privilege+escalation&max_results=5&collection=threat_intelligence`
    """
    if not rag_service.chroma_client:
        raise HTTPException(
            status_code=503,
            detail="RAG system not available. Run: python rag_ingestion/ingest_vector_db.py"
        )

    return rag_service.query_knowledge_base(
        query=q,
        max_results=max_results,
        collection=collection,
    )


@router.get("/playbooks", response_model=List[dict])
def get_playbooks(
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Get all incident response playbooks.

    Returns playbooks for:
    - Compromised credentials
    - S3 data exfiltration
    - Privilege escalation
    - Account enumeration
    - And more...

    Each playbook includes:
    - Triage questions
    - Investigation steps
    - Containment actions
    - CLI commands
    - MITRE techniques covered
    """
    playbooks = rag_service.get_playbooks()
    if not playbooks:
        raise HTTPException(
            status_code=404,
            detail="Playbooks not found. Check knowledge_base/playbooks.json"
        )
    return playbooks


@router.get("/playbooks/{playbook_id}", response_model=dict)
def get_playbook_by_id(
    playbook_id: str,
    rag_service: RAGService = Depends(get_rag_service),
):
    """Get specific playbook by ID (e.g., IR-IAM-001)"""
    playbooks = rag_service.get_playbooks()
    
    for pb in playbooks:
        if pb.get("playbook_id") == playbook_id:
            return pb
    
    raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")


@router.get("/techniques", response_model=List[dict])
def get_techniques(
    tactic: Optional[str] = Query(None, description="Filter by tactic (e.g., privilege-escalation)"),
    limit: int = Query(100, ge=1, le=500, description="Maximum results"),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Get MITRE ATT&CK techniques.

    Returns Cloud-focused techniques with:
    - Technique ID (e.g., T1078)
    - Name and description
    - Tactics (privilege-escalation, persistence, etc.)
    - AWS-specific indicators

    Query parameters:
    - `tactic`: Filter by specific tactic
    - `limit`: Maximum number of results
    """
    techniques = rag_service.get_techniques()
    
    if not techniques:
        raise HTTPException(
            status_code=404,
            detail="Techniques not found. Check knowledge_base/mitre_techniques.json"
        )

    # Filter by tactic if specified
    if tactic:
        techniques = [
            t for t in techniques
            if tactic.lower() in [tac.lower() for tac in t.get("tactics", [])]
        ]

    return techniques[:limit]


@router.get("/techniques/{technique_id}", response_model=dict)
def get_technique_by_id(
    technique_id: str,
    rag_service: RAGService = Depends(get_rag_service),
):
    """Get specific MITRE technique by ID (e.g., T1078)"""
    techniques = rag_service.get_techniques()
    
    for tech in techniques:
        if tech.get("technique_id") == technique_id:
            return tech
    
    raise HTTPException(
        status_code=404,
        detail=f"Technique {technique_id} not found"
    )


@router.get("/collections", response_model=List[dict])
def get_collections(
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Get available ChromaDB collections with metadata.

    Returns collection names, document counts, and descriptions.
    """
    if not rag_service.chroma_client:
        raise HTTPException(
            status_code=503,
            detail="ChromaDB not available"
        )

    collections = []
    collection_names = ["behavioral_incidents", "threat_intelligence"]
    
    for name in collection_names:
        try:
            col = rag_service.chroma_client.get_collection(name)
            collections.append({
                "name": name,
                "count": col.count(),
                "description": _get_collection_description(name)
            })
        except Exception:
            pass

    return collections


def _get_collection_description(name: str) -> str:
    """Get human-readable description for collection"""
    descriptions = {
        "behavioral_incidents": "Past alert windows with behavioral features and context",
        "threat_intelligence": "MITRE ATT&CK techniques and AWS-specific detection indicators",
    }
    return descriptions.get(name, "")

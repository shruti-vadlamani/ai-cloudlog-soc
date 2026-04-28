"""
backend/api/rag.py
===================
API endpoints for RAG-powered queries and graph exploration.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends, Body
from fastapi.responses import StreamingResponse
from neo4j import GraphDatabase
from rag_ingestion.neo4j_env import get_neo4j_config
import json

from backend.models.schemas import (
    RAGQueryRequest,
    RAGQueryResponse,
    Playbook,
)
from backend.services.rag_service import get_rag_service, RAGService
from backend.services.pdf_service import get_pdf_service, PDFService

log = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health", response_model=dict)
def graph_health_check():
    """Check Neo4j connection and graph statistics."""
    try:
        driver, session = _graph_session()
        
        stats = session.run("""
            MATCH (n)
            WITH labels(n)[0] as label, count(n) as count
            RETURN label, count
            ORDER BY count DESC
        """).data()
        
        total_nodes = sum(s['count'] for s in stats)
        edge_stats = session.run("""
            MATCH ()-[r]->()
            WITH type(r) as rel_type, count(r) as count
            RETURN rel_type, count
            ORDER BY count DESC
        """).data()
        
        total_edges = sum(e['count'] for e in edge_stats)
        
        session.close()
        driver.close()
        
        return {
            "status": "ok",
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "node_types": stats,
            "edge_types": edge_stats,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "total_nodes": 0,
            "total_edges": 0,
        }


def _graph_session():
    cfg = get_neo4j_config(require_credentials=True)
    driver = GraphDatabase.driver(
        cfg["uri"],
        auth=(cfg["username"], cfg["password"]),
    )
    session_kwargs = {"database": cfg.get("database")} if cfg.get("database") else {}
    return driver, driver.session(**session_kwargs)


def _node_key(label: str, props: dict) -> str:
    if label == "User":
        return str(props.get("name", "unknown"))
    if label == "Window":
        return str(props.get("window_id", "unknown"))
    if label == "DetectionPattern":
        return str(props.get("id", "unknown"))
    if label == "MITRETechnique":
        return str(props.get("technique_id", "unknown"))
    if label == "Playbook":
        return str(props.get("id", "unknown"))
    return str(props.get("id", props.get("name", "unknown")))


def _node_label(label: str, props: dict) -> str:
    if label == "User":
        return str(props.get("name", "User"))
    if label == "Window":
        user = str(props.get("user_name", "user"))
        window = str(props.get("window", ""))
        short = window.replace("T", " ")
        if "+" in short:
            short = short.split("+")[0]
        if len(short) >= 16:
            short = short[5:16]
        return f"{user} {short}".strip()
    if label == "DetectionPattern":
        return str(props.get("name", "Pattern"))
    if label == "MITRETechnique":
        return str(props.get("technique_id", "Technique"))
    if label == "Playbook":
        return str(props.get("id", "Playbook"))
    return str(props.get("name", label))


def _serialize_node(node):
    if node is None:
        return None
    labels = list(node.labels)
    label = labels[0] if labels else "Node"
    props = dict(node)
    key = _node_key(label, props)
    return {
        "id": f"{label}:{key}",
        "type": label,
        "key": key,
        "label": _node_label(label, props),
        "properties": props,
    }


def _add_node(nodes: dict, node):
    payload = _serialize_node(node)
    if not payload:
        return
    nodes[payload["id"]] = payload


def _add_edge(edges: dict, rel, src_node, dst_node):
    if rel is None or src_node is None or dst_node is None:
        return
    src = _serialize_node(src_node)
    dst = _serialize_node(dst_node)
    if not src or not dst:
        return
    rel_type = rel.type
    edge_id = f"{rel_type}:{src['id']}->{dst['id']}"
    edges[edge_id] = {
        "id": edge_id,
        "source": src["id"],
        "target": dst["id"],
        "type": rel_type,
        "properties": dict(rel),
    }


def _match_context(label: str, props: dict) -> str:
    if label == "Window":
        return (
            f"window={props.get('window', props.get('window_start', 'unknown'))}, "
            f"score={props.get('ensemble_score', 'n/a')}, "
            f"attack={props.get('attack_name', 'unknown')}"
        )
    if label == "DetectionPattern":
        return f"severity={props.get('severity', 'unknown')}, threshold={props.get('anomaly_score_threshold', 'n/a')}"
    if label == "MITRETechnique":
        return f"technique={props.get('technique_id', props.get('id', 'unknown'))}"
    if label == "Playbook":
        return f"playbook={props.get('id', 'unknown')}"
    if label == "User":
        return f"user={props.get('name', 'unknown')}"
    return "related entity"


def _graph_match_score(query: str, match: dict) -> int:
    q = (query or "").strip().lower()
    if not q:
        return 0

    props = match.get("properties", {}) or {}
    text_candidates = [
        str(match.get("id", "")),
        str(match.get("key", "")),
        str(match.get("label", "")),
        str(match.get("type", "")),
        str(props.get("technique_id", "")),
        str(props.get("pattern_id", "")),
        str(props.get("playbook_id", "")),
        str(props.get("id", "")),
        str(props.get("name", "")),
        str(props.get("attack_name", "")),
        str(props.get("window_id", "")),
        str(props.get("user_name", "")),
        str(props.get("description", "")),
    ]
    normalized_candidates = [value.strip().lower() for value in text_candidates if value]

    type_priority = {
        "MITRETechnique": 500,
        "DetectionPattern": 400,
        "Playbook": 300,
        "Window": 200,
        "User": 100,
    }.get(match.get("type"), 0)

    if q in normalized_candidates:
        return 1000 + type_priority

    score = type_priority
    if any(candidate == q for candidate in normalized_candidates):
        score += 250
    if any(q in candidate for candidate in normalized_candidates):
        score += 75

    token_hits = 0
    for token in q.split():
        if len(token) < 2:
            continue
        if any(token in candidate for candidate in normalized_candidates):
            token_hits += 1
    score += token_hits * 20

    return score


@router.get("/graph/subgraph", response_model=dict)
def get_graph_subgraph(
    attack_type: str = Query("", description="Filter by attack_name from Window nodes"),
    technique_id: str = Query("", description="Filter by MITRE technique id"),
    limit: int = Query(30, ge=5, le=80, description="Max seed windows"),
):
    """Return a compact graph for initial rendering in the explorer."""
    driver, session = _graph_session()
    try:
        rows = session.run(
            """
            MATCH (w:Window)
            WHERE ($attack_type = '' OR w.attack_name = $attack_type)
              AND ($technique_id = '' OR EXISTS {
                    MATCH (w)-[:TRIGGERS_INDICATOR]->(:DetectionPattern)<-[:DETECTED_BY]-(t:MITRETechnique {technique_id: $technique_id})
                  })
            WITH w
            ORDER BY w.ensemble_score DESC
            LIMIT $limit
            OPTIONAL MATCH (u:User)-[hw:HAD_WINDOW]->(w)
            OPTIONAL MATCH (w)-[ti:TRIGGERS_INDICATOR]->(d:DetectionPattern)
            OPTIONAL MATCH (d)<-[db:DETECTED_BY]-(t:MITRETechnique)
            OPTIONAL MATCH (d)-[tr:TRIGGERS]->(p:Playbook)
            RETURN u,w,d,t,p,
                   hw, startNode(hw) as hw_src, endNode(hw) as hw_dst,
                   ti, startNode(ti) as ti_src, endNode(ti) as ti_dst,
                   db, startNode(db) as db_src, endNode(db) as db_dst,
                   tr, startNode(tr) as tr_src, endNode(tr) as tr_dst
            """,
            attack_type=attack_type,
            technique_id=technique_id,
            limit=limit,
        )

        nodes = {}
        edges = {}
        for rec in rows:
            for key in ["u", "w", "d", "t", "p"]:
                _add_node(nodes, rec.get(key))

            _add_edge(edges, rec.get("hw"), rec.get("hw_src"), rec.get("hw_dst"))
            _add_edge(edges, rec.get("ti"), rec.get("ti_src"), rec.get("ti_dst"))
            _add_edge(edges, rec.get("db"), rec.get("db_src"), rec.get("db_dst"))
            _add_edge(edges, rec.get("tr"), rec.get("tr_src"), rec.get("tr_dst"))

        return {
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
        }
    finally:
        session.close()
        driver.close()


@router.post("/graph/expand", response_model=dict)
def expand_graph_node(
    node_type: str = Body(..., embed=True),
    node_key: str = Body(..., embed=True),
    limit: int = Body(30, embed=True),
):
    """Expand one-hop neighbors for a selected node in the graph explorer."""
    label_map = {
        "User": ("User", "name"),
        "Window": ("Window", "window_id"),
        "DetectionPattern": ("DetectionPattern", "id"),
        "MITRETechnique": ("MITRETechnique", "technique_id"),
        "Playbook": ("Playbook", "id"),
    }
    if node_type not in label_map:
        raise HTTPException(status_code=400, detail=f"Unsupported node_type: {node_type}")

    label, key_prop = label_map[node_type]
    driver, session = _graph_session()
    try:
        rows = session.run(
            f"""
            MATCH (n:{label} {{{key_prop}: $node_key}})-[r]-(m)
            RETURN n, m, r, startNode(r) as r_src, endNode(r) as r_dst
            LIMIT $limit
            """,
            node_key=node_key,
            limit=max(1, min(limit, 120)),
        )

        nodes = {}
        edges = {}
        for rec in rows:
            _add_node(nodes, rec.get("n"))
            _add_node(nodes, rec.get("m"))
            _add_edge(edges, rec.get("r"), rec.get("r_src"), rec.get("r_dst"))

        return {
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
        }
    finally:
        session.close()
        driver.close()


@router.post("/graph/query", response_model=dict)
def query_graph_insights(
    query: str = Body(..., embed=True, min_length=2),
    limit: int = Body(25, embed=True, ge=5, le=80),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Search graph with natural language and return graph + LLM explanation.
    
    Returns:
    - Graph nodes and edges for visualization
    - LLM-synthesized explanation about what was found
    - Specific matches if available
    """
    import logging
    log = logging.getLogger("rag_graph_query")
    
    q = query.strip().lower()
    if not q:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    # Extract meaningful keywords from query (remove stop words)
    stop_words = {'what', 'is', 'the', 'a', 'an', 'are', 'and', 'or', 'of', 'in', 'on', 'at', 'how', 'why', 'when', 'where', 'can', 'i', 'you', 'we', 'they', 'about', 'show', 'tell', 'find'}
    keywords = [w for w in q.split() if w not in stop_words and len(w) > 2]
    
    # Synonym mapping for better matching
    synonym_map = {
        'mitre': ['technique', 'att&ck', 'tactic'],
        'alert': ['detection', 'anomaly', 'window'],
        'user': ['identity', 'account', 'principal'],
        'privilege': ['escalation', 'permission', 'access'],
        'attack': ['technique', 'pattern', 'threat'],
        'playbook': ['response', 'procedure', 'runbook'],
        'threat': ['attack', 'incident', 'pattern'],
    }
    
    expanded_keywords = set(keywords)
    for keyword in keywords:
        if keyword in synonym_map:
            expanded_keywords.update(synonym_map[keyword])
    
    log.info(f"Query keywords: {keywords}, Expanded: {expanded_keywords}")

    driver, session = _graph_session()
    try:
        # First try: enhanced keyword match with multiple term matching
        log.info(f"Running keyword query for: {query}")
        rows = list(session.run(
            """
            MATCH (n)
            WHERE any(lbl IN labels(n) WHERE lbl IN ['User','Window','DetectionPattern','MITRETechnique','Playbook','Technique','TechniqueNode'])
              AND (
                toLower(coalesce(n.name, '')) CONTAINS $q
                OR toLower(coalesce(n.id, '')) CONTAINS $q
                OR toLower(coalesce(n.technique_id, '')) CONTAINS $q
                OR toLower(coalesce(n.attack_name, '')) CONTAINS $q
                OR toLower(coalesce(n.window_id, '')) CONTAINS $q
                OR toLower(coalesce(n.user_name, '')) CONTAINS $q
                OR toLower(coalesce(n.description, '')) CONTAINS $q
                OR any(keyword IN $expanded_keywords WHERE toLower(coalesce(n.name, '') + ' ' + coalesce(n.description, '')) CONTAINS keyword)
              )
            WITH n
            LIMIT $limit
            OPTIONAL MATCH (n)-[r]-(m)
            RETURN n, m, r, startNode(r) as r_src, endNode(r) as r_dst
            LIMIT $limit * 8
            """,
            q=q,
            expanded_keywords=list(expanded_keywords),
            limit=limit,
        ))
        
        log.info(f"Keyword query returned {len(rows)} rows")

        nodes = {}
        edges = {}
        matches = {}

        for rec in rows:
            n = rec.get("n")
            m = rec.get("m")

            _add_node(nodes, n)
            _add_node(nodes, m)
            _add_edge(edges, rec.get("r"), rec.get("r_src"), rec.get("r_dst"))

            if n is not None:
                n_payload = _serialize_node(n)
                if n_payload:
                    matches[n_payload["id"]] = {
                        "id": n_payload["id"],
                        "type": n_payload["type"],
                        "key": n_payload["key"],
                        "label": n_payload["label"],
                        "context": _match_context(n_payload["type"], n_payload.get("properties", {})),
                    }
        
        log.info(f"Matched {len(matches)} entities from keyword query")
        
        # If no direct matches, try broader traversal for natural language queries
        if not matches:
            log.info("No keyword matches found, trying fallback to knowledge graph overview")
            # Get ALL key entity types (not just limited sample)
            all_nodes_result = session.run(
                """
                MATCH (n)
                WHERE any(lbl IN labels(n) WHERE lbl IN ['User','Window','DetectionPattern','MITRETechnique','Playbook','Technique','TechniqueNode'])
                RETURN n
                LIMIT 50
                """
            )
            
            sample_rows = list(all_nodes_result)
            log.info(f"Retrieved {len(sample_rows)} sample nodes from knowledge graph")
            
            if sample_rows:
                # Add all sample nodes
                for rec in sample_rows:
                    n = rec.get("n")
                    if n:
                        _add_node(nodes, n)
                        log.debug(f"Added node: {n.get('name', n.get('id', 'unknown'))}")
                
                # Get some edges connecting them
                neighbors_result = session.run(
                    """
                    MATCH (n)-[r]-(m)
                    WHERE any(lbl IN labels(n) WHERE lbl IN ['User','Window','DetectionPattern','MITRETechnique','Playbook','Technique','TechniqueNode'])
                      AND any(lbl IN labels(m) WHERE lbl IN ['User','Window','DetectionPattern','MITRETechnique','Playbook','Technique','TechniqueNode'])
                    RETURN n, r, m
                    LIMIT 100
                    """
                )
                
                for nbr_rec in neighbors_result:
                    n = nbr_rec.get("n")
                    m = nbr_rec.get("m")
                    r = nbr_rec.get("r")
                    _add_node(nodes, n)
                    _add_node(nodes, m)
                    _add_edge(edges, r, n, m)
                
                log.info(f"Added {len(edges)} edges from fallback query")
            else:
                log.warning("No nodes found even in fallback query")

        matched_values = list(matches.values())
        matched_values.sort(key=lambda item: _graph_match_score(query, item), reverse=True)
        focus_match = matched_values[0] if matched_values else None
        type_counts = {}
        for item in matched_values:
            t = item.get("type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        dominant = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        dominant_text = ", ".join([f"{k} ({v})" for k, v in dominant]) if dominant else "no dominant type"

        # Determine summary message
        if matched_values:
            summary = (
                f"Found {len(matched_values)} relevant entities and {len(edges)} relationships for '{query}'. "
                f"Most matches: {dominant_text}."
            )
        elif nodes:
            summary = (
                f"No specific matches for '{query}', showing knowledge graph overview "
                f"with {len(nodes)} entities and {len(edges)} relationships."
            )
        else:
            summary = (
                f"No graph entities matched '{query}'. Try technique IDs, attack names, user names, or playbook IDs."
            )

        insights = []
        if matched_values:
            top_windows = [m for m in matched_values if m.get("type") == "Window"]
            top_patterns = [m for m in matched_values if m.get("type") == "DetectionPattern"]
            top_techniques = [m for m in matched_values if m.get("type") == "MITRETechnique"]
            if top_windows:
                insights.append(
                    f"{len(top_windows)} suspicious windows matched. Inspect their linked patterns and playbooks first."
                )
            if top_patterns:
                insights.append(
                    f"{len(top_patterns)} detection patterns matched. Validate thresholds and false-positive sources."
                )
            if top_techniques:
                ids = ", ".join([x.get("key", "") for x in top_techniques[:4]])
                insights.append(f"Mapped ATT&CK techniques include: {ids}.")
            insights.append("Click a matched node to open analyst guidance and route trace in the side panel.")
        else:
            if len(nodes) > 0:
                insights.append(f"Showing {len(nodes)} entities from the knowledge graph.")
                insights.append("Hover over nodes to inspect details. Double-click to expand neighbors.")
        
        # Generate LLM explanation about the graph findings
        explanation = _generate_graph_explanation(query, nodes, edges, matched_values, rag_service)

        log.info(f"Returning {len(nodes)} nodes and {len(edges)} edges")
        
        return {
            "summary": summary,
            "insights": insights,
            "matches": matched_values[:12],
            "focus_match": focus_match,
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
            "explanation": explanation,  # LLM-synthesized explanation
        }
    except Exception as e:
        log.error(f"Graph query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Graph query error: {str(e)}")
    finally:
        session.close()
        driver.close()


def _generate_graph_explanation(query: str, nodes: dict, edges: dict, matches: list, rag_service: RAGService) -> Optional[str]:
    """
    Use Vertex AI (Gemini) to generate a structured SOC analyst response about graph findings.
    """
    if not rag_service.llm_handler:
        return None
    
    try:
        # Build comprehensive context from the graph
        node_summary = _summarize_nodes(nodes)
        edge_summary = _summarize_edges(edges)
        match_summary = _summarize_matches(matches) if matches else "No specific entity matches."
        
        # Build detailed node context with properties and relationships
        detailed_nodes = []
        for node_id, node_data in list(nodes.items())[:10]:  # Top 10 nodes
            node_type = node_data.get("type", "Unknown")
            node_name = node_data.get("label", node_data.get("key", node_id))
            node_props = node_data.get("properties", {})
            detailed_nodes.append(f"  - {node_name} ({node_type}): {str(node_props)[:200]}")
        
        detailed_nodes_text = "\n".join(detailed_nodes) if detailed_nodes else "  No detailed node information available"
        
        # Build edge context showing relationships
        edge_details = []
        for edge_data in list(edges.values())[:15]:  # Top 15 edges
            edge_type = edge_data.get("label", "relates_to")
            source = edge_data.get("source_label", "Unknown")
            target = edge_data.get("target_label", "Unknown")
            edge_details.append(f"  - {source} --[{edge_type}]--> {target}")
        
        edges_text = "\n".join(edge_details) if edge_details else "  No relationship details available"
        
        soc_system_prompt = """You are an expert AWS Cloud Security Operations Center (SOC) analyst with deep expertise in:
- AWS CloudTrail log analysis and event pattern recognition
- MITRE ATT&CK framework (techniques, tactics, procedures)
- IAM privilege escalation, lateral movement, and data exfiltration patterns
- Anomaly detection models and alert correlation
- Incident response procedures and AWS-specific containment actions
- Threat intelligence correlation

You are analyzing a knowledge graph query to help security analysts investigate potential threats.
Answer ONLY using the provided graph context. Be specific, technical, and immediately actionable."""

        context = f"""KNOWLEDGE GRAPH ANALYSIS:
        
Matched Entities: {match_summary}

Entity Types Found:
{node_summary}

Key Relationships:
{edge_summary}

Detailed Entities (top 10):
{detailed_nodes_text}

Relationship Details (top 15):
{edges_text}"""

        prompt = f"""{soc_system_prompt}

{context}

ANALYST QUESTION: {query}

REQUIRED RESPONSE FORMAT (fill all sections):

### Key Findings
[What the graph shows about the question - 2-3 sentences]

### Entity Analysis
[List matched entity types and their relevance - use bullet points]

### Relationship Patterns
[Describe key relationships visible in the graph and security implications]

### MITRE ATT&CK Mapping
[If techniques are found, list technique IDs and tactics - otherwise state "Not directly applicable"]

### CloudTrail Detection Signals
[AWS API calls or events to monitor based on this graph pattern]

### Risk Assessment
Severity: [CRITICAL | HIGH | MEDIUM | LOW]
Blast Radius: [Potential impact if this pattern is malicious]

### Immediate Next Steps
1. [First action for analyst]
2. [Second action for analyst]
3. [Third action for analyst]

Be concise and specific - no generic statements."""

        log.info(f"Graph explanation: using {len(nodes)} nodes, {len(edges)} edges, {len(matches)} matches")

        explanation = rag_service.llm_handler.generate_text_sync(
            prompt=prompt,
            temperature=0.2,  # Deterministic for consistency
            max_tokens=3000,  # Increased to ensure complete response without truncation
            top_p=0.9,
        )
        return explanation if explanation else None
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Graph explanation generation failed: {e}")
        return None


def _summarize_nodes(nodes: dict) -> str:
    """Create a summary of node types in the graph."""
    type_counts = {}
    for node in nodes.values():
        t = node.get("type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    
    if not type_counts:
        return "No entities"
    
    return ", ".join([f"{k} ({v})" for k, v in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)])


def _summarize_edges(edges: dict) -> str:
    """Create a summary of edge types in the graph."""
    edge_types = {}
    for edge in edges.values():
        t = edge.get("type", "UNKNOWN")
        edge_types[t] = edge_types.get(t, 0) + 1
    
    if not edge_types:
        return "No relationships"
    
    return ", ".join([f"{k} ({v})" for k, v in sorted(edge_types.items(), key=lambda x: x[1], reverse=True)])


def _summarize_matches(matches: list) -> str:
    """Create a summary of matched entities."""
    if not matches:
        return "No matches"
    
    match_types = {}
    for match in matches[:10]:  # Top 10
        t = match.get("type", "Unknown")
        match_types[t] = match_types.get(t, 0) + 1
    
    return ", ".join([f"{k} ({v})" for k, v in sorted(match_types.items(), key=lambda x: x[1], reverse=True)])


@router.post("/query", response_model=RAGQueryResponse)
def query_knowledge_base(
    request: RAGQueryRequest = Body(...),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Query the RAG knowledge base with optional LLM synthesis.

    Searches ChromaDB collections for relevant information:
    - **behavioral_incidents**: Past alert windows with behavioral context
    - **threat_intelligence**: MITRE techniques, AWS-specific indicators

    If `use_llm=true`, uses Google Vertex AI (Gemini) to synthesize results into a detailed explanation.

    Example request:
    ```json
    {
        "query": "What are indicators of privilege escalation in AWS?",
        "max_results": 5,
        "collection": "threat_intelligence",
        "use_llm": true
    }
    ```

    Returns semantically similar documents with metadata, similarity scores, and optional LLM explanation.
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
        use_llm=request.use_llm,
    )


@router.get("/query", response_model=RAGQueryResponse)
def query_knowledge_base_get(
    q: str = Query(..., min_length=3, description="Search query"),
    max_results: int = Query(5, ge=1, le=20, description="Maximum results"),
    collection: Optional[str] = Query(None, description="Collection to search"),
    use_llm: bool = Query(True, description="Use LLM to synthesize results"),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Query knowledge base via GET request with optional LLM synthesis.

    Example:
    `/api/rag/query?q=privilege+escalation&max_results=5&collection=threat_intelligence&use_llm=true`
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
        use_llm=use_llm,
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


@router.post("/export/pdf")
def export_query_results_to_pdf(
    request: RAGQueryRequest = Body(...),
    rag_service: RAGService = Depends(get_rag_service),
    pdf_service: PDFService = Depends(get_pdf_service),
):
    """
    Export RAG query results to a PDF file.

    Takes the same request as /api/rag/query but returns a downloadable PDF
    containing formatted query results with metadata, similarity scores, and
    professional formatting.

    Returns:
        PDF file as binary stream
    """
    # Get query results
    response = rag_service.query_knowledge_base(
        query=request.query,
        max_results=request.max_results,
        collection=request.collection,
    )

    # Convert results to dict format for PDF generation
    results_list = [
        {
            "content": r.content,
            "metadata": r.metadata,
            "similarity": r.similarity,
        }
        for r in response.results
    ]

    # Generate PDF
    try:
        pdf_bytes = pdf_service.generate_query_report(
            query=response.query,
            results=results_list,
            collection=response.collection,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Return as downloadable file
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="query_report_{request.query[:30].replace(" ", "_")}.pdf"'
        },
    )


@router.post("/export/summary")
def export_query_summary(
    request: RAGQueryRequest = Body(...),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Export RAG query results as a JSON summary.

    Returns compact JSON with metadata about the query, results count,
    and all results with similarity scores for programmatic processing.

    Returns:
        JSON object containing query metadata and results
    """
    response = rag_service.query_knowledge_base(
        query=request.query,
        max_results=request.max_results,
        collection=request.collection,
    )

    return {
        "query": response.query,
        "collection": response.collection,
        "result_count": len(response.results),
        "results": [
            {
                "content": r.content,
                "metadata": r.metadata,
                "similarity": r.similarity,
            }
            for r in response.results
        ],
    }

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
):
    """
    Search the knowledge graph using keyword matching and return a focused subgraph.

    Phase 1: keyword-match candidate nodes (no LLM).
    Phase 2: pick the single best-matching node as the focus, then expand
             only its 1-hop neighborhood — exactly like Neo4j Desktop.

    Returns focus_match so the frontend can select/highlight the node.
    """
    log = logging.getLogger("rag_graph_query")

    q = query.strip().lower()
    if not q:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    # ── keyword extraction (remove stop words) ──────────────────────────────
    stop_words = {
        'what', 'is', 'the', 'a', 'an', 'are', 'and', 'or', 'of', 'in', 'on', 'at',
        'how', 'why', 'when', 'where', 'can', 'i', 'you', 'we', 'they', 'about',
        'show', 'tell', 'find', 'me', 'for', 'to', 'with', 'from', 'by', 'this',
        'that', 'these', 'those', 'it', 'as',
    }
    keywords = [w for w in q.split() if w not in stop_words and len(w) > 2]

    synonym_map = {
        'mitre':     ['technique', 'att&ck', 'tactic'],
        'alert':     ['detection', 'anomaly', 'window'],
        'user':      ['identity', 'account', 'principal'],
        'privilege': ['escalation', 'permission', 'access'],
        'attack':    ['technique', 'pattern', 'threat'],
        'playbook':  ['response', 'procedure', 'runbook'],
        'threat':    ['attack', 'incident', 'pattern'],
    }
    expanded_keywords = set(keywords)
    for kw in keywords:
        expanded_keywords.update(synonym_map.get(kw, []))

    log.info(f"Graph query '{query}' → keywords={keywords} expanded={expanded_keywords}")

    # ── candidate limit: keep small so Cypher LIMIT is always a plain integer ─
    candidate_limit = max(5, min(limit, 30))       # plain int — valid Cypher
    neighbor_limit  = max(30, min(limit * 4, 120)) # plain int — valid Cypher

    driver, session = _graph_session()
    try:
        # ── PHASE 1: find candidate nodes that match the keyword ─────────────
        log.info(f"Phase 1: keyword candidate search (limit={candidate_limit})")
        candidate_rows = list(session.run(
            """
            MATCH (n)
            WHERE any(lbl IN labels(n) WHERE lbl IN
                  ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
              AND (
                toLower(coalesce(n.name,        '')) CONTAINS $q
                OR toLower(coalesce(n.id,          '')) CONTAINS $q
                OR toLower(coalesce(n.technique_id, '')) CONTAINS $q
                OR toLower(coalesce(n.attack_name,  '')) CONTAINS $q
                OR toLower(coalesce(n.window_id,    '')) CONTAINS $q
                OR toLower(coalesce(n.user_name,    '')) CONTAINS $q
                OR toLower(coalesce(n.description,  '')) CONTAINS $q
                OR any(kw IN $expanded_keywords
                       WHERE toLower(coalesce(n.name, '') + ' ' + coalesce(n.description, ''))
                             CONTAINS kw)
              )
            RETURN n
            LIMIT $candidate_limit
            """,
            q=q,
            expanded_keywords=list(expanded_keywords),
            candidate_limit=candidate_limit,
        ))
        log.info(f"Phase 1 returned {len(candidate_rows)} candidates")

        # ── score each candidate and pick the best focus node ────────────────
        def _score(payload: dict) -> int:
            """Simple keyword relevance score — higher is better."""
            props = payload.get("properties", {})
            text_fields = [
                str(payload.get("key", "")),
                str(payload.get("label", "")),
                str(props.get("name", "")),
                str(props.get("technique_id", "")),
                str(props.get("attack_name", "")),
                str(props.get("id", "")),
                str(props.get("description", "")),
            ]
            combined = " ".join(text_fields).lower()
            # Type priority: more specific types rank higher
            type_bonus = {
                "MITRETechnique": 500, "DetectionPattern": 400,
                "Playbook": 300, "Window": 200, "User": 100,
            }.get(payload.get("type", ""), 0)
            # Exact full-query match
            if q in combined:
                return 1000 + type_bonus
            # Keyword token hits
            score = type_bonus
            for token in q.split():
                if len(token) >= 2 and token in combined:
                    score += 60
            return score

        candidates = []
        for rec in candidate_rows:
            n = rec.get("n")
            if n is None:
                continue
            payload = _serialize_node(n)
            if payload:
                candidates.append(payload)

        # Rank and pick the single best focus node
        candidates.sort(key=_score, reverse=True)
        focus_node_payload = candidates[0] if candidates else None

        nodes: dict = {}
        edges: dict = {}
        matches: list = []

        if focus_node_payload:
            # ── PHASE 2: expand ONLY the focus node's 1-hop neighborhood ────
            focus_type = focus_node_payload["type"]
            focus_props = focus_node_payload.get("properties", {})

            label_map = {
                "User":             ("User",             "name"),
                "Window":           ("Window",           "window_id"),
                "DetectionPattern": ("DetectionPattern", "id"),
                "MITRETechnique":   ("MITRETechnique",   "technique_id"),
                "Playbook":         ("Playbook",         "id"),
            }
            label, key_prop = label_map.get(focus_type, (focus_type, "id"))
            key_value = focus_props.get(key_prop) or focus_props.get("id") or focus_props.get("name")

            log.info(f"Phase 2: expanding focus node {focus_type}:{key_value} (limit={neighbor_limit})")

            if key_value:
                focus_rows = list(session.run(
                    f"""
                    MATCH (n:{label} {{{key_prop}: $key_value}})-[r]-(m)
                    RETURN n, m, r, startNode(r) as r_src, endNode(r) as r_dst
                    LIMIT $neighbor_limit
                    """,
                    key_value=key_value,
                    neighbor_limit=neighbor_limit,
                ))
                log.info(f"Phase 2 returned {len(focus_rows)} neighbor rows")

                for rec in focus_rows:
                    _add_node(nodes, rec.get("n"))
                    _add_node(nodes, rec.get("m"))
                    _add_edge(edges, rec.get("r"), rec.get("r_src"), rec.get("r_dst"))

            # Build matches list from all candidates (for sidebar display)
            for c in candidates:
                matches.append({
                    "id":      c["id"],
                    "type":    c["type"],
                    "key":     c["key"],
                    "label":   c["label"],
                    "context": _match_context(c["type"], c.get("properties", {})),
                })

        else:
            # ── FALLBACK: no keyword match → overview of first 50 nodes ─────
            log.info("No keyword match — falling back to overview graph")
            overview_rows = list(session.run(
                """
                MATCH (n)
                WHERE any(lbl IN labels(n) WHERE lbl IN
                      ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
                RETURN n
                LIMIT 50
                """
            ))
            for rec in overview_rows:
                _add_node(nodes, rec.get("n"))

            edge_rows = list(session.run(
                """
                MATCH (n)-[r]-(m)
                WHERE any(lbl IN labels(n) WHERE lbl IN
                      ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
                  AND any(lbl IN labels(m) WHERE lbl IN
                      ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
                RETURN n, r, m
                LIMIT 100
                """
            ))
            for rec in edge_rows:
                _add_node(nodes, rec.get("n"))
                _add_node(nodes, rec.get("m"))
                _add_edge(edges, rec.get("r"), rec.get("n"), rec.get("m"))

        # ── build response metadata ──────────────────────────────────────────
        focus_match = {
            "id":      focus_node_payload["id"],
            "type":    focus_node_payload["type"],
            "key":     focus_node_payload["key"],
            "label":   focus_node_payload["label"],
            "context": _match_context(focus_node_payload["type"],
                                      focus_node_payload.get("properties", {})),
        } if focus_node_payload else None

        type_counts: dict = {}
        for m in matches:
            t = m.get("type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        dominant = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        dominant_text = ", ".join(f"{k} ({v})" for k, v in dominant) if dominant else "none"

        if matches:
            summary = (
                f"Found {len(matches)} relevant entities for '{query}'. "
                f"Showing 1-hop neighborhood of best match: {focus_match['label']} ({focus_match['type']}). "
                f"Dominant types: {dominant_text}."
            )
        elif nodes:
            summary = (
                f"No specific match for '{query}'. "
                f"Showing overview graph with {len(nodes)} entities."
            )
        else:
            summary = (
                f"No graph entities matched '{query}'. "
                f"Try technique IDs (e.g. T1078), attack names, user names, or playbook IDs."
            )

        insights = []
        if matches:
            top_windows    = [m for m in matches if m.get("type") == "Window"]
            top_patterns   = [m for m in matches if m.get("type") == "DetectionPattern"]
            top_techniques = [m for m in matches if m.get("type") == "MITRETechnique"]
            if top_windows:
                insights.append(f"{len(top_windows)} suspicious window(s) matched. Inspect linked patterns and playbooks.")
            if top_patterns:
                insights.append(f"{len(top_patterns)} detection pattern(s) matched. Validate thresholds.")
            if top_techniques:
                ids = ", ".join(x.get("key", "") for x in top_techniques[:4])
                insights.append(f"Mapped ATT&CK techniques: {ids}.")
            insights.append("Click a node to view analyst details. Double-click to expand its neighbors.")
        elif nodes:
            insights.append(f"Showing {len(nodes)} entities from the knowledge graph.")
            insights.append("Enter a keyword, technique ID, or attack name to focus the view.")

        log.info(f"Returning focus={focus_match['id'] if focus_match else None}, "
                 f"{len(nodes)} nodes, {len(edges)} edges")

        return {
            "summary":     summary,
            "insights":    insights,
            "matches":     matches[:12],
            "focus_match": focus_match,
            "nodes":       list(nodes.values()),
            "edges":       list(edges.values()),
            "explanation": None,
        }
    except Exception as e:
        log.error(f"Graph query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Graph query error: {str(e)}")
    finally:
        session.close()
        driver.close()


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


@router.post("/graph/nl-query", response_model=dict)
def nl_graph_query(
    query: str = Body(..., embed=True, min_length=5),
    limit: int = Body(20, embed=True, ge=5, le=60),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Natural language query over the knowledge base + knowledge graph.

    Flow:
      1. Query ChromaDB (semantic similarity) with the raw NL question.
      2. Extract entity identifiers (technique IDs, playbook IDs, attack names)
         from the ChromaDB results' metadata.
      3. Query Neo4j for those specific entities and their 1-hop neighborhoods.
      4. Build a comprehensive prompt (ChromaDB context + graph context) and
         call Vertex AI (Gemini) for a structured SOC analyst answer.
      5. Return: answer text + graph nodes/edges + focus_match + sources.

    If Vertex AI is unavailable, the graph data is still returned with a note.
    """
    import re
    nl_log = logging.getLogger("nl_graph_query")
    nl_log.info(f"NL query received: {query[:80]}")

    # ── 1. ChromaDB semantic search ──────────────────────────────────────────
    chroma_results = []
    if rag_service.chroma_client and rag_service.embedder:
        for col_name in ["threat_intelligence", "behavioral_incidents"]:
            try:
                col = rag_service.chroma_client.get_collection(col_name)
                emb = rag_service.embedder.encode(query).tolist()
                res = col.query(query_embeddings=[emb], n_results=5)
                if res.get("documents") and res["documents"][0]:
                    for i, doc in enumerate(res["documents"][0]):
                        meta = (res.get("metadatas") or [[]])[0][i] if res.get("metadatas") else {}
                        dist = (res.get("distances") or [[1.0]])[0][i]
                        chroma_results.append({
                            "content": doc,
                            "metadata": meta,
                            "similarity": round(1.0 / (1.0 + dist), 3),
                            "collection": col_name,
                        })
            except Exception as ce:
                nl_log.warning(f"ChromaDB query failed for {col_name}: {ce}")

        chroma_results.sort(key=lambda x: x["similarity"], reverse=True)
        chroma_results = chroma_results[:8]
        nl_log.info(f"ChromaDB returned {len(chroma_results)} results")

    # ── 2. Extract entity identifiers from chroma metadata + query text ──────
    # Collect candidate search terms: technique IDs, playbook IDs, attack names
    entity_terms = set()

    # From the raw query — regex for common ID patterns
    entity_terms.update(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', query, re.IGNORECASE))
    entity_terms.update(re.findall(r'\bIR-[A-Z]+-\d+\b', query, re.IGNORECASE))
    entity_terms.update(re.findall(r'\bIOC-[A-Z]+-\d+\b', query, re.IGNORECASE))

    # From ChromaDB metadata
    for r in chroma_results:
        meta = r.get("metadata", {})
        for field in ["technique_id", "playbook_id", "attack_name", "id"]:
            val = meta.get(field)
            if val and isinstance(val, str) and len(val) > 2:
                entity_terms.add(val.strip())

    # Also build a plain-text keyword set from meaningful words in the query
    stop_words = {
        'what', 'is', 'the', 'a', 'an', 'are', 'and', 'or', 'of', 'in', 'on', 'at',
        'how', 'why', 'when', 'where', 'can', 'show', 'tell', 'find', 'me', 'for',
        'to', 'with', 'from', 'by', 'this', 'that', 'it', 'as', 'about', 'give',
        'list', 'all', 'any', 'my', 'do', 'does', 'did', 'has', 'have', 'been',
        'which', 'who', 'their', 'there', 'then', 'than', 'into', 'onto', 'not',
    }
    kw_terms = [
        w for w in query.lower().replace('-', ' ').split()
        if len(w) > 3 and w not in stop_words
    ]

    nl_log.info(f"Entity terms: {entity_terms} | Keywords: {kw_terms[:6]}")

    # ── 3. Neo4j graph query for found entities ───────────────────────────────
    nodes: dict = {}
    edges: dict = {}
    focus_node_payload = None

    try:
        driver, session = _graph_session()
        try:
            # Build a combined keyword string from entity_terms + kw_terms
            all_terms = list(entity_terms) + kw_terms
            # Try each term and collect matching nodes; stop when we have a match
            candidates = []
            for term in all_terms[:12]:  # cap to avoid long loop
                term_lower = term.lower()
                term_rows = list(session.run(
                    """
                    MATCH (n)
                    WHERE any(lbl IN labels(n) WHERE lbl IN
                          ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
                      AND (
                        toLower(coalesce(n.name,        '')) CONTAINS $t
                        OR toLower(coalesce(n.id,          '')) CONTAINS $t
                        OR toLower(coalesce(n.technique_id, '')) CONTAINS $t
                        OR toLower(coalesce(n.attack_name,  '')) CONTAINS $t
                        OR toLower(coalesce(n.description,  '')) CONTAINS $t
                      )
                    RETURN n
                    LIMIT 10
                    """,
                    t=term_lower,
                ))
                for rec in term_rows:
                    n = rec.get("n")
                    if n:
                        p = _serialize_node(n)
                        if p:
                            candidates.append(p)

            # De-duplicate by node id
            seen = {}
            for c in candidates:
                if c["id"] not in seen:
                    seen[c["id"]] = c
            candidates = list(seen.values())
            nl_log.info(f"Neo4j candidates: {len(candidates)}")

            # Pick the best candidate as focus (prefer technique/playbook/pattern)
            type_priority = {
                "MITRETechnique": 5, "DetectionPattern": 4,
                "Playbook": 3, "Window": 2, "User": 1,
            }
            if candidates:
                candidates.sort(
                    key=lambda c: type_priority.get(c.get("type", ""), 0),
                    reverse=True,
                )
                focus_node_payload = candidates[0]

            # Expand the focus node's 1-hop neighborhood
            if focus_node_payload:
                focus_type = focus_node_payload["type"]
                focus_props = focus_node_payload.get("properties", {})
                label_map = {
                    "User": ("User", "name"),
                    "Window": ("Window", "window_id"),
                    "DetectionPattern": ("DetectionPattern", "id"),
                    "MITRETechnique": ("MITRETechnique", "technique_id"),
                    "Playbook": ("Playbook", "id"),
                }
                label, key_prop = label_map.get(focus_type, (focus_type, "id"))
                key_value = focus_props.get(key_prop) or focus_props.get("id") or focus_props.get("name")

                if key_value:
                    neighbor_limit = max(30, min(limit * 4, 120))
                    focus_rows = list(session.run(
                        f"""
                        MATCH (n:{label} {{{key_prop}: $kv}})-[r]-(m)
                        RETURN n, m, r, startNode(r) as r_src, endNode(r) as r_dst
                        LIMIT $nlimit
                        """,
                        kv=key_value,
                        nlimit=neighbor_limit,
                    ))
                    for rec in focus_rows:
                        _add_node(nodes, rec.get("n"))
                        _add_node(nodes, rec.get("m"))
                        _add_edge(edges, rec.get("r"), rec.get("r_src"), rec.get("r_dst"))

                    nl_log.info(f"Focus node expanded: {len(nodes)} nodes, {len(edges)} edges")
            else:
                # No entity match — show a small overview
                nl_log.info("No entity match — using overview graph")
                ov_rows = list(session.run(
                    """
                    MATCH (n)
                    WHERE any(lbl IN labels(n) WHERE lbl IN
                          ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
                    RETURN n LIMIT 40
                    """
                ))
                for rec in ov_rows:
                    _add_node(nodes, rec.get("n"))
                ov_edge_rows = list(session.run(
                    """
                    MATCH (n)-[r]-(m)
                    WHERE any(lbl IN labels(n) WHERE lbl IN
                          ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
                      AND any(lbl IN labels(m) WHERE lbl IN
                          ['User','Window','DetectionPattern','MITRETechnique','Playbook'])
                    RETURN n, r, m LIMIT 80
                    """
                ))
                for rec in ov_edge_rows:
                    _add_node(nodes, rec.get("n"))
                    _add_node(nodes, rec.get("m"))
                    _add_edge(edges, rec.get("r"), rec.get("n"), rec.get("m"))
        finally:
            session.close()
            driver.close()

    except Exception as ge:
        nl_log.error(f"Neo4j query failed: {ge}", exc_info=True)

    # ── 4. Build LLM prompt and generate answer ───────────────────────────────
    answer = None
    if rag_service.llm_handler:
        try:
            # Format ChromaDB context
            ctx_parts = []
            for i, r in enumerate(chroma_results[:6], 1):
                meta = r.get("metadata", {})
                src = meta.get("source", r.get("collection", "knowledge base"))
                tid = meta.get("technique_id", "")
                header = f"[Source {i}: {src}" + (f" | {tid}]" if tid else "]")
                ctx_parts.append(f"{header}\n{r['content'][:600]}")
            chroma_ctx = "\n\n".join(ctx_parts) if ctx_parts else "No ChromaDB results available."

            # Format graph context
            graph_ctx_parts = []
            for node in list(nodes.values())[:15]:
                props = node.get("properties", {})
                name = props.get("name") or props.get("technique_id") or node.get("key", "")
                desc = str(props.get("description", ""))[:200]
                graph_ctx_parts.append(f"  - [{node['type']}] {name}: {desc}")
            graph_ctx = "\n".join(graph_ctx_parts) if graph_ctx_parts else "No graph entities found."

            edge_ctx_parts = []
            for edge in list(edges.values())[:10]:
                src_id = edge.get("source", "").split(":")[-1]
                dst_id = edge.get("target", "").split(":")[-1]
                edge_ctx_parts.append(f"  - {src_id} --[{edge.get('type', '?')}]--> {dst_id}")
            edge_ctx = "\n".join(edge_ctx_parts) if edge_ctx_parts else "No relationships found."

            prompt = f"""You are an expert AWS Cloud Security Operations Center (SOC) analyst.
You have access to a security knowledge base and a knowledge graph of detected threats.
Answer the analyst's question using ONLY the retrieved context below. Be specific, technical, and actionable.

## KNOWLEDGE BASE (ChromaDB semantic search results):
{chroma_ctx}

## KNOWLEDGE GRAPH ENTITIES (Neo4j):
{graph_ctx}

## GRAPH RELATIONSHIPS:
{edge_ctx}

## ANALYST QUESTION:
{query}

## INSTRUCTIONS:
- Answer based strictly on the context above. Do not hallucinate.
- Reference specific MITRE technique IDs, playbook IDs, or detection pattern names where visible.
- Structure your answer with clear sections using ### headers.
- End with 2-3 concrete next steps the analyst should take right now.
- If the context doesn't contain enough information, say so clearly and suggest what to search for.
"""
            nl_log.info("Calling Vertex AI for NL answer...")
            answer = rag_service.llm_handler.generate_text_sync(
                prompt=prompt,
                temperature=0.2,
                max_tokens=2500,
                top_p=0.9,
            )
            nl_log.info(f"Vertex AI answer: {len(answer or '')} chars")
        except Exception as le:
            nl_log.error(f"LLM call failed: {le}", exc_info=True)
            answer = None

    # ── 5. Build response ─────────────────────────────────────────────────────
    focus_match = None
    if focus_node_payload:
        focus_match = {
            "id":      focus_node_payload["id"],
            "type":    focus_node_payload["type"],
            "key":     focus_node_payload["key"],
            "label":   focus_node_payload["label"],
            "context": _match_context(focus_node_payload["type"],
                                      focus_node_payload.get("properties", {})),
        }

    sources = [
        {
            "content": r["content"][:300],
            "collection": r["collection"],
            "similarity": r["similarity"],
            "metadata": r["metadata"],
        }
        for r in chroma_results[:5]
    ]

    if focus_match:
        summary = (
            f"Knowledge base + graph queried for: '{query}'. "
            f"Best match: {focus_match['label']} ({focus_match['type']}). "
            f"{len(nodes)} entities in subgraph."
        )
    else:
        summary = (
            f"Queried knowledge base for: '{query}'. "
            f"Found {len(chroma_results)} relevant documents. "
            f"No specific graph entity matched — showing graph overview."
        )

    return {
        "answer":      answer,
        "summary":     summary,
        "sources":     sources,
        "focus_match": focus_match,
        "nodes":       list(nodes.values()),
        "edges":       list(edges.values()),
    }


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

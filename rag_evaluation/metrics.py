"""
rag_evaluation/metrics.py
==========================
Core evaluation metrics for retrieval, generation, and RAG components.
"""

import logging
from typing import Dict, List, Optional, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer, util

log = logging.getLogger("rag_evaluation.metrics")


# ─── RETRIEVAL METRICS ─────────────────────────────────────────────────────

def precision_at_k(
    relevant_indices: List[int],
    retrieved_indices: List[int],
    k: int = 5,
) -> float:
    """
    Compute Precision@K: fraction of top-K retrieved items that are relevant.
    
    Args:
        relevant_indices: Ground truth relevant item indices
        retrieved_indices: Ranked list of retrieved item indices
        k: Number of top items to evaluate
        
    Returns:
        Precision@K score [0, 1]
    """
    if not retrieved_indices or k == 0:
        return 0.0
    
    retrieved_at_k = set(retrieved_indices[:k])
    relevant_set = set(relevant_indices)
    
    hits = len(retrieved_at_k & relevant_set)
    precision = hits / min(k, len(retrieved_at_k))
    
    return float(precision)


def recall_at_k(
    relevant_indices: List[int],
    retrieved_indices: List[int],
    k: int = 5,
) -> float:
    """
    Compute Recall@K: fraction of all relevant items found in top-K.
    
    Args:
        relevant_indices: Ground truth relevant item indices
        retrieved_indices: Ranked list of retrieved item indices
        k: Number of top items to evaluate
        
    Returns:
        Recall@K score [0, 1]
    """
    if not relevant_indices or not retrieved_indices or k == 0:
        return 0.0
    
    retrieved_at_k = set(retrieved_indices[:k])
    relevant_set = set(relevant_indices)
    
    hits = len(retrieved_at_k & relevant_set)
    recall = hits / len(relevant_set)
    
    return float(recall)


def mean_reciprocal_rank(
    relevant_indices: List[int],
    retrieved_indices: List[int],
) -> float:
    """
    Compute Mean Reciprocal Rank (MRR): 1 / rank of first relevant item.
    
    Args:
        relevant_indices: Ground truth relevant item indices
        retrieved_indices: Ranked list of retrieved item indices
        
    Returns:
        MRR score [0, 1]. 1.0 = first item is relevant, 0.0 = no relevant item
    """
    if not relevant_indices or not retrieved_indices:
        return 0.0
    
    relevant_set = set(relevant_indices)
    
    for rank, item_idx in enumerate(retrieved_indices, start=1):
        if item_idx in relevant_set:
            return 1.0 / rank
    
    return 0.0


def ndcg_at_k(
    relevance_scores: List[float],
    k: int = 5,
) -> float:
    """
    Compute Normalized Discounted Cumulative Gain (nDCG@K).
    
    Measures ranking quality by penalizing relevant items ranked lower.
    
    Args:
        relevance_scores: Relevance score for each retrieved item [0, 1]
        k: Number of top items to evaluate
        
    Returns:
        nDCG@K score [0, 1]
    """
    if not relevance_scores or k == 0:
        return 0.0
    
    # Actual DCG
    dcg = 0.0
    for i, score in enumerate(relevance_scores[:k], start=1):
        dcg += score / np.log2(i + 1)
    
    # Ideal DCG (sorted scores descending)
    ideal_scores = sorted(relevance_scores, reverse=True)[:k]
    idcg = 0.0
    for i, score in enumerate(ideal_scores, start=1):
        idcg += score / np.log2(i + 1)
    
    if idcg == 0:
        return 0.0
    
    ndcg = dcg / idcg
    return float(np.clip(ndcg, 0.0, 1.0))


# ─── GENERATION METRICS ────────────────────────────────────────────────────

def faithfulness_score(
    generated_text: str,
    context_texts: List[str],
    model: Optional[SentenceTransformer] = None,
    threshold: float = 0.5,
) -> float:
    """
    Compute Faithfulness: does generated text stay grounded in context?
    
    Uses semantic similarity - higher similarity = more faithful to context.
    
    Args:
        generated_text: Generated response
        context_texts: List of retrieved context documents
        model: Embedding model (loads default if None)
        threshold: Similarity threshold to consider "grounded"
        
    Returns:
        Faithfulness score [0, 1]
    """
    if not generated_text or not context_texts:
        return 0.0
    
    if model is None:
        model = SentenceTransformer("all-MiniLM-L6-v2")
    
    try:
        # Embed generated text and context
        gen_embedding = model.encode(generated_text, convert_to_tensor=True)
        context_embeddings = model.encode(context_texts, convert_to_tensor=True)
        
        # Compute max similarity to any context document
        similarities = util.pytorch_cos_sim(gen_embedding, context_embeddings)[0]
        max_similarity = float(similarities.max().item())
        
        # Normalize: if max_similarity > threshold, score = max_similarity
        # Otherwise, penalize by threshold/actual_sim
        if max_similarity >= threshold:
            return float(np.clip(max_similarity, 0.0, 1.0))
        else:
            return float(max_similarity * 0.5)  # Penalize non-grounded text
    
    except Exception as e:
        log.error(f"Error computing faithfulness: {e}")
        return 0.0


def answer_relevance(
    query: str,
    generated_text: str,
    model: Optional[SentenceTransformer] = None,
) -> float:
    """
    Compute Answer Relevance: how well does generated answer address the query?
    
    Uses semantic similarity between query and generated answer.
    
    Args:
        query: Original query/prompt
        generated_text: Generated response
        model: Embedding model (loads default if None)
        
    Returns:
        Answer Relevance score [0, 1]
    """
    if not query or not generated_text:
        return 0.0
    
    if model is None:
        model = SentenceTransformer("all-MiniLM-L6-v2")
    
    try:
        query_embedding = model.encode(query, convert_to_tensor=True)
        answer_embedding = model.encode(generated_text, convert_to_tensor=True)
        
        similarity = util.pytorch_cos_sim(query_embedding, answer_embedding)[0][0]
        return float(np.clip(similarity.item(), 0.0, 1.0))
    
    except Exception as e:
        log.error(f"Error computing answer relevance: {e}")
        return 0.0


def context_utilization(
    context_texts: List[str],
    generated_text: str,
    model: Optional[SentenceTransformer] = None,
    threshold: float = 0.3,
) -> float:
    """
    Compute Context Utilization: what fraction of context was used in response?
    
    Args:
        context_texts: List of retrieved context documents
        generated_text: Generated response
        model: Embedding model (loads default if None)
        threshold: Similarity threshold to consider "used"
        
    Returns:
        Context Utilization [0, 1]: fraction of context used
    """
    if not context_texts or not generated_text:
        return 0.0
    
    if model is None:
        model = SentenceTransformer("all-MiniLM-L6-v2")
    
    try:
        # For each context document, check if similar to generated text
        gen_embedding = model.encode(generated_text, convert_to_tensor=True)
        context_embeddings = model.encode(context_texts, convert_to_tensor=True)
        
        similarities = util.pytorch_cos_sim(gen_embedding, context_embeddings)[0]
        used_contexts = sum(1 for sim in similarities if sim > threshold)
        
        utilization = used_contexts / len(context_texts)
        return float(np.clip(utilization, 0.0, 1.0))
    
    except Exception as e:
        log.error(f"Error computing context utilization: {e}")
        return 0.0


# ─── RAG-SPECIFIC METRICS (RAGAS-style) ────────────────────────────────────

def context_precision(
    relevant_context_indices: List[int],
    retrieved_context_indices: List[int],
) -> float:
    """
    Compute Context Precision: fraction of retrieved context that is relevant.
    
    Also known as "precision of retrieval".
    
    Args:
        relevant_context_indices: Ground truth relevant context indices
        retrieved_context_indices: Retrieved context indices
        
    Returns:
        Context Precision [0, 1]
    """
    if not retrieved_context_indices:
        return 0.0
    
    if not relevant_context_indices:
        return 0.0
    
    retrieved_set = set(retrieved_context_indices)
    relevant_set = set(relevant_context_indices)
    
    hits = len(retrieved_set & relevant_set)
    precision = hits / len(retrieved_set)
    
    return float(np.clip(precision, 0.0, 1.0))


def context_recall(
    relevant_context_indices: List[int],
    retrieved_context_indices: List[int],
) -> float:
    """
    Compute Context Recall: fraction of relevant context that was retrieved.
    
    Also known as "recall of retrieval". Measures completeness of retrieval.
    
    Args:
        relevant_context_indices: Ground truth relevant context indices
        retrieved_context_indices: Retrieved context indices
        
    Returns:
        Context Recall [0, 1]
    """
    if not relevant_context_indices:
        return 1.0  # If no relevant context required, perfect recall
    
    if not retrieved_context_indices:
        return 0.0
    
    retrieved_set = set(retrieved_context_indices)
    relevant_set = set(relevant_context_indices)
    
    hits = len(retrieved_set & relevant_set)
    recall = hits / len(relevant_set)
    
    return float(np.clip(recall, 0.0, 1.0))


def rag_precision(
    generated_text: str,
    context_texts: List[str],
    model: Optional[SentenceTransformer] = None,
) -> float:
    """
    Composite RAG Precision: both retrieval and generation relevance.
    
    Combines context_precision with faithfulness.
    
    Args:
        generated_text: Generated response
        context_texts: Retrieved context documents
        model: Embedding model
        
    Returns:
        RAG Precision [0, 1]
    """
    faithfulness = faithfulness_score(generated_text, context_texts, model)
    context_util = context_utilization(context_texts, generated_text, model)
    
    # Weighted average
    rag_precision_score = 0.6 * faithfulness + 0.4 * context_util
    return float(np.clip(rag_precision_score, 0.0, 1.0))

"""
rag_evaluation/plots.py
=======================
Visualization utilities for evaluation results.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt
import numpy as np

try:
    import seaborn as sns
    SEABORN_AVAILABLE = True
except ImportError:
    SEABORN_AVAILABLE = False

log = logging.getLogger("rag_evaluation.plots")

PROJECT_ROOT = Path(__file__).parent.parent


def plot_metric_bar_chart(
    metrics: Dict[str, float],
    title: str = "Evaluation Metrics",
    output_path: Optional[str] = None,
    figsize: tuple = (12, 6),
) -> Optional[str]:
    """
    Plot metrics as a bar chart.
    
    Args:
        metrics: Dictionary of metric names to scores [0, 1]
        title: Chart title
        output_path: Save path. If None, doesn't save.
        figsize: Figure size (width, height)
        
    Returns:
        Path to saved figure or None
    """
    try:
        if SEABORN_AVAILABLE:
            sns.set_style("whitegrid")
        
        fig, ax = plt.subplots(figsize=figsize)
        
        names = list(metrics.keys())
        values = list(metrics.values())
        
        # Color gradient: red (poor) to green (good)
        colors = plt.cm.RdYlGn(np.array(values))
        
        bars = ax.bar(range(len(names)), values, color=colors, alpha=0.8, edgecolor="black")
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height,
                f"{value:.3f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )
        
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels(names, rotation=45, ha="right")
        ax.set_ylim([0, 1.1])
        ax.set_ylabel("Score", fontsize=12, fontweight="bold")
        ax.set_title(title, fontsize=14, fontweight="bold")
        ax.grid(axis="y", alpha=0.3)
        
        plt.tight_layout()
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            log.info(f"Saved metric chart to {output_path}")
            return str(output_path)
        
        return None
    
    except Exception as e:
        log.error(f"Error creating metric chart: {e}")
        return None
    finally:
        plt.close()


def plot_precision_recall_curve(
    precisions: List[float],
    recalls: List[float],
    output_path: Optional[str] = None,
    figsize: tuple = (10, 8),
) -> Optional[str]:
    """
    Plot Precision-Recall curve.
    
    Args:
        precisions: List of precision values
        recalls: List of recall values
        output_path: Save path
        figsize: Figure size
        
    Returns:
        Path to saved figure or None
    """
    try:
        if SEABORN_AVAILABLE:
            sns.set_style("whitegrid")
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Sort by recall for proper line plot
        sorted_pairs = sorted(zip(recalls, precisions))
        recalls_sorted = [r for r, _ in sorted_pairs]
        precisions_sorted = [p for _, p in sorted_pairs]
        
        ax.plot(recalls_sorted, precisions_sorted, "b-", linewidth=2.5, marker="o", label="PR Curve")
        
        # Add diagonal (random classifier)
        ax.plot([0, 1], [1, 0], "r--", linewidth=1.5, alpha=0.5, label="Random Classifier")
        
        ax.set_xlabel("Recall", fontsize=12, fontweight="bold")
        ax.set_ylabel("Precision", fontsize=12, fontweight="bold")
        ax.set_title("Precision-Recall Curve", fontsize=14, fontweight="bold")
        ax.set_xlim([0, 1.05])
        ax.set_ylim([0, 1.05])
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=11)
        
        plt.tight_layout()
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            log.info(f"Saved P-R curve to {output_path}")
            return str(output_path)
        
        return None
    
    except Exception as e:
        log.error(f"Error creating P-R curve: {e}")
        return None
    finally:
        plt.close()


def plot_confusion_matrix(
    confusion_matrix: np.ndarray,
    labels: List[str] = None,
    output_path: Optional[str] = None,
    figsize: tuple = (8, 8),
) -> Optional[str]:
    """
    Plot Confusion Matrix heatmap.
    
    Args:
        confusion_matrix: 2x2 numpy array [[TN, FP], [FN, TP]]
        labels: Class labels (default: ["Normal", "Attack"])
        output_path: Save path
        figsize: Figure size
        
    Returns:
        Path to saved figure or None
    """
    try:
        if labels is None:
            labels = ["Normal", "Attack"]
        
        if SEABORN_AVAILABLE:
            sns.set_style("whitegrid")
            fig, ax = plt.subplots(figsize=figsize)
            sns.heatmap(
                confusion_matrix,
                annot=True,
                fmt="d",
                cmap="Blues",
                xticklabels=labels,
                yticklabels=labels,
                cbar_kws={"label": "Count"},
                ax=ax,
            )
        else:
            fig, ax = plt.subplots(figsize=figsize)
            im = ax.imshow(confusion_matrix, cmap="Blues", aspect="auto")
            
            # Add text annotations
            for i in range(confusion_matrix.shape[0]):
                for j in range(confusion_matrix.shape[1]):
                    text = ax.text(
                        j, i,
                        str(confusion_matrix[i, j]),
                        ha="center", va="center",
                        color="white" if confusion_matrix[i, j] > confusion_matrix.max() / 2 else "black",
                        fontsize=14, fontweight="bold",
                    )
            
            ax.set_xticks(range(len(labels)))
            ax.set_yticks(range(len(labels)))
            ax.set_xticklabels(labels)
            ax.set_yticklabels(labels)
            plt.colorbar(im, ax=ax, label="Count")
        
        ax.set_xlabel("Predicted Label", fontsize=12, fontweight="bold")
        ax.set_ylabel("True Label", fontsize=12, fontweight="bold")
        ax.set_title("Confusion Matrix", fontsize=14, fontweight="bold")
        
        plt.tight_layout()
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            log.info(f"Saved confusion matrix to {output_path}")
            return str(output_path)
        
        return None
    
    except Exception as e:
        log.error(f"Error creating confusion matrix: {e}")
        return None
    finally:
        plt.close()


def plot_metrics_comparison(
    system_names: List[str],
    metrics_dict: Dict[str, Dict[str, float]],
    output_path: Optional[str] = None,
    figsize: tuple = (14, 8),
) -> Optional[str]:
    """
    Plot comparison across multiple systems (baseline comparison).
    
    Args:
        system_names: Names of systems (e.g., ["No RAG", "Vector RAG", "Graph RAG"])
        metrics_dict: {system_name: {metric_name: score}}
        output_path: Save path
        figsize: Figure size
        
    Returns:
        Path to saved figure or None
    """
    try:
        if SEABORN_AVAILABLE:
            sns.set_style("whitegrid")
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Extract metrics
        all_metrics = set()
        for metrics in metrics_dict.values():
            all_metrics.update(metrics.keys())
        all_metrics = sorted(list(all_metrics))
        
        x = np.arange(len(all_metrics))
        width = 0.25
        
        colors = ["#FF6B6B", "#4ECDC4", "#45B7D1"]
        
        for idx, system_name in enumerate(system_names):
            scores = [
                metrics_dict[system_name].get(metric, 0.0)
                for metric in all_metrics
            ]
            offset = (idx - 1) * width
            ax.bar(x + offset, scores, width, label=system_name, color=colors[idx % len(colors)])
        
        ax.set_ylabel("Score", fontsize=12, fontweight="bold")
        ax.set_title("System Comparison", fontsize=14, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(all_metrics, rotation=45, ha="right")
        ax.set_ylim([0, 1.0])
        ax.legend(fontsize=11)
        ax.grid(axis="y", alpha=0.3)
        
        plt.tight_layout()
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            log.info(f"Saved comparison chart to {output_path}")
            return str(output_path)
        
        return None
    
    except Exception as e:
        log.error(f"Error creating comparison chart: {e}")
        return None
    finally:
        plt.close()


def plot_radar_chart(
    metric_names: List[str],
    scores: List[float],
    label: str = "System Performance",
    output_path: Optional[str] = None,
    figsize: tuple = (8, 8),
) -> Optional[str]:
    """
    Plot Radar/Spider chart for multidimensional metrics.
    
    Args:
        metric_names: Names of metrics
        scores: Scores for each metric [0, 1]
        label: Label for the data series
        output_path: Save path
        figsize: Figure size
        
    Returns:
        Path to saved figure or None
    """
    try:
        num_vars = len(metric_names)
        
        # Compute angle for each axis
        angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
        scores_plot = scores + [scores[0]]  # Complete the circle
        angles += angles[:1]
        
        fig, ax = plt.subplots(figsize=figsize, subplot_kw=dict(projection="polar"))
        
        ax.plot(angles, scores_plot, "o-", linewidth=2, label=label, color="#4ECDC4")
        ax.fill(angles, scores_plot, alpha=0.25, color="#4ECDC4")
        
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(metric_names, fontsize=10)
        ax.set_ylim(0, 1.0)
        ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
        ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], fontsize=9)
        ax.grid(True)
        ax.set_title(label, fontsize=14, fontweight="bold", pad=20)
        
        plt.tight_layout()
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            log.info(f"Saved radar chart to {output_path}")
            return str(output_path)
        
        return None
    
    except Exception as e:
        log.error(f"Error creating radar chart: {e}")
        return None
    finally:
        plt.close()

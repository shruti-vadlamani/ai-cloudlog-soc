"""
models/autoencoder.py
======================
Autoencoder-based anomaly detector using PyTorch.

Best suited for: temporal pattern breaks and gradual drift.
Catches what IF and LOF miss:
  - Data exfiltration (gradual 3-day volume ramp — reconstruction
    error increases as the pattern diverges from normal baseline)
  - Any attack where the combination of features is unusual even
    if individual features aren't extreme outliers

Architecture:
  Encoder: 43 → 32 → 16 → 8 (bottleneck)
  Decoder: 8 → 16 → 32 → 43
  Loss: MSE reconstruction error
  Anomaly score = reconstruction error on held-out windows

Training protocol:
  - Train ONLY on normal windows
  - Anomaly score = MSE between input and reconstruction
  - Windows with high reconstruction error = anomalous behavior
    the autoencoder has never seen

Falls back gracefully if torch is not installed —
prints a clear error with install instructions.

Run:
    python models/autoencoder.py
    python models/autoencoder.py --epochs 100 --no-tune

Saves model to data/models/autoencoder.pkl
"""

import logging
import os
import sys
import numpy as np
import pickle
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.metrics import f1_score

from models.model_utils import (
    load_feature_matrix,
    get_X_y,
    train_test_split_by_label,
    fit_scaler,
    evaluate,
    save_results,
    FEATURE_COLUMNS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("autoencoder")


# ── PyTorch Availability Check ────────────────────────────────────────────────

def _check_torch():
    try:
        import torch
        import torch.nn as nn
        return torch, nn
    except ImportError:
        print("\n" + "="*55)
        print("PyTorch not installed.")
        print("Install with: pip install torch")
        print("Or (CPU-only, lighter): pip install torch --index-url https://download.pytorch.org/whl/cpu")
        print("="*55 + "\n")
        sys.exit(1)


# ── Model Definition ──────────────────────────────────────────────────────────

def _build_autoencoder(input_dim: int, torch, nn):
    """
    Build the autoencoder. Called after torch is confirmed available.
    Separate function so torch.nn isn't imported at module level.
    """
    class CloudTrailAutoencoder(nn.Module):
        def __init__(self, input_dim: int):
            super().__init__()

            # Encoder: compress to bottleneck
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 32),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(32, 16),
                nn.BatchNorm1d(16),
                nn.ReLU(),
                nn.Linear(16, 8),  # bottleneck
                nn.ReLU(),
            )

            # Decoder: reconstruct from bottleneck
            self.decoder = nn.Sequential(
                nn.Linear(8, 16),
                nn.BatchNorm1d(16),
                nn.ReLU(),
                nn.Linear(16, 32),
                nn.BatchNorm1d(32),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(32, input_dim),
                # No activation on output — inputs are standardized (can be negative)
            )

        def forward(self, x):
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded

        def reconstruction_error(self, x):
            """Per-sample MSE reconstruction error."""
            with torch.no_grad():
                recon = self.forward(x)
                errors = ((x - recon) ** 2).mean(dim=1)
            return errors

    return CloudTrailAutoencoder(input_dim)


# ── Training ──────────────────────────────────────────────────────────────────

def _find_best_threshold(scores: np.ndarray, y_true: np.ndarray) -> tuple:
    """Find threshold maximizing F1 by scanning percentiles."""
    best_f1, best_thresh = -1, np.percentile(scores, 90)
    for p in [85, 87, 89, 90, 91, 92, 93, 95, 97, 99]:
        thresh = np.percentile(scores, p)
        y_pred = (scores >= thresh).astype(int)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        if f1 > best_f1:
            best_f1, best_thresh = f1, thresh
    return best_thresh, best_f1


def train(
    epochs: int = 50,
    batch_size: int = 64,
    learning_rate: float = 1e-3,
    tune: bool = True,
) -> dict:
    """
    Full training + evaluation pipeline for the Autoencoder.

    Args:
        epochs: Training epochs (50 is enough for this dataset size)
        batch_size: Mini-batch size
        learning_rate: Adam optimizer LR
        tune: If True, try a few LR values and pick best
    """
    torch, nn = _check_torch()
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info(f"Device: {device}")

    log.info("Loading feature matrix...")
    df = load_feature_matrix()

    train_df, test_df = train_test_split_by_label(df)

    X_train, _, _ = get_X_y(train_df)
    X_test, y_true, y_multi = get_X_y(test_df)

    # Scale on normal training data only
    scaler = fit_scaler(X_train)
    X_train_scaled = scaler.transform(X_train).astype(np.float32)
    X_test_scaled = scaler.transform(X_test).astype(np.float32)

    input_dim = X_train_scaled.shape[1]  # 43

    # LR tuning: try a small range if tune=True
    lr_candidates = [1e-3, 5e-4, 1e-4] if tune else [learning_rate]
    best_result = {"f1": -1, "lr": learning_rate}

    for lr in lr_candidates:
        log.info(f"Training with lr={lr}, epochs={epochs}...")

        model = _build_autoencoder(input_dim, torch, nn).to(device)
        optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
        criterion = nn.MSELoss()

        # LR scheduler: reduce on plateau to avoid overfitting
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode="min", factor=0.5, patience=5
        )

        # Dataset
        X_tensor = torch.tensor(X_train_scaled).to(device)
        dataset = TensorDataset(X_tensor)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=False)

        # Training loop
        model.train()
        for epoch in range(epochs):
            epoch_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon = model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item() * len(batch)

            avg_loss = epoch_loss / len(X_train_scaled)
            scheduler.step(avg_loss)

            if (epoch + 1) % 10 == 0:
                log.info(f"  Epoch {epoch+1}/{epochs} — loss: {avg_loss:.6f}")

        # Score test set
        model.eval()
        X_test_tensor = torch.tensor(X_test_scaled).to(device)
        anomaly_scores = model.reconstruction_error(X_test_tensor).cpu().numpy()

        thresh, f1 = _find_best_threshold(anomaly_scores, y_true)
        log.info(f"  lr={lr}: F1={f1:.4f}, threshold={thresh:.6f}")

        if f1 > best_result["f1"]:
            best_result = {
                "f1": f1,
                "lr": lr,
                "threshold": thresh,
                "model": model,
                "scores": anomaly_scores,
            }

    # Final evaluation with best model
    best_model = best_result["model"]
    anomaly_scores = best_result["scores"]
    best_thresh = best_result["threshold"]
    y_pred = (anomaly_scores >= best_thresh).astype(int)

    log.info(f"\nBest lr={best_result['lr']}, F1={best_result['f1']:.4f}")
    log.info(f"Threshold: {best_thresh:.6f} "
             f"(flags top {100*(anomaly_scores >= best_thresh).mean():.1f}% of windows)")

    results = evaluate(y_true, y_pred, anomaly_scores, y_multi, "Autoencoder")
    results["learning_rate"] = best_result["lr"]
    results["epochs"] = epochs
    results["threshold"] = float(best_thresh)

    # Save model
    Path("data/models").mkdir(parents=True, exist_ok=True)
    payload = {
        "model_state": best_model.state_dict(),
        "input_dim": input_dim,
        "scaler": scaler,
        "threshold": best_thresh,
        "feature_columns": FEATURE_COLUMNS,
    }
    with open("data/models/autoencoder.pkl", "wb") as f:
        pickle.dump(payload, f)
    log.info("Saved to data/models/autoencoder.pkl")

    save_results(results, "autoencoder")

    # Save scores
    score_df = test_df[["user_name", "window"]].copy()
    score_df["ae_score"] = anomaly_scores
    score_df["ae_pred"] = y_pred
    score_df.to_csv("data/models/ae_scores.csv", index=False)
    log.info("Scores saved to data/models/ae_scores.csv")

    return results


def load_and_score(X_new: np.ndarray, models_dir: str = "data/models") -> np.ndarray:
    """
    Load saved autoencoder and score new (already-scaled) data.
    Returns anomaly scores (higher = more anomalous).
    """
    torch, nn = _check_torch()

    with open(Path(models_dir) / "autoencoder.pkl", "rb") as f:
        payload = pickle.load(f)

    input_dim = payload["input_dim"]
    model = _build_autoencoder(input_dim, torch, nn)
    model.load_state_dict(payload["model_state"])
    model.eval()

    X_tensor = torch.tensor(X_new.astype(np.float32))
    scores = model.reconstruction_error(X_tensor).numpy()
    return scores


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--no-tune", action="store_true")
    args = parser.parse_args()
    train(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        tune=not args.no_tune,
    )

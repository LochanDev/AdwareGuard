"""
AdwareGuard Model Training Pipeline
====================================
Loads multimodal datasets, fits the simulated FT-Transformer architecture,
evaluates across test benchmarks, and exports production checkpoints.

Research Grounding:
  - Multi-metric evaluation per [2] (Almakayeel, Scientific Reports 2024: 25175).
  - Lightweight inference configuration per [3] (Bavishi & Modi, arXiv 2024).
  - Multimodal input fusion per [4] (Tanveer et al., Scientific Reports 2025: 38341).
"""

import os
import sys

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from data.dataset_loader import AdwareDatasetLoader
from model.classifier import AdwareGuardModel


def main():
    print("=" * 65)
    print("AdwareGuard — Multimodal Android Adware Detector Training")
    print("=" * 65)

    # 1. Dataset Loading & Preprocessing
    loader = AdwareDatasetLoader()
    (X_train, y_train), (X_val, y_val), (X_test, y_test) = loader.load_and_preprocess()

    # 2. Model Initialization
    model = AdwareGuardModel()

    # 3. Model Training
    model.train(X_train, y_train, scaler=loader.scaler)

    # 4. Model Evaluation
    metrics = model.evaluate(X_test, y_test)

    # 5. Checkpoint Persistence
    model.save(config.MODEL_PATH)

    print("\n" + "=" * 65)
    print("FINAL MODEL BENCHMARK RESULTS (Test Set):")
    print(f"  [+] Accuracy  : {metrics['accuracy']}%")
    print(f"  [+] Precision : {metrics['precision']}%")
    print(f"  [+] Recall    : {metrics['recall']}%")
    print(f"  [+] F1-Score  : {metrics['f1_score']}%")
    print(f"  [+] AUC-ROC   : {metrics['auc_roc']}")
    print(f"\nModel saved to {config.MODEL_PATH}")
    print("=" * 65)


if __name__ == "__main__":
    main()

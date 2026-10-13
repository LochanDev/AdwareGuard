"""
AdwareGuard Configuration Module
=================================
Central configuration constants for the AdwareGuard Hybrid Multimodal
Transformer-Based Android Adware Detection System.

RESEARCH FOUNDATION (Peer-Reviewed References Only):
[1] Ullah, Farhan, et al. "Explainable malware detection system using
    transformers-based transfer learning and multi-model visual
    representation." Sensors 22.18 (2022): 6766.
[2] Almakayeel, Naif. "Deep learning-based improved transformer model
    on android malware detection and classification in internet of
    vehicles." Scientific Reports 14.1 (2024): 25175.
[3] Bavishi, Shrey, and Shrey Modi. "Accelerating malware
    classification: A vision transformer solution." arXiv preprint
    arXiv:2409.19461 (2024).
[4] Tanveer, Muhammad Usama, et al. "Graph-augmented multi-modal
    learning framework for robust android malware detection."
    Scientific Reports 15.1 (2025): 38341.
[5] Alshomrani, Mohammed, et al. "An Explainable Hybrid CNN–Transformer
    Architecture for Visual Malware Classification." Sensors 25.15
    (2025): 4581.
"""

import os

# Dataset File Paths
DATASET_PATHS = {
    "cicmaldroid": os.path.join(".", "data", "CICMalDroid2020", "features.csv"),
    "cicandmal":   os.path.join(".", "data", "CICAndMal2017", "features.csv"),
    "drebin":      os.path.join(".", "data", "Drebin", "features.csv"),
    "androzoo":    os.path.join(".", "data", "AndroZoo", "features.csv"),
    "malgenome":   os.path.join(".", "data", "MalGenome", "features.csv"),
}

# Feature Dimensions
PERM_VOCAB_SIZE = 200
API_VOCAB_SIZE = 150
METADATA_DIM = 10
TOTAL_INPUT_DIM = 360  # 200 (Perms) + 150 (APIs) + 10 (Metadata)

# Classification Classes
NUM_CLASSES = 3
LABELS = {
    0: "Benign",
    1: "Adware",
    2: "Malware"
}

LABEL_COLORS = {
    0: "#2E7D32",  # Forest Green
    1: "#C00000",  # Crimson Red
    2: "#E65100"   # Deep Orange
}

# Model and Preprocessing Artifact Paths
MODEL_PATH = os.path.join(".", "model", "adwareguard_model.pkl")
SCALER_PATH = os.path.join(".", "model", "scaler.pkl")
ENCODER_PATH = os.path.join(".", "model", "encoder.pkl")
CONFUSION_MATRIX_PATH = os.path.join(".", "static", "plots", "confusion_matrix.png")

# Data Splits & Random State
RANDOM_SEED = 42
TEST_SPLIT = 0.15
VAL_SPLIT = 0.15
CONFIDENCE_THRESHOLD = 0.75

# Upload Constraints
MAX_CONTENT_LENGTH = 250 * 1024 * 1024  # 250 MB
ALLOWED_EXTENSIONS = {"apk"}
UPLOAD_FOLDER = os.path.join(".", "uploads")

# Server Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = PROJECT_ROOT / "data" / "messages.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "goldenguard_model.joblib"
RESOURCE_PATH = PROJECT_ROOT / "knowledge" / "resources.json"
RAW_KNOWLEDGE_PATH = PROJECT_ROOT / "knowledge" / "raw"
RAG_INDEX_PATH = PROJECT_ROOT / "knowledge" / "index" / "chunks.json"

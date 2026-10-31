import json
from pathlib import Path

from src.config import RAG_INDEX_PATH, RAW_KNOWLEDGE_PATH
from src.rag.chunker import chunk_documents
from src.rag.document_loader import load_documents


def build_index(
    raw_directory: str | Path = RAW_KNOWLEDGE_PATH,
    output_file: str | Path = RAG_INDEX_PATH,
) -> dict[str, int | str]:
    documents = load_documents(raw_directory)
    chunks = chunk_documents(documents)

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps([chunk.to_dict() for chunk in chunks], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    result = {
        "documents": len(documents),
        "chunks": len(chunks),
        "path": str(output_path),
    }
    print(f"Loaded {len(documents)} document(s).")
    print(f"Created {len(chunks)} chunk(s).")
    print(f"Saved index to {output_path}.")
    return result


if __name__ == "__main__":
    build_index()

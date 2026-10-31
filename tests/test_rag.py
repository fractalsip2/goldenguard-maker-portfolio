from pathlib import Path

from src.rag.build_index import build_index
from src.rag.retriever import load_chunks, retrieve


def test_usps_query_returns_usps_first(tmp_path: Path):
    index_path = tmp_path / "chunks.json"
    build_index(output_file=index_path)
    load_chunks.cache_clear()

    results = retrieve(
        "USPS says my package cannot be delivered and I must pay a small fee",
        scam_type="package_delivery",
        index_file=index_path,
    )

    assert results
    assert results[0]["category"] == "package_delivery"
    assert "USPS" in results[0]["title"]

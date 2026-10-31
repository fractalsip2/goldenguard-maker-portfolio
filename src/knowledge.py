import json
from functools import lru_cache

from src.config import RESOURCE_PATH
from src.rag.retriever import retrieve_resources


@lru_cache(maxsize=1)
def load_resources() -> dict:
    with RESOURCE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_static_resources(scam_type: str) -> list[dict[str, str]]:
    resources = load_resources()
    raw_value = resources.get(scam_type, resources.get("unknown", []))
    if isinstance(raw_value, dict):
        return [raw_value]
    return list(raw_value)


def get_resource(scam_type: str) -> dict[str, str]:
    return get_static_resources(scam_type)[0]


def get_helpful_resources(
    message: str,
    scam_type: str,
    top_k: int = 3,
) -> list[dict]:
    combined: list[dict] = []

    try:
        combined.extend(retrieve_resources(message, scam_type, top_k=top_k))
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        pass

    combined.extend(get_static_resources(scam_type))

    deduplicated: list[dict] = []
    seen_urls: set[str] = set()

    for resource in combined:
        url = resource.get("url", "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        deduplicated.append(
            {
                "provider": resource.get("provider", "Trusted source"),
                "title": resource.get("title", "Scam guidance"),
                "url": url,
                "description": resource.get("description", ""),
                "category": resource.get("category", scam_type),
                **(
                    {"relevance_score": resource["relevance_score"]}
                    if "relevance_score" in resource
                    else {}
                ),
            }
        )

        if len(deduplicated) >= top_k:
            break

    return deduplicated

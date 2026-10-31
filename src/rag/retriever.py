import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import List

from src.config import RAG_INDEX_PATH


STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can",
    "do", "for", "from", "had", "has", "have", "he", "her", "here", "him",
    "his", "i", "if", "in", "is", "it", "its", "me", "my", "of", "on", "or",
    "our", "she", "so", "that", "the", "their", "them", "there", "they", "this",
    "to", "was", "we", "were", "what", "when", "where", "which", "who", "will",
    "with", "you", "your",
}

CATEGORY_TERMS = {
    "bank_impersonation": ["bank", "account", "card", "chase", "fraud", "locked"],
    "account_takeover": ["verification", "code", "otp", "password", "account", "login"],
    "gift_card": ["gift", "card", "pin", "payment"],
    "grandparent_emergency": ["grandchild", "family", "emergency", "bail", "jail"],
    "government_impersonation": ["government", "irs", "ssa", "social", "security"],
    "package_delivery": ["package", "delivery", "usps", "fedex", "ups", "tracking"],
    "romance": ["romance", "dating", "relationship", "love", "money"],
    "investment_crypto": ["investment", "crypto", "bitcoin", "return", "trading"],
    "tech_support": ["tech", "support", "computer", "virus", "remote", "microsoft"],
    "prize_sweepstakes": ["prize", "winner", "lottery", "sweepstakes", "claim", "fee"],
    "employment": ["job", "employer", "recruiter", "check", "equipment", "remote"],
    "marketplace": ["marketplace", "buyer", "seller", "overpayment", "refund", "check"],
    "toll_payment": ["toll", "unpaid", "balance", "fee", "road", "text"],
}


def tokenize(text: str) -> List[str]:
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return [token for token in tokens if len(token) > 1 and token not in STOP_WORDS]


@lru_cache(maxsize=4)
def load_chunks(index_file: str | Path = RAG_INDEX_PATH) -> List[dict]:
    index_path = Path(index_file)
    if not index_path.exists():
        raise FileNotFoundError(
            f"Index not found: {index_path}. Run python -m src.rag.build_index first."
        )

    chunks = json.loads(index_path.read_text(encoding="utf-8"))
    if not chunks:
        raise ValueError("The index is empty. Add documents and rebuild it.")
    return chunks


def _idf(token: str, tokenized_documents: list[list[str]]) -> float:
    containing = sum(1 for tokens in tokenized_documents if token in set(tokens))
    return math.log((1 + len(tokenized_documents)) / (1 + containing)) + 1.0


def _score_chunk(
    query_tokens: list[str],
    chunk: dict,
    tokenized_documents: list[list[str]],
    scam_type: str | None,
) -> float:
    document_tokens = tokenize(
        " ".join(
            [
                chunk.get("title", ""),
                chunk.get("description", ""),
                chunk.get("category", ""),
                chunk.get("text", ""),
            ]
        )
    )
    document_counts = Counter(document_tokens)
    score = 0.0

    for token in set(query_tokens):
        frequency = document_counts[token]
        if frequency:
            score += (1.0 + math.log(frequency)) * _idf(token, tokenized_documents)

    title_tokens = set(tokenize(chunk.get("title", "")))
    score += 1.25 * len(set(query_tokens) & title_tokens)

    if scam_type and chunk.get("category") == scam_type:
        score += 5.0

    if scam_type:
        category_matches = set(CATEGORY_TERMS.get(scam_type, [])) & set(query_tokens)
        if chunk.get("category") == scam_type:
            score += 0.5 * len(category_matches)

    return score


def retrieve(
    query: str,
    top_k: int = 3,
    index_file: str | Path = RAG_INDEX_PATH,
    scam_type: str | None = None,
) -> List[dict]:
    if not query.strip():
        raise ValueError("Query cannot be empty.")
    if top_k <= 0:
        return []

    chunks = load_chunks(index_file)
    query_text = query
    if scam_type:
        query_text += " " + " ".join(CATEGORY_TERMS.get(scam_type, []))
    query_tokens = tokenize(query_text)

    tokenized_documents = [
        tokenize(
            " ".join(
                [
                    chunk.get("title", ""),
                    chunk.get("description", ""),
                    chunk.get("category", ""),
                    chunk.get("text", ""),
                ]
            )
        )
        for chunk in chunks
    ]

    best_by_document: dict[str, dict] = {}
    for chunk in chunks:
        score = _score_chunk(query_tokens, chunk, tokenized_documents, scam_type)
        if score <= 0:
            continue

        result = chunk.copy()
        result["score"] = round(score, 4)
        result["excerpt"] = chunk.get("text", "")[:360].strip()
        document_id = chunk.get("document_id", chunk.get("chunk_id", "unknown"))

        current = best_by_document.get(document_id)
        if current is None or result["score"] > current["score"]:
            best_by_document[document_id] = result

    ranked = sorted(
        best_by_document.values(),
        key=lambda result: result["score"],
        reverse=True,
    )
    return ranked[:top_k]


def retrieve_resources(query: str, scam_type: str, top_k: int = 3) -> List[dict]:
    results = retrieve(query, top_k=top_k, scam_type=scam_type)
    resources: list[dict] = []

    for result in results:
        if not result.get("url"):
            continue

        result_category = result.get("category", "unknown")
        if scam_type == "unknown" and result_category != "unknown":
            continue
        if scam_type != "unknown" and result_category not in {scam_type, "unknown"}:
            continue

        resources.append(
            {
                "provider": result.get("provider", result.get("source", "Trusted source")),
                "title": result.get("title", "Scam guidance"),
                "url": result["url"],
                "description": result.get("description", ""),
                "category": result.get("category", "unknown"),
                "relevance_score": result.get("score", 0.0),
                "excerpt": result.get("excerpt", ""),
            }
        )

    return resources


if __name__ == "__main__":
    user_query = input("Enter a suspicious message or question: ").strip()
    results = retrieve(user_query)

    if not results:
        print("No relevant knowledge found.")
    else:
        for number, result in enumerate(results, start=1):
            print(f"\nResult {number}")
            print(f"Title: {result['title']}")
            print(f"Source: {result.get('provider', result.get('source'))}")
            print(f"URL: {result.get('url', '')}")
            print(f"Score: {result['score']}")
            print(f"Text: {result['excerpt']}")

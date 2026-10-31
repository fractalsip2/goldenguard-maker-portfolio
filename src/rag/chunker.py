from dataclasses import asdict, dataclass
from typing import List

from src.rag.document_loader import Document


@dataclass
class Chunk:
    chunk_id: str
    document_id: str
    title: str
    provider: str
    source: str
    url: str
    category: str
    description: str
    text: str
    path: str

    def to_dict(self) -> dict:
        return asdict(self)


def chunk_document(
    document: Document,
    chunk_size: int = 800,
    overlap: int = 150,
) -> List[Chunk]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be at least 0 and smaller than chunk_size")

    words = document.text.split()
    if not words:
        return []

    chunks: List[Chunk] = []
    start = 0
    chunk_number = 0

    while start < len(words):
        end = start
        current_length = 0

        while end < len(words):
            added_length = len(words[end]) + (1 if current_length else 0)
            if end > start and current_length + added_length > chunk_size:
                break
            current_length += added_length
            end += 1

        chunk_text = " ".join(words[start:end])
        chunks.append(
            Chunk(
                chunk_id=f"{document.document_id}__chunk_{chunk_number}",
                document_id=document.document_id,
                title=document.title,
                provider=document.provider,
                source=document.source,
                url=document.url,
                category=document.category,
                description=document.description,
                text=chunk_text,
                path=document.path,
            )
        )
        chunk_number += 1

        if end >= len(words):
            break

        overlap_length = 0
        next_start = end
        while next_start > start + 1 and overlap_length < overlap:
            next_start -= 1
            overlap_length += len(words[next_start]) + 1
        start = next_start

    return chunks


def chunk_documents(
    documents: List[Document],
    chunk_size: int = 800,
    overlap: int = 150,
) -> List[Chunk]:
    chunks: List[Chunk] = []
    for document in documents:
        chunks.extend(chunk_document(document, chunk_size, overlap))
    return chunks

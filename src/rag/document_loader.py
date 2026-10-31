from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List


SUPPORTED_EXTENSIONS = {".md", ".txt"}
METADATA_KEYS = {
    "source": "provider",
    "provider": "provider",
    "source url": "url",
    "url": "url",
    "category": "category",
    "description": "description",
}


@dataclass
class Document:
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


def extract_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        cleaned = line.strip().lstrip("#").strip()
        if cleaned:
            return cleaned
    return fallback


def parse_document(raw_text: str, fallback_title: str, fallback_source: str) -> dict:
    title = extract_title(raw_text, fallback_title)
    metadata = {
        "provider": fallback_source.upper(),
        "url": "",
        "category": "unknown",
        "description": "",
    }
    body_lines: list[str] = []

    for line in raw_text.splitlines():
        stripped = line.strip()

        if stripped.startswith("#"):
            continue

        if ":" in stripped:
            key, value = stripped.split(":", 1)
            normalized_key = key.strip().lower()
            mapped_key = METADATA_KEYS.get(normalized_key)

            if mapped_key and value.strip():
                metadata[mapped_key] = value.strip()
                continue

        body_lines.append(line)

    text = "\n".join(body_lines).strip()
    description = metadata["description"] or next(
        (line.strip() for line in body_lines if line.strip()),
        title,
    )

    return {
        "title": title,
        "provider": metadata["provider"],
        "url": metadata["url"],
        "category": metadata["category"],
        "description": description,
        "text": text,
    }


def load_documents(root_directory: str | Path = "knowledge/raw") -> List[Document]:
    root = Path(root_directory)

    if not root.exists():
        raise FileNotFoundError(
            f"Knowledge directory does not exist: {root.resolve()}"
        )

    documents: List[Document] = []

    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file() or file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        raw_text = file_path.read_text(encoding="utf-8").strip()
        if not raw_text:
            continue

        relative_path = file_path.relative_to(root)
        source = relative_path.parts[0] if len(relative_path.parts) > 1 else "unknown"
        parsed = parse_document(
            raw_text,
            fallback_title=file_path.stem.replace("_", " ").title(),
            fallback_source=source,
        )

        documents.append(
            Document(
                document_id=str(relative_path).replace("/", "__"),
                source=source,
                path=str(file_path),
                **parsed,
            )
        )

    return documents


if __name__ == "__main__":
    loaded_documents = load_documents()
    print(f"Loaded {len(loaded_documents)} document(s).")

    for document in loaded_documents:
        print(
            f"- [{document.provider}] {document.title} "
            f"({document.category}, {len(document.text)} characters)"
        )

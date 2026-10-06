from pathlib import Path


KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"

CHUNK_SIZE = 800
CHUNK_OVERLAP = 120


def load_documents(directory: Path = KNOWLEDGE_DIR) -> list[dict]:
    documents = []

    for file_path in sorted(directory.glob("*.md")):
        content = file_path.read_text(encoding="utf-8").strip()

        if not content:
            continue

        documents.append({
            "source": file_path.name,
            "content": content,
        })

    return documents


def split_into_chunks(
    text: str,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[str]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero.")

    if overlap < 0 or overlap >= chunk_size:
        raise ValueError(
            "overlap must be non-negative and smaller than chunk_size."
        )

    words = text.split()

    if not words:
        return []

    chunks = []
    start = 0

    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunk = " ".join(words[start:end])
        chunks.append(chunk)

        if end == len(words):
            break

        start = end - overlap

    return chunks


def build_knowledge_base(
    directory: Path = KNOWLEDGE_DIR,
) -> list[dict]:
    documents = load_documents(directory)
    knowledge_chunks = []

    for document in documents:
        chunks = split_into_chunks(document["content"])

        for index, chunk in enumerate(chunks):
            knowledge_chunks.append({
                "id": f"{document['source']}:{index}",
                "source": document["source"],
                "chunk_index": index,
                "content": chunk,
            })

    return knowledge_chunks
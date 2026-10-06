from pathlib import Path

import chromadb
from openai import OpenAI

from app.assistant.config import get_openai_api_key
from app.assistant.documents import build_knowledge_base


DEFAULT_DB_PATH = Path("data/chroma")
EMBEDDING_MODEL = "text-embedding-3-small"


class SecurityKnowledgeBase:
    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        client=None,
        embedding_client=None,
    ):
        self.db_path = db_path
        self.db_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.client = client or chromadb.PersistentClient(
            path=str(self.db_path)
        )

        self.embedding_client = (
            embedding_client
            or OpenAI(api_key=get_openai_api_key())
        )

        self.collection = self.client.get_or_create_collection(
            name="security_knowledge",
            metadata={
                "hnsw:space": "cosine",
            },
        )

    def create_embeddings(
        self,
        texts: list[str],
    ) -> list[list[float]]:
        if not texts:
            return []

        response = self.embedding_client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=texts,
        )

        return [
            item.embedding
            for item in response.data
        ]

    def index_documents(self) -> int:
        chunks = build_knowledge_base()

        if not chunks:
            return 0

        embeddings = self.create_embeddings(
            [chunk["content"] for chunk in chunks]
        )

        self.collection.upsert(
            ids=[
                chunk["id"]
                for chunk in chunks
            ],
            documents=[
                chunk["content"]
                for chunk in chunks
            ],
            embeddings=embeddings,
            metadatas=[
                {
                    "source": chunk["source"],
                    "chunk_index": chunk["chunk_index"],
                }
                for chunk in chunks
            ],
        )

        return len(chunks)

    def search(
        self,
        query: str,
        top_k: int = 3,
    ) -> list[dict]:
        if not query.strip():
            raise ValueError(
                "Query cannot be empty."
            )

        if top_k < 1 or top_k > 10:
            raise ValueError(
                "top_k must be between 1 and 10."
            )

        collection_size = self.collection.count()

        if collection_size == 0:
            return []

        query_embedding = self.create_embeddings(
            [query]
        )[0]

        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=min(
                top_k,
                collection_size,
            ),
            include=[
                "documents",
                "metadatas",
                "distances",
            ],
        )

        documents = results["documents"][0]
        metadatas = results["metadatas"][0]
        distances = results["distances"][0]

        return [
            {
                "content": document,
                "source": metadata["source"],
                "chunk_index": metadata["chunk_index"],
                "distance": distance,
            }
            for document, metadata, distance in zip(
                documents,
                metadatas,
                distances,
            )
        ]

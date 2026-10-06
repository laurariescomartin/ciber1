import pytest

from app.assistant.retrieval import SecurityKnowledgeBase


class FakeEmbeddingResponse:
    def __init__(self, embeddings):
        self.data = [
            type("Embedding", (), {"embedding": embedding})()
            for embedding in embeddings
        ]


class FakeEmbeddingClient:
    class embeddings:
        @staticmethod
        def create(model, input):
            vectors = []

            for text in input:
                normalized = text.lower()

                if "cookie" in normalized or "httponly" in normalized:
                    vectors.append([1.0, 0.0, 0.0])

                elif "https" in normalized or "transport" in normalized:
                    vectors.append([0.0, 1.0, 0.0])

                else:
                    vectors.append([0.0, 0.0, 1.0])

            return FakeEmbeddingResponse(vectors)


def test_create_embeddings(tmp_path):
    knowledge_base = SecurityKnowledgeBase(
        db_path=tmp_path / "chroma",
        embedding_client=FakeEmbeddingClient(),
    )

    embeddings = knowledge_base.create_embeddings(
        [
            "Cookie security with HttpOnly",
            "HTTPS and transport security",
        ]
    )

    assert len(embeddings) == 2
    assert embeddings[0] == [1.0, 0.0, 0.0]
    assert embeddings[1] == [0.0, 1.0, 0.0]


def test_create_embeddings_empty_list(tmp_path):
    knowledge_base = SecurityKnowledgeBase(
        db_path=tmp_path / "chroma",
        embedding_client=FakeEmbeddingClient(),
    )

    embeddings = knowledge_base.create_embeddings([])

    assert embeddings == []


def test_search_rejects_empty_query(tmp_path):
    knowledge_base = SecurityKnowledgeBase(
        db_path=tmp_path / "chroma",
        embedding_client=FakeEmbeddingClient(),
    )

    with pytest.raises(ValueError):
        knowledge_base.search("   ")


def test_search_rejects_invalid_top_k(tmp_path):
    knowledge_base = SecurityKnowledgeBase(
        db_path=tmp_path / "chroma",
        embedding_client=FakeEmbeddingClient(),
    )

    with pytest.raises(ValueError):
        knowledge_base.search("cookie security", top_k=0)

    with pytest.raises(ValueError):
        knowledge_base.search("cookie security", top_k=11)


def test_search_returns_relevant_document(tmp_path, monkeypatch):
    knowledge_base = SecurityKnowledgeBase(
        db_path=tmp_path / "chroma",
        embedding_client=FakeEmbeddingClient(),
    )

    def fake_build_knowledge_base():
        return [
            {
                "id": "cookies.md:0",
                "source": "cookies.md",
                "chunk_index": 0,
                "content": (
                    "Cookie security requires HttpOnly "
                    "and Secure attributes."
                ),
            },
            {
                "id": "headers.md:0",
                "source": "headers.md",
                "chunk_index": 0,
                "content": (
                    "HSTS enforces HTTPS connections."
                ),
            },
        ]

    monkeypatch.setattr(
        "app.assistant.retrieval.build_knowledge_base",
        fake_build_knowledge_base,
    )

    indexed_count = knowledge_base.index_documents()

    assert indexed_count == 2

    results = knowledge_base.search(
        "How do I protect a cookie?",
        top_k=1,
    )

    assert len(results) == 1
    assert results[0]["source"] == "cookies.md"
    assert "HttpOnly" in results[0]["content"]


def test_search_empty_collection(tmp_path):
    knowledge_base = SecurityKnowledgeBase(
        db_path=tmp_path / "chroma",
        embedding_client=FakeEmbeddingClient(),
    )

    results = knowledge_base.search(
        "cookie security"
    )

    assert results == []


def test_index_documents_returns_zero_when_empty(
    tmp_path,
    monkeypatch,
):
    knowledge_base = SecurityKnowledgeBase(
        db_path=tmp_path / "chroma",
        embedding_client=FakeEmbeddingClient(),
    )

    monkeypatch.setattr(
        "app.assistant.retrieval.build_knowledge_base",
        lambda: [],
    )

    indexed_count = knowledge_base.index_documents()

    assert indexed_count == 0
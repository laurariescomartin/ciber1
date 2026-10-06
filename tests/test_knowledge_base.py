from pathlib import Path

import pytest

from app.assistant.documents import (
    build_knowledge_base,
    load_documents,
    split_into_chunks,
)


def test_load_documents(tmp_path):
    document = tmp_path / "security.md"
    document.write_text(
        "# Security\nUse HTTPS.",
        encoding="utf-8",
    )

    documents = load_documents(tmp_path)

    assert len(documents) == 1
    assert documents[0]["source"] == "security.md"
    assert "Use HTTPS" in documents[0]["content"]


def test_load_documents_ignores_empty_files(tmp_path):
    (tmp_path / "empty.md").write_text("", encoding="utf-8")

    documents = load_documents(tmp_path)

    assert documents == []


def test_split_into_chunks():
    text = "one two three four five six"

    chunks = split_into_chunks(
        text,
        chunk_size=3,
        overlap=1,
    )

    assert chunks == [
        "one two three",
        "three four five",
        "five six",
    ]


def test_split_empty_text():
    assert split_into_chunks("") == []


@pytest.mark.parametrize(
    ("chunk_size", "overlap"),
    [
        (0, 0),
        (5, -1),
        (5, 5),
        (5, 6),
    ],
)
def test_invalid_chunk_configuration(chunk_size, overlap):
    with pytest.raises(ValueError):
        split_into_chunks(
            "some text",
            chunk_size=chunk_size,
            overlap=overlap,
        )


def test_build_knowledge_base(tmp_path):
    (tmp_path / "cookies.md").write_text(
        "# Cookies\nUse HttpOnly and Secure.",
        encoding="utf-8",
    )

    chunks = build_knowledge_base(tmp_path)

    assert len(chunks) == 1
    assert chunks[0]["id"] == "cookies.md:0"
    assert chunks[0]["source"] == "cookies.md"
    assert chunks[0]["chunk_index"] == 0
    assert "HttpOnly" in chunks[0]["content"]
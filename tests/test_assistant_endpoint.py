import httpx
import pytest

from app.main import app


@pytest.mark.asyncio
async def test_assistant_endpoint(monkeypatch):
    async def fake_answer(
        question,
        top_k=3,
    ):
        return {
            "question": question,
            "answer": "Use HttpOnly for appropriate session cookies.",
            "sources": [
                {
                    "source": "cookies.md",
                    "chunk_index": 0,
                    "distance": 0.1,
                }
            ],
        }

    class FakeAssistant:
        def answer(self, question, top_k=3):
            return {
                "question": question,
                "answer": "Use HttpOnly for appropriate session cookies.",
                "sources": [
                    {
                        "source": "cookies.md",
                        "chunk_index": 0,
                        "distance": 0.1,
                    }
                ],
            }

    monkeypatch.setattr(
        "app.main.assistant",
        FakeAssistant(),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/assistant",
            json={
                "question": "Why should I use HttpOnly?",
                "top_k": 3,
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["question"] == "Why should I use HttpOnly?"
    assert "HttpOnly" in data["answer"]
    assert data["sources"][0]["source"] == "cookies.md"
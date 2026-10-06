from app.assistant.assistant import SecurityAssistant


class FakeKnowledgeBase:
    def search(self, query, top_k=3):
        return [
            {
                "source": "cookies.md",
                "chunk_index": 0,
                "content": (
                    "HttpOnly prevents JavaScript from "
                    "accessing cookies."
                ),
                "distance": 0.1,
            }
        ]


class FakeGenerator:
    def generate(self, question, context):
        assert question == "How do I protect cookies?"
        assert len(context) == 1

        return "Use HttpOnly and Secure for appropriate session cookies."


def test_assistant_combines_retrieval_and_generation():
    assistant = SecurityAssistant(
        knowledge_base=FakeKnowledgeBase(),
        generator=FakeGenerator(),
    )

    result = assistant.answer(
        "How do I protect cookies?"
    )

    assert result["question"] == "How do I protect cookies?"
    assert "HttpOnly" in result["answer"]
    assert len(result["sources"]) == 1
    assert result["sources"][0]["source"] == "cookies.md"


def test_assistant_returns_message_without_results():
    class EmptyKnowledgeBase:
        def search(self, query, top_k=3):
            return []

    assistant = SecurityAssistant(
        knowledge_base=EmptyKnowledgeBase(),
        generator=FakeGenerator(),
    )

    result = assistant.answer(
        "Something unrelated"
    )

    assert result["sources"] == []
    assert "No relevant" in result["answer"]


def test_assistant_rejects_empty_question():
    assistant = SecurityAssistant(
        knowledge_base=FakeKnowledgeBase(),
        generator=FakeGenerator(),
    )

    try:
        assistant.answer("   ")
        assert False
    except ValueError:
        pass


def test_assistant_explains_finding():
    class FindingKnowledgeBase:
        def search(self, query, top_k=3):
            assert "Content-Security-Policy" in query

            return [
                {
                    "source": "security_headers.md",
                    "chunk_index": 0,
                    "content": (
                        "Content-Security-Policy helps reduce "
                        "the impact of XSS and content injection."
                    ),
                    "distance": 0.1,
                }
            ]

    class FindingGenerator:
        def generate(self, question, context):
            assert "Missing Content-Security-Policy" in question
            assert "Risk score: 9" in question
            assert len(context) == 1

            return (
                "The missing CSP header increases the impact "
                "of certain XSS and content injection attacks."
            )

    assistant = SecurityAssistant(
        knowledge_base=FindingKnowledgeBase(),
        generator=FindingGenerator(),
    )

    finding = {
        "id": "SEC-001",
        "title": "Missing Content-Security-Policy",
        "severity": "medium",
        "category": "Security Headers",
        "evidence": (
            "The Content-Security-Policy header "
            "was not present in the HTTP response."
        ),
        "recommendation": (
            "Define a restrictive Content-Security-Policy."
        ),
        "risk_score": 9,
        "risk_level": "medium",
    }

    result = assistant.explain_finding(finding)

    assert result["finding_id"] == "SEC-001"
    assert "missing CSP" in result["answer"]
    assert len(result["sources"]) == 1
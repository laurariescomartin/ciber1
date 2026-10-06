from app.assistant.generator import SecurityAnswerGenerator
from app.assistant.retrieval import SecurityKnowledgeBase


class SecurityAssistant:
    def __init__(
        self,
        knowledge_base=None,
        generator=None,
    ):
        self.knowledge_base = (
            knowledge_base
            or SecurityKnowledgeBase()
        )

        self.generator = (
            generator
            or SecurityAnswerGenerator()
        )

    def answer(
        self,
        question: str,
        top_k: int = 3,
    ) -> dict:
        if not question.strip():
            raise ValueError(
                "Question cannot be empty."
            )

        results = self.knowledge_base.search(
            question,
            top_k=top_k,
        )

        if not results:
            return {
                "question": question,
                "answer": (
                    "No relevant security knowledge "
                    "was found for this question."
                ),
                "sources": [],
            }

        answer = self.generator.generate(
            question,
            results,
        )

        return {
            "question": question,
            "answer": answer,
            "sources": [
                {
                    "source": result["source"],
                    "chunk_index": result["chunk_index"],
                    "distance": result["distance"],
                }
                for result in results
            ],
        }

    def explain_finding(
        self,
        finding: dict,
        top_k: int = 3,
    ) -> dict:
        required_fields = {
            "id",
            "title",
            "severity",
            "category",
            "evidence",
            "recommendation",
            "risk_score",
            "risk_level",
        }

        missing_fields = required_fields - finding.keys()

        if missing_fields:
            raise ValueError(
                "Finding is missing required fields: "
                + ", ".join(sorted(missing_fields))
            )

        question = f"""
Explain the following CyberSentinel security finding.

Finding ID: {finding["id"]}
Title: {finding["title"]}
Severity: {finding["severity"]}
Category: {finding["category"]}
Risk score: {finding["risk_score"]}
Risk level: {finding["risk_level"]}

Evidence:
{finding["evidence"]}

Current recommendation:
{finding["recommendation"]}

Explain:
1. What the finding means.
2. Why it matters from a security perspective.
3. What risks it may introduce.
4. How it can be mitigated.

Base the explanation on the available security knowledge.
Do not invent evidence that is not present in the finding.
""".strip()

        result = self.answer(
            question,
            top_k=top_k,
        )

        return {
            **result,
            "finding_id": finding["id"],
        }
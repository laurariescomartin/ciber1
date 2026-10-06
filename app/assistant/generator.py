from openai import OpenAI

from app.assistant.config import get_openai_api_key


GENERATION_MODEL = "gpt-4o-mini"


class SecurityAnswerGenerator:
    def __init__(
        self,
        client=None,
    ):
        self.client = client or OpenAI(
            api_key=get_openai_api_key()
        )

    def generate(
        self,
        question: str,
        context: list[dict],
    ) -> str:
        if not question.strip():
            raise ValueError(
                "Question cannot be empty."
            )

        if not context:
            raise ValueError(
                "Context cannot be empty."
            )

        context_text = "\n\n".join(
            (
                f"Source: {item['source']}\n"
                f"{item['content']}"
            )
            for item in context
        )

        system_prompt = """
You are a cybersecurity assistant for CyberSentinel.

Your role is to explain security findings clearly and
provide practical defensive recommendations.

Use only the supplied security context when making
security-specific claims.

Do not invent vulnerabilities, evidence, or facts
that are not supported by the context.

If the context is insufficient, explicitly say that
the available evidence is insufficient.

Keep recommendations defensive and focused on
secure configuration, mitigation, and risk reduction.
"""

        user_prompt = f"""
Security context:

{context_text}

Question:

{question}

Provide a concise technical explanation and, when
appropriate, a practical mitigation recommendation.
"""

        response = self.client.chat.completions.create(
            model=GENERATION_MODEL,
            temperature=0.2,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt.strip(),
                },
                {
                    "role": "user",
                    "content": user_prompt.strip(),
                },
            ],
        )

        return response.choices[0].message.content.strip()
from app.assistant.generator import SecurityAnswerGenerator


class FakeChoice:
    class Message:
        content = "Use HttpOnly to reduce client-side access to the cookie."

    message = Message()


class FakeResponse:
    choices = [FakeChoice()]


class FakeCompletions:
    def create(self, **kwargs):
        return FakeResponse()


class FakeChat:
    completions = FakeCompletions()


class FakeOpenAIClient:
    chat = FakeChat()


def test_generate_answer():
    generator = SecurityAnswerGenerator(
        client=FakeOpenAIClient()
    )

    context = [
        {
            "source": "cookies.md",
            "content": (
                "HttpOnly prevents JavaScript from "
                "accessing the cookie through normal browser APIs."
            ),
        }
    ]

    answer = generator.generate(
        "Why should I use HttpOnly?",
        context,
    )

    assert "HttpOnly" in answer


def test_generate_rejects_empty_question():
    generator = SecurityAnswerGenerator(
        client=FakeOpenAIClient()
    )

    context = [
        {
            "source": "cookies.md",
            "content": "Cookie security information.",
        }
    ]

    try:
        generator.generate(
            "   ",
            context,
        )
        assert False
    except ValueError:
        pass


def test_generate_rejects_empty_context():
    generator = SecurityAnswerGenerator(
        client=FakeOpenAIClient()
    )

    try:
        generator.generate(
            "How should I secure cookies?",
            [],
        )
        assert False
    except ValueError:
        pass
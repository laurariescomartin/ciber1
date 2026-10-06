from app.assistant.retrieval import SecurityKnowledgeBase


def main():
    knowledge_base = SecurityKnowledgeBase()

    count = knowledge_base.index_documents()

    print(
        f"Indexed {count} security knowledge chunks."
    )


if __name__ == "__main__":
    main()
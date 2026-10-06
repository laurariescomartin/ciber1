# CyberSentinel

CyberSentinel is a defensive web security analysis platform built with Python and FastAPI for identifying common security weaknesses in authorized web applications.

The project combines automated security checks, explainable risk scoring, PostgreSQL persistence, a professional dashboard and a RAG-based Security Assistant.

## Key Features

- Automated analysis of web security configurations
- Security header and cookie analysis
- HTTPS and transport security checks
- Detection of information disclosure
- Form security analysis
- Explainable risk scoring based on likelihood and impact
- PostgreSQL persistence for scans and findings
- Interactive security dashboard
- RAG-based Security Assistant using ChromaDB and OpenAI
- Docker support
- Automated test suite

## Security Checks

CyberSentinel currently analyzes:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Cookie security attributes: Secure, HttpOnly and SameSite
- HTTPS usage and redirects
- Server and technology disclosure
- Form submission over insecure HTTP
- External form destinations

The platform performs defensive, non-exploitative analysis and does not attempt to compromise the target.

## Risk Model

Each finding is evaluated using:

**Risk Score = Likelihood × Impact**

Findings are then classified into:

`Very Low · Low · Medium · High · Very High · Critical`

This provides an explainable way to prioritize security findings instead of simply reporting isolated configuration issues.

## Security Assistant

CyberSentinel includes a Retrieval-Augmented Generation (RAG) assistant that provides security explanations based on the project's knowledge base.

**Flow:**

`Finding → Retrieval → Security Context → LLM → Explanation`

Technologies used:

- ChromaDB for vector storage
- OpenAI embeddings
- LangChain
- OpenAI LLM
- Markdown-based security knowledge base

The assistant is designed to explain findings, their security impact and recommended mitigations without inventing evidence that was not detected by the scanner.

## Architecture

```text
Web Dashboard
      │
      ▼
   FastAPI
      │
      ▼
 Security Engine
      │
      ├── Headers Scanner
      ├── Cookies Scanner
      ├── HTTPS Scanner
      ├── Server Scanner
      └── Forms Scanner
      │
      ▼
 Risk Assessment
      │
      ▼
 PostgreSQL
      │
      └── Security Assistant
              │
              ├── ChromaDB
              ├── Retrieval
              └── LLM
```

## Tech Stack

### Backend

- Python
- FastAPI
- Pydantic
- SQLAlchemy

### Security

- HTTP security analysis
- Security headers
- Cookie security
- HTTPS configuration
- Risk assessment
- Defensive security automation

### AI / RAG

- ChromaDB
- OpenAI
- LangChain
- Embeddings
- Retrieval-Augmented Generation

### Database

- PostgreSQL

### Frontend

- HTML
- CSS
- JavaScript

### DevOps & Testing

- Docker
- Docker Compose
- Git
- Pytest

## Testing

The project includes automated tests covering scanners, URL validation, HTTP handling, risk assessment, database persistence and the RAG assistant.

**78 tests passed**

## Project Structure

```text
app/
├── assistant/
├── database/
├── http/
├── models/
├── scanners/
├── security/
├── static/
└── templates/

scripts/
tests/
data/
```

## Running Locally

```bash
python -m uvicorn app.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

## Docker

```bash
docker compose up --build
```

## Scope

CyberSentinel is intended for **authorized defensive security assessments**.

It focuses on identifying and explaining security configuration weaknesses without performing exploitation or intrusive attacks.

## Author

**Laura**
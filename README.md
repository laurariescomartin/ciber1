# CyberSentinel

CyberSentinel is a defensive web security analysis platform built with Python and FastAPI to identify common security weaknesses in authorized web applications.

The platform combines automated security checks, explainable risk scoring, PostgreSQL persistence, an interactive dashboard, and a Retrieval-Augmented Generation (RAG) Security Assistant.

## Key Features

- Automated analysis of web security configurations
- Security header and cookie analysis
- HTTPS usage and redirect checks
- Server and technology information disclosure detection
- Form security analysis
- Explainable risk scoring based on likelihood and impact
- PostgreSQL persistence for scans and findings
- Interactive security dashboard with scan history
- RAG-based Security Assistant powered by ChromaDB and OpenAI
- Docker support
- Automated test suite

## Security Checks

CyberSentinel currently analyzes:

- `Content-Security-Policy` (CSP)
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- Cookie security attributes: `Secure`, `HttpOnly`, and `SameSite`
- HTTPS usage and redirect behavior
- Server and technology information disclosure
- Form submissions over insecure HTTP
- External form destinations

The platform focuses on defensive, non-intrusive analysis. It does not attempt to exploit vulnerabilities or compromise target systems.

## Risk Model

Each finding is evaluated using likelihood and impact values.

**Risk Score = Likelihood × Impact**

Findings are classified into six risk levels:

`Very Low · Low · Medium · High · Very High · Critical`

This scoring model provides an explainable way to prioritize findings and remediation efforts. Risk scores are heuristic indicators and should be interpreted in the context of the application being assessed.

## Security Assistant

CyberSentinel includes a Retrieval-Augmented Generation (RAG) assistant that explains security findings using a dedicated security knowledge base.

**Workflow:**

`Finding → Retrieval → Security Context → LLM → Explanation`

Technologies used:

- **ChromaDB** for vector storage
- **OpenAI embeddings** for semantic retrieval
- **LangChain** for LLM integration
- **OpenAI** for generating explanations
- **Markdown** for the security knowledge base

The assistant provides context about findings, their potential security impact, and recommended mitigations. Its explanations are advisory; the scanner's evidence remains the basis for each detected finding.

## Architecture

```text
Web Dashboard
      |
      v
   FastAPI
      |
      v
 Security Engine
      |
      +-- Headers Scanner
      +-- Cookies Scanner
      +-- HTTPS Scanner
      +-- Server Scanner
      +-- Forms Scanner
      |
      v
 Risk Assessment
      |
      v
 PostgreSQL
      |
      +-- Scan History
      +-- Findings

Security Assistant
      |
      +-- Security Knowledge Base
      +-- ChromaDB Retrieval
      +-- OpenAI LLM
```

## Tech Stack

### Backend

- Python
- FastAPI
- Pydantic
- SQLAlchemy
- HTTPX

### Security Analysis

- HTTP security configuration analysis
- Security headers and cookie attributes
- HTTPS and redirect checks
- Information disclosure detection
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

### DevOps and Testing

- Docker
- Docker Compose
- Git
- Pytest

## Testing

The automated test suite covers security scanners, URL validation, HTTP handling, risk assessment, database persistence, knowledge retrieval, and the Security Assistant.

**Last recorded result: 78 tests passed.**

Run the test suite with:

```bash
python -m pytest -q
```

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

### Requirements

- Python 3.13 or a compatible version
- PostgreSQL
- An OpenAI API key for the Security Assistant

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

Configure the required environment variables in a local `.env` file, using `.env.example` as a template. Ensure PostgreSQL is running and `DATABASE_URL` points to the correct database. Set `OPENAI_API_KEY` to enable the Security Assistant.

Start the application:

```bash
python -m uvicorn app.main:app --reload
```

Open the dashboard:

`http://127.0.0.1:8000`

API documentation:

`http://127.0.0.1:8000/docs`

## Docker

Start the application and its configured services with:

```bash
docker compose up --build
```

Ensure the required environment variables are configured before starting the services.

## Scope and Responsible Use

CyberSentinel is intended exclusively for authorized defensive security assessments. Only scan websites and applications that you own or have explicit permission to assess.

The platform identifies and explains selected web security configuration weaknesses. It is not a full penetration testing framework and does not perform intrusive exploitation.

## Author

**Laura Riesco Martín**

# Peregrine Security — Site Sentry

A cinematic AI-powered web security auditor built with FastAPI and Google Gemini.

![Peregrine](intro_buddha.png)

## Features

- **Cinematic Intro** — 3D parallax Matrix Buddha with glitch effects and digital rain
- **Oracle Intelligence** — Ask any security question; powered by Gemini AI
- **Site Sentry Scanner** — Deep security audit of any live URL:
  - Real HTTP/HTTPS fetch with redirect tracking
  - SSL/TLS certificate validation & expiry check
  - 8-point security header analysis (CSP, HSTS, X-Frame-Options, etc.)
  - Cookie flag inspection (HttpOnly, Secure, SameSite)
  - Information disclosure detection
  - AI-generated risk score (0–100), executive summary, exploit vectors & remediation code

## Stack

| Layer | Tech |
|---|---|
| Backend | Python · FastAPI · Uvicorn |
| AI | Google Gemini 2.0 Flash |
| HTTP Analysis | httpx |
| Frontend | HTML · TailwindCSS CDN · Lucide Icons |

## Quick Start

### 1. Install dependencies
```bash
pip install fastapi uvicorn httpx python-dotenv google-genai
```

### 2. Configure API key
```bash
cp .env.example .env
# Edit .env and add your Gemini API key
# Get one free at: https://aistudio.google.com/app/apikey
```

### 3. Run
```bash
python server.py
```

Open **http://localhost:8000** in your browser.

## API Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/` | Frontend (peregrine.html) |
| GET | `/api/health` | Server + Gemini status |
| POST | `/api/oracle` | AI security oracle |
| POST | `/api/scan` | Full URL security audit |

### Oracle Request
```json
POST /api/oracle
{ "prompt": "How do I protect against XSS?" }
```

### Scan Request
```json
POST /api/scan
{ "url": "https://example.com" }
```

### Scan Response (summary)
```json
{
  "status": "success",
  "target": "https://example.com",
  "risk_score": 53,
  "ai_summary": "...",
  "vulnerabilities": [...],
  "exploit_vectors": [...],
  "remediation": "..."
}
```

## Fallback Mode

If no `GEMINI_API_KEY` is set, the backend runs in **smart fallback mode** — real HTTP/SSL scanning still works, but AI analysis uses curated static responses.

## License

MIT

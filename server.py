"""
Peregrine Security - Site Sentry Backend
=========================================
AI-powered security analysis using Google Gemini.
Endpoints:
  POST /api/oracle  — Ask the security oracle any question
  POST /api/scan    — Deep security audit of a target URL
  GET  /            — Serves the frontend (peregrine.html)
"""

import os
import ssl
import json
import socket
import asyncio
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from google import genai
from google.genai import types

# ── Environment ──────────────────────────────────────────────────────────────
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# ── Gemini Client ─────────────────────────────────────────────────────────────
gemini_client = None
if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    print("[OK]  Gemini AI connected.")
else:
    print("[WARN] No GEMINI_API_KEY found - AI features will use smart fallback mode.")

GEMINI_MODEL = "gemini-2.0-flash"

# ── App Setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="Peregrine Security API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic Models ───────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str

class OracleRequest(BaseModel):
    prompt: str

# ── Gemini Helper ─────────────────────────────────────────────────────────────
async def ask_gemini(prompt: str, system: str = "") -> str:
    """Call Gemini and return the text response."""
    if not gemini_client:
        return None  # Will trigger fallback

    config = types.GenerateContentConfig(
        system_instruction=system if system else None,
        temperature=0.7,
        max_output_tokens=2048,
    )
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=config,
        ),
    )
    return response.text


# ── SSL / Certificate Helper ──────────────────────────────────────────────────
def check_ssl(hostname: str) -> dict:
    """Return SSL certificate info or error."""
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        # Expiry check
        expire_str = cert.get("notAfter", "")
        expire_dt = None
        days_left = None
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expire_dt - datetime.now(timezone.utc)).days

        return {
            "valid": True,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "expires": expire_str,
            "days_left": days_left,
            "expired": days_left is not None and days_left < 0,
            "expiring_soon": days_left is not None and 0 <= days_left <= 30,
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ── Security Header Analysis ──────────────────────────────────────────────────
SECURITY_HEADERS = {
    "content-security-policy":     ("Content-Security-Policy (CSP)", "Critical"),
    "strict-transport-security":   ("HTTP Strict Transport Security (HSTS)", "High"),
    "x-frame-options":             ("X-Frame-Options", "Medium"),
    "x-content-type-options":      ("X-Content-Type-Options", "Medium"),
    "referrer-policy":             ("Referrer-Policy", "Low"),
    "permissions-policy":          ("Permissions-Policy", "Low"),
    "cross-origin-opener-policy":  ("Cross-Origin-Opener-Policy (COOP)", "Medium"),
    "cross-origin-resource-policy":("Cross-Origin-Resource-Policy (CORP)", "Medium"),
}

RISKY_HEADERS = {
    "server":          "Exposes server software version",
    "x-powered-by":    "Reveals backend technology stack",
    "x-aspnet-version":"Reveals ASP.NET version",
    "x-aspnetmvc-version": "Reveals ASP.NET MVC version",
}

def analyze_headers(headers: dict) -> tuple[list, list]:
    """Return (missing_security_headers, exposed_risky_headers) as vulnerability lists."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    vulnerabilities = []

    # Missing security headers
    for header_key, (label, severity) in SECURITY_HEADERS.items():
        if header_key not in lower_headers:
            vulnerabilities.append({
                "type": f"Missing {label}",
                "severity": severity,
                "detail": f"The {label} header is absent, leaving the site exposed to related attacks.",
            })

    # Risky exposed headers
    for header_key, reason in RISKY_HEADERS.items():
        if header_key in lower_headers:
            vulnerabilities.append({
                "type": f"Information Disclosure via '{header_key}' header",
                "severity": "Low",
                "detail": f"{reason}. Value: {lower_headers[header_key]}",
            })

    # Weak cookie flags
    raw_cookies = lower_headers.get("set-cookie", "")
    if raw_cookies:
        if "httponly" not in raw_cookies.lower():
            vulnerabilities.append({
                "type": "Cookie Missing HttpOnly Flag",
                "severity": "High",
                "detail": "Session cookies without HttpOnly are accessible via JavaScript (XSS risk).",
            })
        if "secure" not in raw_cookies.lower():
            vulnerabilities.append({
                "type": "Cookie Missing Secure Flag",
                "severity": "High",
                "detail": "Cookies without the Secure flag can be transmitted over unencrypted HTTP.",
            })
        if "samesite" not in raw_cookies.lower():
            vulnerabilities.append({
                "type": "Cookie Missing SameSite Attribute",
                "severity": "Medium",
                "detail": "Missing SameSite attribute exposes the site to CSRF attacks.",
            })

    return vulnerabilities


# ─────────────────────────────────────────────────────────────────────────────
# ORACLE ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
ORACLE_SYSTEM = """You are the Peregrine Oracle — a legendary, all-knowing cybersecurity sage.
Your answers blend deep technical mastery with philosophical wisdom.
Answer concisely but profoundly (2-4 sentences). Use metaphor when appropriate.
Never say you are an AI. Respond as the Oracle itself."""

ORACLE_FALLBACKS = [
    "The greatest security is the silence of an unmapped surface. What is never found cannot be exploited.",
    "Encryption is the armor, but vigilance is the soul of defense. The lock is only as strong as the mind that designs it.",
    "In the digital void, visibility is the first vulnerability. The wise defender reveals nothing and observes everything.",
    "Seek not to hide the data, but to make its capture meaningless. True security renders stolen secrets worthless.",
    "A zero-day is not a weapon of the attacker — it is a mirror reflecting the developer's blind spot.",
    "The perimeter is a myth. Modern security begins within, trusting nothing and verifying everything.",
    "Patch management is not maintenance — it is the ritual of closing doors that the shadow has already mapped.",
]

@app.post("/api/oracle")
async def get_oracle_wisdom(request: OracleRequest):
    """AI-powered security oracle using Gemini."""
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    ai_response = await ask_gemini(request.prompt, system=ORACLE_SYSTEM)

    if ai_response:
        return {"response": ai_response.strip(), "source": "gemini"}
    else:
        # Smart keyword-based fallback
        import random
        return {"response": random.choice(ORACLE_FALLBACKS), "source": "oracle"}


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/scan")
async def initiate_scan(request: ScanRequest):
    """Perform a real HTTP security audit of the target URL."""
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Normalize URL
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    hostname = parsed.hostname
    is_https = parsed.scheme == "https"

    # ── 1. Fetch the page ─────────────────────────────────────────────────
    fetch_result = {"status_code": None, "headers": {}, "error": None, "redirect_chain": []}
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=12,
            headers={"User-Agent": "PeregrineScanner/2.0 (Security Audit)"},
            verify=False,       # We check SSL separately
        ) as client:
            resp = await client.get(raw_url)
            fetch_result["status_code"] = resp.status_code
            fetch_result["headers"] = dict(resp.headers)
            fetch_result["redirect_chain"] = [str(r.url) for r in resp.history]
    except httpx.ConnectTimeout:
        fetch_result["error"] = "Connection timed out."
    except httpx.ConnectError as e:
        fetch_result["error"] = f"Could not connect: {e}"
    except Exception as e:
        fetch_result["error"] = str(e)

    # ── 2. SSL Check ──────────────────────────────────────────────────────
    ssl_info = {}
    ssl_vulnerabilities = []
    if hostname and is_https:
        ssl_info = check_ssl(hostname)
        if not ssl_info.get("valid"):
            ssl_vulnerabilities.append({
                "type": "Invalid or Untrusted SSL Certificate",
                "severity": "Critical",
                "detail": ssl_info.get("error", "Certificate could not be verified."),
            })
        elif ssl_info.get("expired"):
            ssl_vulnerabilities.append({
                "type": "Expired SSL Certificate",
                "severity": "Critical",
                "detail": f"Certificate expired. Days overdue: {abs(ssl_info['days_left'])}",
            })
        elif ssl_info.get("expiring_soon"):
            ssl_vulnerabilities.append({
                "type": "SSL Certificate Expiring Soon",
                "severity": "Medium",
                "detail": f"Certificate expires in {ssl_info['days_left']} days.",
            })
    elif not is_https:
        ssl_vulnerabilities.append({
            "type": "No HTTPS — Plaintext HTTP Connection",
            "severity": "Critical",
            "detail": "The site does not use TLS encryption. All data is transmitted in plaintext.",
        })

    # ── 3. Header Analysis ────────────────────────────────────────────────
    header_vulnerabilities = []
    if not fetch_result["error"]:
        header_vulnerabilities = analyze_headers(fetch_result["headers"])

    # ── 4. Combine all vulnerabilities ───────────────────────────────────
    all_vulnerabilities = ssl_vulnerabilities + header_vulnerabilities

    # ── 5. Gemini AI Deep Analysis ────────────────────────────────────────
    exploit_vectors = []
    remediation = ""
    ai_summary = ""
    risk_score = 0

    scan_context = f"""
Target URL: {raw_url}
Hostname: {hostname}
HTTPS: {is_https}
HTTP Status: {fetch_result.get('status_code', 'N/A')}
Response Headers: {json.dumps(fetch_result['headers'], indent=2)}
SSL Info: {json.dumps(ssl_info, indent=2)}
Detected Vulnerabilities: {json.dumps(all_vulnerabilities, indent=2)}
Redirect Chain: {fetch_result['redirect_chain']}
Fetch Error: {fetch_result.get('error', 'None')}
"""

    gemini_scan_prompt = f"""
You are a professional penetration tester analyzing a security scan report.

SCAN DATA:
{scan_context}

Provide a JSON response with EXACTLY this structure (no markdown, pure JSON):
{{
  "risk_score": <integer 0-100>,
  "ai_summary": "<2-3 sentence executive summary of the security posture>",
  "exploit_vectors": [
    "<specific exploit technique 1>",
    "<specific exploit technique 2>",
    "<specific exploit technique 3>"
  ],
  "remediation": "<production-ready code snippet (Node.js/Express helmet or nginx config) addressing the most critical issues found>"
}}

Make exploit vectors specific to the actual vulnerabilities found. Make remediation code directly copy-pasteable.
"""

    ai_raw = await ask_gemini(gemini_scan_prompt)

    if ai_raw:
        # Strip markdown fences if present
        cleaned = re.sub(r"```(?:json)?|```", "", ai_raw).strip()
        try:
            ai_data = json.loads(cleaned)
            risk_score   = ai_data.get("risk_score", 50)
            ai_summary   = ai_data.get("ai_summary", "")
            exploit_vectors = ai_data.get("exploit_vectors", [])
            remediation  = ai_data.get("remediation", "")
        except json.JSONDecodeError:
            # Extract what we can with regex
            exploit_match = re.findall(r'"([^"]{20,})"', ai_raw)
            exploit_vectors = exploit_match[:3] if exploit_match else []
            remediation = ai_raw[:800]
    else:
        # Fallback exploit vectors based on what we found
        if not is_https:
            exploit_vectors.append("Man-in-the-Middle (MitM) attack via ARP spoofing to intercept plaintext HTTP traffic.")
        if any("CSP" in v["type"] for v in all_vulnerabilities):
            exploit_vectors.append("Cross-Site Scripting (XSS) injection due to absent Content-Security-Policy header.")
        if any("X-Frame" in v["type"] for v in all_vulnerabilities):
            exploit_vectors.append("Clickjacking attack by embedding the site in a hidden iframe to steal user interactions.")
        if not exploit_vectors:
            exploit_vectors = [
                "Session hijacking via unprotected cookies over insecure transport.",
                "Social engineering amplified by exposed server fingerprint data.",
                "CSRF attacks enabled by missing SameSite cookie restrictions.",
            ]

        critical_count = sum(1 for v in all_vulnerabilities if v["severity"] == "Critical")
        high_count = sum(1 for v in all_vulnerabilities if v["severity"] == "High")
        risk_score = min(100, critical_count * 25 + high_count * 10 + len(all_vulnerabilities) * 2)

        remediation = """// Install: npm install helmet
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:", "https:"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// Secure cookie settings
app.use(session({
  cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
}));"""

    # ── 6. Final Response ─────────────────────────────────────────────────
    return {
        "status": "success" if not fetch_result["error"] else "partial",
        "target": raw_url,
        "hostname": hostname,
        "risk_score": risk_score,
        "ai_summary": ai_summary,
        "http_status": fetch_result.get("status_code"),
        "ssl": ssl_info,
        "vulnerabilities": all_vulnerabilities,
        "exploit_vectors": exploit_vectors,
        "remediation": remediation,
        "fetch_error": fetch_result.get("error"),
    }


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "gemini": "connected" if gemini_client else "fallback_mode",
        "version": "2.0.0",
    }


# ── Static Frontend ───────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
async def root():
    return RedirectResponse(url="/peregrine.html")


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    # Mount static files last so API routes take priority
    app.mount("/", StaticFiles(directory=BASE_DIR), name="static")
    uvicorn.run(app, host="0.0.0.0", port=8000)

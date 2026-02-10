# app/main.py
"""
CYBERGUARD CORE - ACCURACY BOOSTED
Includes Hybrid Heuristics to catch Business Email Compromise (BEC)
"""
import uvicorn
import shutil
import tempfile
import os
import re
import datetime
import logging
import sqlite3
import asyncio
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any
from pathlib import Path

# Framework Imports
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image
import pytesseract

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberGuard")

# --- 1. DATA MODELS ---
class ExplanationItem(BaseModel):
    type: str
    text: str
    severity: str

class AnalysisResponse(BaseModel):
    risk_score: int
    attack_type: str
    confidence: float
    explanations: List[ExplanationItem]
    analyzed_text: str
    processing_details: dict
    timestamp: str

# --- 2. SUBSYSTEM: OCR ---
def extract_text_from_image(image_path: str) -> str:
    path = Path(image_path)
    if not path.exists(): return ""
    try:
        with Image.open(path) as img:
            gray_img = img.convert('L') # Grayscale
            # Tesseract config to treat image as block of text
            custom_config = r'--oem 3 --psm 6' 
            text = pytesseract.image_to_string(gray_img, config=custom_config, timeout=5)
            clean_text = " ".join(text.split())
            logger.info(f"OCR Extracted: {clean_text[:50]}...")
            return clean_text
    except Exception as e:
        logger.error(f"OCR Error: {e}")
        return ""

# --- 3. SUBSYSTEM: THREAT DB ---
DB_PATH = "threat_intel.db"
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS malicious_domains
                 (domain TEXT PRIMARY KEY, threat_type TEXT, risk_score INTEGER)''')
    demo_data = [
        ('fake-login.com', 'Credential Harvesting', 95),
        ('secure-update-verify.net', 'Phishing', 90),
        ('apple-support-verify.com', 'Impersonation', 85),
    ]
    try:
        c.executemany('INSERT OR IGNORE INTO malicious_domains VALUES (?,?,?)', demo_data)
        conn.commit()
    except Exception: pass
    finally: conn.close()

def check_domain(url: str) -> dict:
    try:
        if not url.startswith(('http://', 'https://')): url = 'http://' + url
        domain = urlparse(url).netloc
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT threat_type, risk_score FROM malicious_domains WHERE domain=?", (domain,))
        result = c.fetchone()
        conn.close()
        if result: return {"found": True, "threat_type": result[0], "db_risk_score": result[1]}
    except Exception: pass
    return {"found": False, "db_risk_score": 0}

# --- 4. SUBSYSTEM: AI + HEURISTICS (THE FIX) ---
class AnalysisEngine:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AnalysisEngine, cls).__new__(cls)
            cls._instance.model = None
        return cls._instance

    def load_model(self):
        if self.model is None:
            logger.info("Loading BERT Model...")
            try:
                from transformers import pipeline
                self.model = pipeline("text-classification", model="mrm8488/bert-tiny-finetuned-sms-spam-detection", top_k=None)
            except Exception:
                self.model = None

    def calculate_heuristic_score(self, text: str) -> Dict[str, Any]:
        """Manual overrides for specific phishing phrases"""
        text_lower = text.lower()
        score = 0
        triggers = []

        # 1. Critical Phrases (Instant High Score)
        critical_phrases = {
            "account has been suspended": 90,
            "verify your identity": 85,
            "update your information": 80,
            "unusual activity detected": 85,
            "click here to login": 80,
            "confirm your password": 90
        }

        # 2. Suspicious Keywords (Additive Score)
        keywords = ["urgent", "immediately", "suspended", "lock", "bank", "paypal", "wells fargo", "irs", "expires"]
        
        # Check Phrases
        for phrase, weight in critical_phrases.items():
            if phrase in text_lower:
                score = max(score, weight)
                triggers.append(f"Detected Threat Phrase: '{phrase}'")

        # Check Keywords
        keyword_count = sum(1 for k in keywords if k in text_lower)
        if keyword_count > 2 and score < 60:
            score = 65
            triggers.append(f"High density of urgency keywords ({keyword_count} found)")

        return {"score": score, "triggers": triggers}

    def analyze(self, text: str) -> Dict[str, Any]:
        if not self.model: self.load_model()
        
        # 1. Get AI Score
        ai_score = 0
        if self.model and text:
            try:
                results = self.model(text[:512])
                scores = {item['label']: item['score'] for item in results[0]}
                ai_score = scores.get('LABEL_1', 0.0) * 100
            except: pass

        # 2. Get Heuristic Score (The Safety Net)
        heuristics = self.calculate_heuristic_score(text)
        h_score = heuristics["score"]

        # 3. Hybrid Decision: Take the HIGHER of the two
        # This ensures that if AI misses it (24%), but Heuristics sees "Suspended" (90%), we return 90%.
        final_confidence = max(ai_score, h_score)
        
        return {
            "phishing_confidence": round(final_confidence, 2),
            "heuristic_triggers": heuristics["triggers"],
            "ai_raw": round(ai_score, 2)
        }

ai_engine = AnalysisEngine()

# --- 5. SUBSYSTEM: AGENT ---
async def analyze_url_deeply(url: str):
    results = {"domain_age_days": -1}
    try:
        import whois
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            results["domain_age_days"] = (datetime.datetime.now() - cd).days
    except: pass
    return results

# --- 6. API CONTROLLER ---
init_db()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_content(
    channel: str = Form(...),
    text: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None),
) -> AnalysisResponse:
    
    analyzed_content = ""
    processing_source = "text"

    if text:
        analyzed_content = text
    elif image:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
                shutil.copyfileobj(image.file, tmp)
                tmp_path = tmp.name
            analyzed_content = extract_text_from_image(tmp_path)
            processing_source = "image"
        finally:
            if 'tmp_path' in locals() and os.path.exists(tmp_path): os.unlink(tmp_path)
    else:
        raise HTTPException(status_code=400, detail="No input provided")

    if not analyzed_content.strip(): analyzed_content = "Empty content"

    # Analysis
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', analyzed_content)
    agent_findings = {}
    if urls: agent_findings = await analyze_url_deeply(urls[0])

    analysis_result = ai_engine.analyze(analyzed_content)
    risk_score = analysis_result["phishing_confidence"]
    triggers = analysis_result["heuristic_triggers"]
    
    # DB Check
    db_found = False
    db_info = {}
    for url in urls:
        check = check_domain(url)
        if check["found"]:
            db_found = True
            db_info = check
            risk_score = 99 # DB overrides everything
            break

    # Build Response
    explanations = []

    if db_found:
        explanations.append(ExplanationItem(type="threat_intel", text=f"Blocked by Threat DB: {db_info['threat_type']}", severity="critical"))
    
    if risk_score > 80:
        if triggers:
            for t in triggers:
                 explanations.append(ExplanationItem(type="heuristic", text=t, severity="critical"))
        else:
             explanations.append(ExplanationItem(type="ai", text=f"AI Model Confidence: {risk_score}%", severity="critical"))
    elif risk_score > 50:
        explanations.append(ExplanationItem(type="ai", text="Suspicious Language Patterns Detected", severity="high"))

    if agent_findings.get("domain_age_days", 999) < 30 and agent_findings.get("domain_age_days") != -1:
        risk_score = max(risk_score, 85)
        explanations.append(ExplanationItem(type="forensics", text=f"New Domain (Registered {agent_findings['domain_age_days']} days ago)", severity="critical"))

    return AnalysisResponse(
        risk_score=int(min(99, risk_score)),
        attack_type="Phishing / Malicious" if risk_score > 75 else "Safe",
        confidence=risk_score/100,
        explanations=explanations,
        analyzed_text=analyzed_content[:500],
        processing_details={
            "source": processing_source,
            "raw_ai": analysis_result["ai_raw"],
            "triggers_found": len(triggers)
        },
        timestamp=datetime.datetime.now().isoformat()
    )
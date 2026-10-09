import shap
import numpy as np
import urllib.parse
import difflib
import sqlite3
import pandas as pd
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # THIS IS THE MISSING LINE
from pydantic import BaseModel
from typing import List, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from backend.database import init_db, save_alert, DB_NAME

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

# --- SCENARIO 1: REAL DATASET ML PIPELINE ---
vectorizer = TfidfVectorizer()
classifier = LogisticRegression()

# Load the real dataset using Pandas
dataset_path = "phishing_dataset.csv"

try:
    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        X_train = vectorizer.fit_transform(df['text'])
        classifier.fit(X_train, df['label'])
        print(f"✅ ML Model trained successfully on {len(df)} records.")
        #pass the actual X_train variable to the explainer 
        background_data = X_train[:100]
        # pass the actual classifier variable to SHAP
        explainer = shap.LinearExplainer(classifier, background_data)
        print("✅ SHAP Explainer ready.")
    else:
        print("⚠️ Warning: phishing_dataset.csv not found. Falling back to toy data.")
        vectorizer.fit(["urgent verify account", "lunch meeting tomorrow project"])
        classifier.fit(vectorizer.transform(["urgent verify account", "lunch meeting tomorrow project"]), [1, 0])
        explainer = None
except Exception as e:
    print(f"❌ Failed to load dataset: {e}")

# --- API DATA MODELS ---
class PhishingRequest(BaseModel):
    sender_email: str
    reply_to: Optional[str] = None
    subject: str
    body: str
    urls: List[str] = []

class URLRequest(BaseModel):
    url: str
    
class LoginRequest(BaseModel):
    username: str
    timestamp: str
    ip_address: str
    location: str
    failed_attempt_count: int
    login_status: str

# --- SCENARIO 1: PHISHING ENGINE ---
@app.post("/api/analyze/phishing")
def analyze_phishing(request: PhishingRequest):
    evidence = []
    risk_score = 0
    
    combined_text = f"{request.subject} {request.body}"
    text_features = vectorizer.transform([combined_text])
    ml_prediction = classifier.predict(text_features)[0]
    
    if ml_prediction == 1:
        risk_score += 40
        evidence.append("AI Text Analysis flagged suspicious language.")
        
    if request.reply_to and request.reply_to.lower() != request.sender_email.lower():
        risk_score += 30
        evidence.append(f"Sender ({request.sender_email}) and Reply-To ({request.reply_to}) mismatch.")
        
    suspicious_keywords = ["login", "verify", "secure", "update", "account"]
    for url in request.urls:
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            risk_score += 30
            evidence.append(f"Suspicious keyword found in URL: {url}")
            
    risk_level = "Critical" if risk_score >= 70 else "Medium" if risk_score >= 40 else "Low"
    recommended_action = "Quarantine email" if risk_score >= 40 else "Allow delivery"
    
    if risk_score > 0:
        save_alert("Phishing / Social Engineering", request.sender_email, min(risk_score, 100), risk_level, evidence, recommended_action)
        
    return {
        "threat_category": "Phishing / Social Engineering",
        "total_risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "evidence": evidence
    }

# --- SCENARIO 5: MALICIOUS URL ENGINE ---
@app.post("/api/analyze/url")
def analyze_url(request: URLRequest):
    try:
        evidence = []
        risk_score = 0
        url = request.url
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = str(parsed_url.hostname or "").lower()
        except ValueError:
            raw_netloc = url.split("://")[-1].split("/")[0]
            domain = raw_netloc.split("@")[-1].lower() if "@" in raw_netloc else raw_netloc.lower()
        
        if len(url) > 75:
            risk_score += 15
            evidence.append(f"URL is unusually long ({len(url)} characters).")
            
        if "@" in url:
            risk_score += 40
            evidence.append("Suspicious '@' symbol found. May be attempting to hide the true destination.")
            
        if "-" in domain:
            risk_score += 15
            evidence.append("Domain contains hyphens, often used in deceptive domains.")

        protected_brands = ["paypal.com", "google.com", "secure-bank.com"]
        for brand in protected_brands:
            similarity = difflib.SequenceMatcher(None, domain, brand).ratio()
            if similarity > 0.80 and domain != brand:
                risk_score += 60
                evidence.append(f"Typosquatting alert: Domain '{domain}' is impersonating '{brand}'.")
                break

        risk_level = "Critical" if risk_score >= 70 else "Medium" if risk_score >= 40 else "Low"
        recommended_action = "Block URL immediately" if risk_score >= 70 else "Show warning interstitial" if risk_score >= 40 else "Allow access"
        
        if risk_score > 0:
            save_alert("Malicious URL / Digital Impersonation", domain, min(risk_score, 100), risk_level, evidence, recommended_action)
            
        return {
            "threat_category": "Malicious URL / Digital Impersonation",
            "analyzed_domain": domain,
            "total_risk_score": min(risk_score, 100),
            "risk_level": risk_level,
            "evidence": evidence
        }
    except Exception as e:
        return {"CRITICAL_DEBUG_ERROR": str(e), "line_failed": e.__traceback__.tb_lineno}

# --- SCENARIO 4: ACCOUNT TAKEOVER ENGINE ---
@app.post("/api/analyze/login")
def analyze_login(request: LoginRequest):
    evidence = []
    risk_score = 0
    
    if request.failed_attempt_count >= 5:
        risk_score += 50
        evidence.append(f"High number of failed attempts ({request.failed_attempt_count}). Possible Brute Force or Credential Stuffing.")
        
    baseline_location = "Brahmapur, IN"
    if request.location.lower() != baseline_location.lower():
        risk_score += 30
        evidence.append(f"Login attempt from unusual location: {request.location} (Baseline: {baseline_location}).")
        
    if request.login_status.lower() == "success" and request.failed_attempt_count > 3:
        risk_score += 40
        evidence.append("Successful login immediately following multiple failed attempts. High risk of Account Takeover.")

    risk_level = "Critical" if risk_score >= 70 else "Medium" if risk_score >= 40 else "Low"
    recommended_action = "Lock account and require immediate password reset" if risk_score >= 70 else "Require MFA challenge" if risk_score >= 40 else "Allow login"
    
    if risk_score > 0:
        save_alert("Credential Theft / Account Takeover", request.username, min(risk_score, 100), risk_level, evidence, recommended_action)
        
    return {
        "threat_category": "Credential Theft / Account Takeover",
        "analyzed_user": request.username,
        "total_risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "evidence": evidence,
        "recommended_action": recommended_action
    }

# --- FETCH ALERTS FOR DASHBOARD (READ) ---
@app.get("/api/alerts")
def get_alerts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    
    alerts = []
    for row in rows:
        alerts.append({
            "id": row[0],
            "timestamp": row[1],
            "threat_category": row[2],
            "target_entity": row[3],
            "risk_score": row[4],
            "risk_level": row[5],
            "evidence": row[6],
            "recommended_action": row[7]
        })
    return alerts
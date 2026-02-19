from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import os
import random

app = Flask(__name__)
# CORS allow karta hai taki Chrome Extension server se data bhej/le sake
CORS(app) 

LOG_FILE = 'scanned_urls.csv'

# Agar CSV file nahi hai toh nayi banayein
if not os.path.exists(LOG_FILE):
    df = pd.DataFrame(columns=['Timestamp', 'URL', 'Status', 'Risk Score'])
    df.to_csv(LOG_FILE, index=False)

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '')
    timestamp = data.get('timestamp', '')
    
    print(f"\n🌐 Nayi Request Aayi: {url}")
    
    # YAHAN AAPKA AI MODEL AAYEGA
    # Demo ke liye hum ek random risk score generate kar rahe hain (0.1 se 0.9)
    # Asli project me aap yahan: model.predict(features) likhenge
    risk_score = random.uniform(0.1, 0.9) 
    
    # Agar URL me malware/phishing word hai YA risk score 70% se zyada hai
    if "malware" in url or "phishing" in url or risk_score > 0.70:
        status = "malicious"
    else:
        status = "safe"
        
    # Data ko CSV file me Save kar rahe hain
    log_data = pd.DataFrame([{
        'Timestamp': timestamp,
        'URL': url,
        'Status': status,
        'Risk Score': round(risk_score * 100, 2)
    }])
    log_data.to_csv(LOG_FILE, mode='a', header=False, index=False)
    
    if status == "malicious":
        print(f"🚨 BLOCKED: Data saved to CSV. Risk: {risk_score:.2f}")
    else:
        print(f"✅ ALLOWED: Data saved to CSV. Risk: {risk_score:.2f}")
    
    # Extension ko result wapas bhejein
    return jsonify({"status": status, "risk_score": risk_score})

if __name__ == '__main__':
    print("🚀 Dn AI Shield Backend Server shuru ho gaya hai!")
    print("Extension ab is server par data bhej sakta hai (http://localhost:5000)")
    app.run(port=5000, debug=True)
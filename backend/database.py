import sqlite3
from datetime import datetime

DB_NAME = "cyberguard.db"

def init_db():
    # Connects to the file (or creates it if it doesn't exist)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create the Alerts table with 'id' as our Primary Key
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_category TEXT NOT NULL,
            target_entity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            evidence TEXT NOT NULL,
            recommended_action TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def save_alert(threat_category, target_entity, risk_score, risk_level, evidence_list, recommended_action):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Convert our Python list of evidence into a single string to save in the database
    evidence_str = " | ".join(evidence_list)
    timestamp = datetime.now().isoformat()
    
    # This is the 'C' (Create) in CRUD
    cursor.execute('''
        INSERT INTO alerts (timestamp, threat_category, target_entity, risk_score, risk_level, evidence, recommended_action)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, threat_category, target_entity, risk_score, risk_level, evidence_str, recommended_action))
    
    conn.commit()
    conn.close()
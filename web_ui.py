import os
import json
from flask import Flask, render_template, jsonify
from glob import glob

app = Flask(__name__)

SESSIONS_DIR = os.path.expanduser("~/hackassist_sessions")

def get_all_sessions():
    sessions = []
    if not os.path.exists(SESSIONS_DIR):
        return sessions
        
    for d in os.listdir(SESSIONS_DIR):
        path = os.path.join(SESSIONS_DIR, d)
        if os.path.isdir(path):
            session_data = {
                "id": d,
                "target": "Unknown",
                "findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "commands": 0
            }
            
            # Load metadata if exists
            meta_file = os.path.join(path, "meta.json")
            if os.path.exists(meta_file):
                try:
                    with open(meta_file, 'r') as f:
                        meta = json.load(f)
                        session_data["target"] = meta.get("target", session_data["target"])
                except Exception: pass
            
            # Count findings
            findings_file = os.path.join(path, "findings.json")
            if os.path.exists(findings_file):
                try:
                    with open(findings_file, 'r') as f:
                        findings = json.load(f)
                        session_data["findings"] = len(findings)
                        for fin in findings:
                            sev = fin.get("severity", "info").lower()
                            if sev in ["critical"]: session_data["critical"] += 1
                            elif sev in ["high"]: session_data["high"] += 1
                            elif sev in ["medium"]: session_data["medium"] += 1
                            elif sev in ["low"]: session_data["low"] += 1
                except Exception: pass
            
            # Count commands
            cmd_file = os.path.join(path, "commands.log")
            if os.path.exists(cmd_file):
                session_data["commands"] = sum(1 for _ in open(cmd_file))
                
            sessions.append(session_data)
            
    return sessions

def get_session_details(session_id):
    path = os.path.join(SESSIONS_DIR, session_id)
    if not os.path.exists(path): return None
    
    data = {
        "id": session_id,
        "findings": [],
        "commands": []
    }
    
    findings_file = os.path.join(path, "findings.json")
    if os.path.exists(findings_file):
        try:
            with open(findings_file, 'r') as f:
                data["findings"] = json.load(f)
        except Exception: pass
        
    cmd_file = os.path.join(path, "commands.log")
    if os.path.exists(cmd_file):
        try:
            with open(cmd_file, 'r') as f:
                data["commands"] = [line.strip() for line in f.readlines()[-50:]] # Last 50 commands
        except Exception: pass
        
    return data

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/sessions")
def api_sessions():
    return jsonify(get_all_sessions())

@app.route("/api/sessions/<session_id>")
def api_session_detail(session_id):
    data = get_session_details(session_id)
    return jsonify(data) if data else (jsonify({"error": "Not found"}), 404)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)

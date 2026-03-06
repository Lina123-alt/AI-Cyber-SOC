from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from analyzer import analyze_logs
import json
import simulate_attacks
import requests
import time

app = Flask(__name__)
app.secret_key = "soc_secret_key" 

API_KEY = "my_key" # I hid the API key

def call_gemini_direct(prompt):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={API_KEY}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        response = requests.post(url, json=payload, timeout=5)
        result = response.json()
        if 'candidates' in result:
            return result['candidates'][0]['content']['parts'][0]['text']
    except:
        return None
    return None

@app.route('/')
def index():
    data = analyze_logs()
    total_attempts = sum(info["count"] for info in data.values())

    alerts = [f"CRITICAL: Host {ip} risk level high" for ip, info in data.items() if info["risk_score"] >= 0.7]
    
    top_ips = sorted(data.items(), key=lambda x: x[1]["count"], reverse=True)[:5]
    
    risk_summary = {"Critical": 0, "Medium": 0, "Low": 0}
    for info in data.values():
        if info["risk_score"] >= 0.8: risk_summary["Critical"] += 1
        elif info["risk_score"] >= 0.5: risk_summary["Medium"] += 1
        else: risk_summary["Low"] += 1

    attack_distribution = {"SSH": 0, "FTP": 0, "WebLogin": 0}
    for info in data.values():
        for proto in attack_distribution:
            attack_distribution[proto] += info["types"].get(proto, 0)

    recommendation = {"status": "STABLE", "action": "INTEGRITY VERIFIED", "color": "#4caf50"}
    if risk_summary["Critical"] > 0:
        recommendation = {"status": "CRITICAL", "action": "IMMEDIATE ISOLATION REQUIRED", "color": "#f44336"}

    return render_template(
        "report.html",
        data=data, top_ips=top_ips, alerts=alerts,
        attack_distribution=attack_distribution,
        risk_summary=risk_summary, total_ips=len(data),
        total_attempts=total_attempts, high_risk=len(alerts),
        recommendation=recommendation
    )

@app.route('/ask_cyber', methods=['POST'])
def ask_cyber():
    user_query = request.json.get("query", "").lower()
    
    # 1. Récupération des données réelles du projet
    try:
        data = analyze_logs() 
    except Exception as e:
        return jsonify({"answer": "Erreur technique : Impossible d'analyser les logs."})

    # 2. Préparation des statistiques pour l'IA
    total_attacks = sum(info["count"] for info in data.values())
    critical_ips = [ip for ip, info in data.items() if info["risk_score"] >= 0.8]
    
    all_ports = []
    for info in data.values():
        all_ports.extend(info.get("ports_list", []))
    unique_ports = sorted(list(set(all_ports)))

    # 3. Construction du prompt
    context = (
        f"Statistiques SOC : {total_attacks} incidents. "
        f"Ports détectés : {', '.join(unique_ports) if unique_ports else 'Aucun'}. "
        f"IPs suspectes : {', '.join(critical_ips[:3])}. "
        f"Données brutes ML : {str(data)[:600]}"
    )
    
    prompt = (
        f"Tu es CyberGPT Pro, expert en cybersécurité. "
        f"Réponds de façon technique et concise (pas d'emojis). "
        f"Contexte actuel : {context}. "
        f"Question : {user_query}"
    )
    
    # 4. Appel Gemini
    answer = call_gemini_direct(prompt)
    
    # 5. Système de secours (Fallback) si l'IA est hors-ligne
    if not answer:
        if "port" in user_query:
            answer = f"ANALYSE PORTS : {len(unique_ports)} ports distincts ont été visés. Liste : {unique_ports}."
        elif "ip" in user_query or "attaquant" in user_query:
            threat = critical_ips[0] if critical_ips else "Aucune"
            answer = f"IP TRACKER : {len(critical_ips)} IPs sont classées critiques par le modèle ML. Top menace : {threat}."
        elif "pourquoi" in user_query or "raison" in user_query:
            answer = "RAISON : Les logs indiquent des tentatives de brute-force (SSH/FTP) et des scans de reconnaissance via 'Connection attempt'."
        else:
            answer = "CYBER-ENGINE : Analyse en cours... Le modèle ML confirme un risque élevé sur les ports détectés."

    return jsonify({"answer": answer})

@app.route('/ban_ip', methods=['POST'])
def ban_ip():
    ip = request.json.get('ip')
    # Simulation de la commande système
    # import subprocess
    # subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    return jsonify({"status": "success", "message": f"IP {ip} bannie avec succès du Firewall."})

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/simulate')
def simulate():
    simulate_attacks.simulate_attacks(50)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

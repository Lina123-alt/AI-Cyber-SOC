import os
import re
import joblib

# 🔹 Configuration du modèle ML
MODEL_PATH = "model/model.pkl"

def load_ml_model():
    if not os.path.exists(MODEL_PATH):
        # On ne bloque pas tout le programme, on retourne None si absent
        return None
    return joblib.load(MODEL_PATH)

model = load_ml_model()

def predict_risk(ip_features: dict) -> float:
    """
    Retourne un score entre 0 et 1 basé sur le modèle ML.
    Si le modèle est absent, retourne un score par défaut.
    """
    if model is None:
        return 0.85 # Score de secours si le fichier .pkl est manquant

    try:
        features = [[
            ip_features["total_requests"],
            ip_features["error_count"],
            ip_features["unique_paths"],
            ip_features["error_ratio"],
            ip_features["ftp_ratio"],
            ip_features["weblogin_ratio"]
        ]]
        score = model.predict_proba(features)[0][1]
        return score
    except:
        return 0.82

def analyze_logs(log_file="logs/log.txt"):
    if not os.path.exists(log_file):
        raise FileNotFoundError(f"Fichier de logs non trouve : {log_file}")

    with open(log_file, "r") as f:
        lines = f.readlines()

    # 🔹 Patterns de détection (Ajout du Port Scanning)
    patterns = {
        "SSH": r"Failed password.*from (\d+\.\d+\.\d+\.\d+)",
        "WebLogin": r"login failed.*from (\d+\.\d+\.\d+\.\d+)",
        "FTP": r"Authentication failed.*from (\d+\.\d+\.\d+\.\d+)",
        "PortScan": r"Connection attempt.*port (\d+).*from (\d+\.\d+\.\d+\.\d+)"
    }

    ip_counter = {}

    for line in lines:
        for attack_type, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                # Gestion particuliere pour PortScan car l'IP est en group(2)
                if attack_type == "PortScan":
                    port = match.group(1)
                    ip = match.group(2)
                else:
                    ip = match.group(1)
                    port = None

                if ip not in ip_counter:
                    ip_counter[ip] = {"count": 0, "types": {}, "ports_scanned": set()}

                ip_counter[ip]["count"] += 1
                ip_counter[ip]["types"][attack_type] = ip_counter[ip]["types"].get(attack_type, 0) + 1
                
                if port:
                    ip_counter[ip]["ports_scanned"].add(port)

    # 🔹 Calcul final des scores
    for ip, info in ip_counter.items():
        total = info["count"]
        types = info["types"]
        
        # On prepare les donnees exactes pour le modele ML
        features = {
            "total_requests": total,
            "error_count": total, # Chaque log detecte est une erreur/alerte
            "unique_paths": len(info["ports_scanned"]) if info["ports_scanned"] else 1,
            "error_ratio": 1.0,
            "ftp_ratio": types.get("FTP", 0) / total,
            "weblogin_ratio": types.get("WebLogin", 0) / total
        }

        # Calcul du score via ML + securite projet (>= 0.8)
        raw_score = predict_risk(features)
        info["risk_score"] = max(raw_score, 0.8)
        
        # On transforme le set de ports en liste pour le JSON (Flask n'aime pas les sets)
        info["ports_list"] = list(info["ports_scanned"])
        del info["ports_scanned"] # Nettoyage

    return ip_counter

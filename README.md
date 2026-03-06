AI-Cyber-SOC : Documentation Technique
Ce projet implémente un Dashboard SOC (Security Operations Center) modulaire intégrant une détection hybride par Machine Learning et une analyse contextuelle via l'IA Générative.

 Architecture du Système

🔹 Moteur d'Analyse Web (app.py)
Fonction : Point d'entrée de l'application basé sur le framework Flask. Gère l'orchestration des données entre le backend et l'interface utilisateur.

Intégration IA : Implémente une interface avec l'API Google Gemini (modèle 1.5 Flash) pour générer des rapports d'incidents détaillés à partir des statistiques de trafic.

Protocoles : Gestion des requêtes asynchrones et des points de terminaison REST pour le bannissement d'IP et la simulation.

🔹 Modèle de Détection ML (ml_model.py)
Algorithme : Utilisation d'un classifieur Random Forest (Scikit-Learn).

Features : Analyse de vecteurs basés sur le volume de requêtes, le ratio d'erreurs, l'unicité des chemins et l'activité sur les protocoles critiques (FTP, SSH, Web).

Persistance : Sérialisation du modèle via Joblib pour une inférence rapide sans réentraînement.

🔹 Analyse de Logs et Inférence (analyzer.py)
Traitement de données : Parsing de logs système via expressions régulières (Regex) pour l'extraction d'IP et de ports.

Logique de Scoring : Calcul d'un indice de risque par IP, croisant les détections de patterns (Port Scanning, Brute Force) et les probabilités retournées par le modèle ML.

🔹 Environnement de Simulation (simulate_attacks.py)
Objectif : Génération de trafic synthétique malveillant (SSH Failed login, Connection attempts) pour la validation des alertes.

Conformité : Respect du formatage standard des logs Unix avec horodatage dynamique.

🔹 Interface Utilisateur (loading.html)
UX/UI : Page de transition gérant la latence lors de l'injection de payloads dans le système de logs.

Stack : CSS3 (Animations de transition) et JavaScript pour la gestion des redirections d'états.

🔹 Stack Technique
Backend : Python 3.x / Flask

Data Science : Scikit-Learn, Pandas, Joblib

IA : Google Generative AI API

SecOps : Analyse de logs, Regex, Simulation de vecteurs d'attaque

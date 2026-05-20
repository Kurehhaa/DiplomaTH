# backend/app/ttp_service.py
from typing import List, Dict

# Простая база знаний: порт/технология → MITRE ATT&CK техники
TTP_MAPPING = {
    22: ["T1021.004", "T1110"],           # SSH → Remote Services + Brute Force
    3389: ["T1021.001", "T1110", "T1550"], # RDP → Remote Desktop + Brute Force
    445: ["T1021.002", "T1550", "T1190"], # SMB → Remote Services + Exploit
    3306: ["T1190", "T1550"],             # MySQL
    80: ["T1190", "T1133"],               # HTTP → Exploit Public-Facing App
    443: ["T1190", "T1133"],
    8080: ["T1190"],
    # По технологиям
    "Apache": ["T1190", "T1059"],
    "nginx": ["T1190"],
    "PHP": ["T1190", "T1059.003"],
    "WordPress": ["T1190", "T1210"],
}

def predict_ttp(open_ports: List[int], technologies: List[str], findings: List[dict]) -> List[Dict]:
    """
    Возвращает список вероятных MITRE ATT&CK техник для данной цели
    """
    predicted = []

    # По открытым портам
    for port in open_ports:
        if port in TTP_MAPPING:
            for ttp in TTP_MAPPING[port]:
                predicted.append({
                    "technique_id": ttp,
                    "source": f"Port {port}",
                    "description": f"High probability due to exposed port {port}",
                    "likelihood": "High"
                })

    # По технологиям
    for tech in technologies:
        tech_lower = tech.lower()
        for key, ttps in TTP_MAPPING.items():
            if isinstance(key, str) and key.lower() in tech_lower:
                for ttp in ttps:
                    predicted.append({
                        "technique_id": ttp,
                        "source": f"Technology: {tech}",
                        "description": f"Common technique for {tech}",
                        "likelihood": "Medium"
                    })

    # Убираем дубли
    unique = {item["technique_id"]: item for item in predicted}
    return list(unique.values())[:8]  # максимум 8 самых релевантных
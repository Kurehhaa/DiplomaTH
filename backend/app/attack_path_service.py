# backend/app/attack_path_service.py
from app.llm_service import generate_attack_paths_with_llm


def generate_attack_paths(open_ports: list, technologies: list, ttp_predictions: list, scan_result: dict = None):
    """
    Генерирует Attack Paths через Groq
    """
    if scan_result is None:
        scan_result = {
            "target": "unknown",
            "network": {"open_ports": open_ports},
            "summary": {"detected_technologies": technologies},
            "findings": [],
            "proactive": {"ttp_predictions": ttp_predictions}
        }

    # Основной вызов Groq
    paths = generate_attack_paths_with_llm(scan_result)

    # Fallback если Groq не сработал
    if not paths or len(paths) == 0:
        print("⚠️ Groq не вернул пути → fallback")
        return [
            {
                "name": "Web Application Attack",
                "description": "Exploitation of exposed web services and technologies",
                "ttp_chain": ["T1190", "T1059"],
                "likelihood": "Medium",
                "recommendation": "Perform detailed web vulnerability scanning"
            }
        ]

    return paths
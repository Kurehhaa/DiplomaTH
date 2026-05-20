# backend/app/mitre_service.py
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

# ==================== MITRE ATT&CK MAPPING ====================
PORT_TO_TTP = {
    21: ["T1190", "T1210"],      # FTP → Exploit Public-Facing App / Exploitation of Remote Services
    22: ["T1021.001", "T1110"],  # SSH → Remote Services + Brute Force
    25: ["T1190", "T1566"],      # SMTP
    445: ["T1021.002", "T1210"], # SMB
    3389: ["T1021.001", "T1110"],# RDP
    3306: ["T1210", "T1190"],    # MySQL
    5432: ["T1210"],             # PostgreSQL
    8080: ["T1190"],
    80: ["T1190", "T1505"],
    443: ["T1190", "T1505"],
}

TECH_TO_TTP = {
    "Apache": ["T1190", "T1505.003"],
    "nginx": ["T1190"],
    "PHP": ["T1190", "T1059.004"],
    "WordPress": ["T1190", "T1212"],
    "MySQL": ["T1210"],
    "Microsoft-IIS": ["T1190"],
}

class MitreService:
    
    @staticmethod
    def get_ttp_from_ports(open_ports: List[int]) -> List[Dict]:
        ttps = []
        seen = set()
        
        for port in open_ports:
            if port in PORT_TO_TTP:
                for ttp in PORT_TO_TTP[port]:
                    if ttp not in seen:
                        seen.add(ttp)
                        ttps.append({
                            "technique_id": ttp,
                            "name": f"Technique {ttp}",
                            "description": f"Detected via open port {port}",
                            "likelihood": "High" if port in [445, 3389, 22] else "Medium"
                        })
        return ttps

    @staticmethod
    def get_ttp_from_technologies(technologies: List[str]) -> List[Dict]:
        ttps = []
        seen = set()
        
        for tech in technologies:
            for key in TECH_TO_TTP:
                if key.lower() in tech.lower():
                    for ttp in TECH_TO_TTP[key]:
                        if ttp not in seen:
                            seen.add(ttp)
                            ttps.append({
                                "technique_id": ttp,
                                "name": f"Technique {ttp}",
                                "description": f"Detected via technology: {tech}",
                                "likelihood": "Medium"
                            })
        return ttps

    @staticmethod
    def enrich_scan_with_mitre(scan_result: dict) -> dict:
        """Главный метод обогащения"""
        open_ports = scan_result.get("network", {}).get("open_ports", [])
        technologies = scan_result.get("summary", {}).get("detected_technologies", [])

        ttp_from_ports = MitreService.get_ttp_from_ports(open_ports)
        ttp_from_tech = MitreService.get_ttp_from_technologies(technologies)

        all_ttps = ttp_from_ports + ttp_from_tech

        # Добавляем в scan_result
        scan_result["mitre"] = {
            "ttps": all_ttps,
            "count": len(all_ttps),
            "high_risk_ttps": [t for t in all_ttps if t["likelihood"] == "High"]
        }

        # Обогащаем proactive
        if "proactive" not in scan_result:
            scan_result["proactive"] = {}
        
        scan_result["proactive"]["ttp_predictions"] = all_ttps[:8]  # топ-8

        logger.info(f"MITRE ATT&CK enriched: {len(all_ttps)} techniques found")
        return scan_result
# backend/app/graph_service.py
import networkx as nx
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class AttackGraphService:
    def __init__(self):
        self.G = nx.DiGraph()
        self.build_base_graph()

    def build_base_graph(self):
        """Базовый граф знаний атак"""
        edges = [
            ("Initial Access", "Execution"),
            ("Execution", "Persistence"),
            ("Initial Access", "Lateral Movement"),
            ("Lateral Movement", "Privilege Escalation"),
            ("Privilege Escalation", "Defense Evasion"),
            ("Credential Access", "Lateral Movement"),
        ]
        for src, dst in edges:
            self.G.add_edge(src, dst, weight=1)

    def predict_attack_paths(self, scan_result: Dict) -> List[Dict]:
        open_ports = scan_result.get("network", {}).get("open_ports", [])
        mitre_ttps = [t["technique_id"] for t in scan_result.get("mitre", {}).get("ttps", [])]
        findings = [f["title"] for f in scan_result.get("findings", [])]

        paths = []

        # 1. Web Attack Path
        if any(p in [80, 443, 8080] for p in open_ports):
            paths.append({
                "name": "Web Server Compromise",
                "description": "Exploit public-facing application → code execution → internal pivot",
                "ttp_chain": ["T1190", "T1059", "T1021"],
                "likelihood": "High",
                "recommendation": "Prioritize web vuln scanning (SQLi, RCE, SSRF)"
            })

        # 2. Remote Service Attack
        if 3389 in open_ports or 445 in open_ports:
            paths.append({
                "name": "Remote Service Exploitation",
                "description": "Brute-force or exploit RDP/SMB → privilege escalation",
                "ttp_chain": ["T1110", "T1021", "T1068"],
                "likelihood": "High",
                "recommendation": "Check for weak credentials and outdated services"
            })

        # 3. Generic MITRE-based path
        if mitre_ttps:
            paths.append({
                "name": "Multi-Stage TTP Chain",
                "description": "Attack using detected MITRE techniques",
                "ttp_chain": mitre_ttps[:5],
                "likelihood": "Medium",
                "recommendation": "Use ATT&CK Navigator to map full kill chain"
            })

        # Сортируем по likelihood
        likelihood_order = {"High": 3, "Medium": 2, "Low": 1}
        paths.sort(key=lambda x: likelihood_order.get(x["likelihood"], 0), reverse=True)

        return paths[:4]


# Singleton
attack_graph = AttackGraphService()
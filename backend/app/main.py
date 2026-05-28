from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime

from app.scanner import start_recon_scan
from app.ml_service import ml_risk_service
from app.mitre_service import MitreService
from app.llm_service import (
    generate_attack_paths_with_llm,
    generate_full_report,
    generate_intelligent_findings,
)
from app.cve_service import get_cve_data, summarize_cve_risk

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ThreatScope", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str


@app.post("/api/scans/start")
async def start_scan(request: ScanRequest):
    target = request.target.strip()
    logger.info(f"Starting scan for: {target}")

    try:
        scan_result = start_recon_scan(target)

        # ML Risk
        ml_result = ml_risk_service.predict_risk(scan_result)
        scan_result["ml_risk"] = ml_result
        scan_result["risk_score"] = ml_result["risk_score"]
        scan_result["risk_level"] = ml_result["risk_level"]

        # MITRE
        scan_result = MitreService.enrich_scan_with_mitre(scan_result)

        # LLM Findings
        scan_result["findings"] = generate_intelligent_findings(scan_result)

        # CVE — берём технологии из заголовков сервера
        technologies = []
        server = scan_result.get("web", {}).get("server", "")
        x_powered_by = scan_result.get("web", {}).get("x_powered_by", "")
        if server and server != "Unknown":
            technologies.append(server)
        if x_powered_by and x_powered_by != "Unknown":
            technologies.append(x_powered_by)

        if technologies:
            cve_data = get_cve_data(technologies)
            scan_result["cve"] = {
                "vulnerabilities": cve_data,
                "summary": summarize_cve_risk(cve_data),
            }
            logger.info(f"CVE: найдено {len(cve_data)} уязвимостей")
        else:
            scan_result["cve"] = {"vulnerabilities": [], "summary": {"total": 0}}

        # Attack Paths
        scan_result.setdefault("proactive", {})
        scan_result["proactive"]["attack_paths"] = generate_attack_paths_with_llm(scan_result)

        scan_result["scanned_at"] = datetime.now().isoformat()

        logger.info(f"Scan completed | Risk: {scan_result['risk_level']}")
        return scan_result

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(500, detail=str(e))


@app.post("/api/report")
async def generate_ai_report(data: dict):
    try:
        report = generate_full_report(data.get("scan_result", {}))
        return {"report": report}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

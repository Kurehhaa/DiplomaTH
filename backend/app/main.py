# backend/app/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime

from app.scanner import start_recon_scan
from app.ml_service import predict_risk
from app.mitre_service import MitreService
from app.graph_service import attack_graph
from app.llm_service import (
    generate_attack_paths_with_llm,
    generate_full_report,
    generate_intelligent_findings   # ← добавили
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ThreatScope", version="1.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class ScanRequest(BaseModel):
    target: str


@app.post("/api/scans/start")
async def start_scan(request: ScanRequest):
    target = request.target.strip()
    logger.info(f"Starting scan for: {target}")

    try:
        scan_result = start_recon_scan(target)

        # ML Risk
        ml_result = predict_risk(scan_result)
        scan_result["ml_risk"] = ml_result
        scan_result["risk_score"] = ml_result["risk_score"]
        scan_result["risk_level"] = ml_result["risk_level"]

        # MITRE
        scan_result = MitreService.enrich_scan_with_mitre(scan_result)

        # LLM Findings (самое важное)
        scan_result["findings"] = generate_intelligent_findings(scan_result)

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
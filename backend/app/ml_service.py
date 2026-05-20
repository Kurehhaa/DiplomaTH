# backend/app/ml_service.py
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
import logging
from datetime import datetime
import xgboost as xgb
import shap
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "models/risk_model.pkl"
DATA_PATH = Path(__file__).parent.parent / "data/cicids2017_cleaned.csv"

MODEL_PATH.parent.mkdir(exist_ok=True)

model = None
feature_names = None
explainer = None


def load_model():
    global model, feature_names, explainer
    try:
        if MODEL_PATH.exists():
            data = joblib.load(MODEL_PATH)
            model = data["model"]
            feature_names = data["feature_names"]
            logger.info(f"✅ XGBoost модель загружена (Accuracy: {data.get('accuracy', 'N/A')})")
            
            explainer = shap.TreeExplainer(model)
            logger.info("✅ SHAP explainer создан")
    except Exception as e:
        logger.error(f"Ошибка загрузки модели: {e}")


load_model()


def extract_features(scan_data: dict) -> dict:
    ports = scan_data.get("network", {}).get("open_ports", [])
    web = scan_data.get("web", {})
    ssl = scan_data.get("ssl", {})
    findings = scan_data.get("findings", [])

    return {
        "port_count": len(ports),
        "high_risk_port_count": sum(1 for p in ports if p in [21,22,23,445,3389,3306,5432,5900]),
        "has_ssh": int(22 in ports),
        "has_rdp": int(3389 in ports),
        "has_smb": int(445 in ports),
        "has_db": int(any(p in [3306,5432,1433,27017] for p in ports)),
        "has_web": int(any(p in [80,443,8080,8443] for p in ports)),
        "subdomain_count": len(scan_data.get("subdomains", [])),
        "server_fingerprint": int(web.get("server", "Unknown") != "Unknown"),
        "x_powered_by": int(web.get("x_powered_by", "Unknown") != "Unknown"),
        "ssl_invalid": int(not ssl.get("valid", True)),
        "ssl_expires_soon": int(ssl.get("expires_in_days", 999) <= 45),
        "finding_count": len(findings),
        "high_severity_findings": sum(1 for f in findings if f.get("severity") in ["High", "Critical"]),
    }


def predict_risk(scan_data: dict) -> dict:
    features = extract_features(scan_data)

    if model is None:
        score = min(4.0 + features["high_risk_port_count"]*1.7 + features["high_severity_findings"]*2.0, 10.0)
        level = "Critical" if score >= 8.5 else "High" if score >= 6.5 else "Medium" if score >= 4 else "Low"
        return {"risk_score": round(score, 1), "risk_level": level, "model_used": "fallback"}

    try:
        X = np.array([[features.get(f, 0) for f in feature_names]])
        pred_class = model.predict(X)[0]
        proba = model.predict_proba(X).max()

        risk_score = round(float(proba * 10), 1)

        if risk_score >= 8.5:
            risk_level = "Critical"
        elif risk_score >= 6.5:
            risk_level = "High"
        elif risk_score >= 4.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # SHAP explanation
        shap_values = None
        top_contributors = []
        if explainer is not None:
            try:
                shap_vals = explainer.shap_values(X)[0][0]
                shap_values = shap_vals.tolist()
                
                # Топ-5 факторов, влияющих на решение
                feature_impact = list(zip(feature_names, shap_vals))
                top_contributors = sorted(feature_impact, key=lambda x: abs(x[1]), reverse=True)[:5]
            except:
                pass

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "model_used": "xgboost_cicids2017",
            "features": features,
            "shap_values": shap_values,
            "top_contributors": [{"feature": f, "impact": round(float(i), 4)} for f, i in top_contributors]
        }
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return {"risk_score": 6.0, "risk_level": "Medium", "model_used": "error"}

def train_model():
    logger.info("Training function available if needed.")
    return None


if __name__ == "__main__":
    train_model()
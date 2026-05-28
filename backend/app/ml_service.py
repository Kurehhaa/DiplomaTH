# backend/app/ml_service.py
import joblib
import shap
import pandas as pd
from pathlib import Path
import logging

from app.feature_service import extract_features

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "models" / "risk_model.pkl"

LABEL_MAP = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}


class MLRiskService:
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.explainer = None
        self._load_model()

    def _load_model(self):
        try:
            if MODEL_PATH.exists():
                data = joblib.load(MODEL_PATH)
                self.model = data["model"]
                self.feature_names = data["feature_names"]
                self.explainer = shap.TreeExplainer(self.model)
                logger.info(f"✅ ML модель загружена (Accuracy: {data.get('accuracy', 'N/A')})")
            else:
                logger.warning("⚠️ Файл модели не найден. Используется fallback.")
        except Exception as e:
            logger.error(f"❌ Ошибка загрузки модели: {e}")

    def predict_risk(self, scan_result: dict) -> dict:
        if self.model is None:
            return self._fallback_prediction(scan_result)

        try:
            # Извлекаем реальные фичи из результата сканирования
            raw = extract_features(
                ip=scan_result.get("network", {}).get("ip_address"),
                open_ports=scan_result.get("network", {}).get("open_ports", []),
                http_metadata=scan_result.get("web", {}),
                ssl_info=scan_result.get("ssl", {}),
                subdomains=scan_result.get("subdomains", []),
                findings=scan_result.get("findings", []),
            )

            X = pd.DataFrame([raw])[self.feature_names]

            # Предсказание класса и вероятностей
            pred_class = int(self.model.predict(X)[0])
            probas = self.model.predict_proba(X)[0]

            # Risk score: взвешенная сумма вероятностей (0..10)
            risk_score = round(
                (probas[1] * 3.5 + probas[2] * 7.0 + probas[3] * 10.0), 2
            )
            risk_score = min(risk_score, 10.0)

            # SHAP объяснение
            shap_values = self.explainer.shap_values(X)
            # Берём SHAP для предсказанного класса
            if isinstance(shap_values, list):
                class_shap = shap_values[pred_class][0]
            else:
                class_shap = shap_values[0]

            shap_dict = {
                name: round(float(val), 4)
                for name, val in zip(self.feature_names, class_shap)
            }
            # Топ-8 признаков по абсолютному значению SHAP
            top_shap = dict(
                sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:8]
            )

            return {
                "risk_score": risk_score,
                "risk_level": LABEL_MAP.get(pred_class, "Medium"),
                "model_used": "XGBoost",
                "probabilities": {
                    "Low": round(float(probas[0]), 3),
                    "Medium": round(float(probas[1]), 3),
                    "High": round(float(probas[2]), 3),
                    "Critical": round(float(probas[3]), 3),
                },
                "features": top_shap,  # настоящие SHAP-значения
            }

        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return self._fallback_prediction(scan_result)

    def _fallback_prediction(self, scan_result: dict) -> dict:
        """Используется только если модель не загрузилась"""
        open_ports = scan_result.get("network", {}).get("open_ports", [])
        critical_ports = [p for p in open_ports if p in [445, 3389, 3306]]
        high_ports = [p for p in open_ports if p in [21, 22, 25, 8080]]

        score = 2.0 + len(open_ports) * 0.4
        if critical_ports:
            score += len(critical_ports) * 2.0
        if high_ports:
            score += len(high_ports) * 1.2
        score = min(round(score, 2), 9.5)

        if score >= 8.0:
            level = "Critical"
        elif score >= 6.0:
            level = "High"
        elif score >= 3.5:
            level = "Medium"
        else:
            level = "Low"

        return {
            "risk_score": score,
            "risk_level": level,
            "model_used": "fallback",
            "features": {},
        }


# Singleton
ml_risk_service = MLRiskService()

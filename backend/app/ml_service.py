# backend/app/ml_service.py
import joblib
import pandas as pd
from pathlib import Path
import numpy as np

MODEL_PATH = Path(__file__).parent / "models" / "risk_model.pkl"

class MLRiskService:
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.load_model()

    def load_model(self):
        """Загружает обученную XGBoost модель"""
        try:
            if MODEL_PATH.exists():
                data = joblib.load(MODEL_PATH)
                self.model = data["model"]
                self.feature_names = data["feature_names"]
                print(f"✅ XGBoost модель загружена (Accuracy: {data.get('accuracy', 'N/A')})")
            else:
                print("⚠️ Модель не найдена. Используем fallback.")
        except Exception as e:
            print(f"❌ Ошибка загрузки модели: {e}")

    def extract_features_for_ml(self, scan_result: dict) -> dict:
        """Преобразует результат сканирования в фичи для модели"""
        features = {
            'Destination Port': 80,  # по умолчанию
            'Flow Duration': 100000,
            'Total Fwd Packets': 10,
            'Total Length of Fwd Packets': 1000,
            'Fwd Packet Length Max': 100,
            'Fwd Packet Length Min': 40,
            # ... добавим важные
            'Flow Bytes/s': 5000,
            'Flow Packets/s': 100,
            'FIN Flag Count': 0,
            'PSH Flag Count': 1,
            'ACK Flag Count': 1,
            'Average Packet Size': 100,
            'Init_Win_bytes_forward': 65535,
        }

        # Заполняем реальными данными из скана
        open_ports = scan_result.get("network", {}).get("open_ports", [])
        if open_ports:
            features['Destination Port'] = open_ports[0]

        # Добавляем больше фич из твоего feature_service
        fs = scan_result.get("ml_risk", {}).get("features", {})
        if fs:
            features.update({
                'Flow Duration': fs.get('port_count', 5) * 10000,
                'Total Fwd Packets': fs.get('port_count', 5) * 2,
            })

        # Создаём DataFrame с нужными колонками
        df = pd.DataFrame([features])
        # Добавляем отсутствующие колонки с нулями
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0

        return df[self.feature_names]

    def predict_risk(self, scan_result: dict):
        """Основная функция предсказания риска"""
        if self.model is None:
            return self._fallback_prediction(scan_result)

        try:
            X = self.extract_features_for_ml(scan_result)
            risk_score = self.model.predict_proba(X)[0][1]  # вероятность атаки
            risk_score = round(float(risk_score) * 10, 2)  # от 0 до 10

            if risk_score >= 8.0:
                risk_level = "Critical"
            elif risk_score >= 6.0:
                risk_level = "High"
            elif risk_score >= 3.5:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            return {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "model_used": "XGBoost"
            }
        except Exception as e:
            print(f"ML Prediction error: {e}")
            return self._fallback_prediction(scan_result)

    def _fallback_prediction(self, scan_result):
        """Fallback если модель не загрузилась"""
        open_ports = len(scan_result.get("network", {}).get("open_ports", []))
        high_risk_ports = any(p in [21, 22, 445, 3389, 3306, 8080] 
                            for p in scan_result.get("network", {}).get("open_ports", []))
        
        score = min(9.5, 2.5 + open_ports * 0.4 + (3 if high_risk_ports else 0))
        
        return {
            "risk_score": round(score, 2),
            "risk_level": "High" if score >= 7 else "Medium",
            "model_used": "fallback"
        }


# Singleton
ml_risk_service = MLRiskService()
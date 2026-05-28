# backend/app/ml_train.py
"""
Обучение XGBoost модели на признаках, получаемых из результатов сканирования.

Признаки полностью совместимы с feature_service.py — то, что видит модель
при обучении, совпадает с тем, что она получает при инференсе.

Датасет: синтетический, основан на правилах безопасности (CIS, NIST).
"""

import random
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from pathlib import Path

MODEL_PATH = Path(__file__).parent / "models" / "risk_model.pkl"

FEATURE_NAMES = [
    "has_ip", "port_count",
    "has_21", "has_22", "has_25", "has_53", "has_80", "has_443",
    "has_445", "has_3306", "has_3389", "has_8080",
    "has_http", "status_ok", "has_server_fingerprint", "has_x_powered_by",
    "has_hsts", "has_csp", "has_x_frame_options", "has_x_content_type_options",
    "ssl_enabled", "ssl_valid", "ssl_expires_soon",
    "subdomain_count", "finding_count",
    "critical_findings", "high_findings", "medium_findings",
]

LABEL_MAP = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _sample(risk_level: str) -> dict:
    """Генерирует один синтетический пример для заданного уровня риска."""
    r = {}

    if risk_level == "Low":
        r["has_ip"] = 1
        r["port_count"] = random.randint(1, 2)
        r["has_21"] = 0; r["has_22"] = 0; r["has_25"] = 0
        r["has_53"] = random.randint(0, 1)
        r["has_80"] = random.randint(0, 1); r["has_443"] = random.randint(0, 1)
        r["has_445"] = 0; r["has_3306"] = 0; r["has_3389"] = 0; r["has_8080"] = 0
        r["has_http"] = int(bool(r["has_80"] or r["has_443"]))
        r["status_ok"] = r["has_http"]
        r["has_server_fingerprint"] = 0; r["has_x_powered_by"] = 0
        r["has_hsts"] = random.randint(0, 1); r["has_csp"] = random.randint(0, 1)
        r["has_x_frame_options"] = random.randint(0, 1)
        r["has_x_content_type_options"] = random.randint(0, 1)
        r["ssl_enabled"] = r["has_443"]; r["ssl_valid"] = r["ssl_enabled"]
        r["ssl_expires_soon"] = 0
        r["subdomain_count"] = random.randint(0, 3)
        r["finding_count"] = random.randint(0, 2)
        r["critical_findings"] = 0; r["high_findings"] = 0
        r["medium_findings"] = random.randint(0, 1)

    elif risk_level == "Medium":
        r["has_ip"] = 1
        r["port_count"] = random.randint(2, 5)
        r["has_21"] = 0; r["has_22"] = random.randint(0, 1)
        r["has_25"] = random.randint(0, 1); r["has_53"] = random.randint(0, 1)
        r["has_80"] = 1; r["has_443"] = random.randint(0, 1)
        r["has_445"] = 0; r["has_3306"] = 0; r["has_3389"] = 0
        r["has_8080"] = random.randint(0, 1)
        r["has_http"] = 1; r["status_ok"] = 1
        r["has_server_fingerprint"] = random.randint(0, 1)
        r["has_x_powered_by"] = random.randint(0, 1)
        r["has_hsts"] = random.randint(0, 1); r["has_csp"] = 0
        r["has_x_frame_options"] = 0
        r["has_x_content_type_options"] = random.randint(0, 1)
        r["ssl_enabled"] = r["has_443"]; r["ssl_valid"] = r["ssl_enabled"]
        r["ssl_expires_soon"] = random.randint(0, 1)
        r["subdomain_count"] = random.randint(2, 10)
        r["finding_count"] = random.randint(2, 5)
        r["critical_findings"] = 0; r["high_findings"] = random.randint(0, 1)
        r["medium_findings"] = random.randint(1, 3)

    elif risk_level == "High":
        r["has_ip"] = 1
        r["port_count"] = random.randint(4, 10)
        r["has_21"] = random.randint(0, 1); r["has_22"] = 1
        r["has_25"] = random.randint(0, 1); r["has_53"] = random.randint(0, 1)
        r["has_80"] = 1; r["has_443"] = random.randint(0, 1)
        r["has_445"] = random.randint(0, 1); r["has_3306"] = random.randint(0, 1)
        r["has_3389"] = 0; r["has_8080"] = 1
        r["has_http"] = 1; r["status_ok"] = 1
        r["has_server_fingerprint"] = 1; r["has_x_powered_by"] = random.randint(0, 1)
        r["has_hsts"] = 0; r["has_csp"] = 0
        r["has_x_frame_options"] = 0; r["has_x_content_type_options"] = 0
        r["ssl_enabled"] = r["has_443"]
        r["ssl_valid"] = random.randint(0, 1)
        r["ssl_expires_soon"] = random.randint(0, 1)
        r["subdomain_count"] = random.randint(5, 20)
        r["finding_count"] = random.randint(4, 8)
        r["critical_findings"] = 0; r["high_findings"] = random.randint(1, 3)
        r["medium_findings"] = random.randint(2, 4)

    else:  # Critical
        r["has_ip"] = 1
        r["port_count"] = random.randint(6, 15)
        r["has_21"] = random.randint(0, 1); r["has_22"] = 1
        r["has_25"] = random.randint(0, 1); r["has_53"] = random.randint(0, 1)
        r["has_80"] = 1; r["has_443"] = random.randint(0, 1)
        r["has_445"] = random.randint(0, 1); r["has_3306"] = random.randint(0, 1)
        r["has_3389"] = 1; r["has_8080"] = random.randint(0, 1)
        r["has_http"] = 1; r["status_ok"] = 1
        r["has_server_fingerprint"] = 1; r["has_x_powered_by"] = 1
        r["has_hsts"] = 0; r["has_csp"] = 0
        r["has_x_frame_options"] = 0; r["has_x_content_type_options"] = 0
        r["ssl_enabled"] = r["has_443"]; r["ssl_valid"] = 0
        r["ssl_expires_soon"] = random.randint(0, 1)
        r["subdomain_count"] = random.randint(10, 40)
        r["finding_count"] = random.randint(6, 12)
        r["critical_findings"] = random.randint(1, 3)
        r["high_findings"] = random.randint(2, 5)
        r["medium_findings"] = random.randint(2, 5)

    return r


def train():
    random.seed(42)
    np.random.seed(42)

    print("🚀 Генерация обучающего датасета...")
    samples, labels = [], []

    for level, n in [("Low", 600), ("Medium", 600), ("High", 600), ("Critical", 600)]:
        for _ in range(n):
            samples.append(_sample(level))
            labels.append(LABEL_MAP[level])

    df = pd.DataFrame(samples, columns=FEATURE_NAMES)
    y = pd.Series(labels)
    print(f"✅ Датасет: {df.shape[0]} примеров, {df.shape[1]} признаков")
    print(f"   Классы: {y.value_counts().to_dict()}")

    X_train, X_test, y_train, y_test = train_test_split(
        df, y, test_size=0.2, random_state=42, stratify=y
    )

    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="mlogloss",
    )
    print("\nОбучение XGBoost...")
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    acc = accuracy_score(y_test, pred)

    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТЫ:")
    print(classification_report(y_test, pred, target_names=["Low", "Medium", "High", "Critical"]))
    print(f"Accuracy: {acc:.4f}")
    print("=" * 60)

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump({
        "model": model,
        "feature_names": FEATURE_NAMES,
        "label_map": {v: k for k, v in LABEL_MAP.items()},
        "accuracy": acc,
    }, MODEL_PATH)

    print(f"\n✅ Модель сохранена: {MODEL_PATH}")


if __name__ == "__main__":
    train()

# backend/app/ml_train.py
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from pathlib import Path

DATA_PATH = Path(__file__).parent.parent / "data" / "cicids2017_cleaned.csv"
MODEL_PATH = Path(__file__).parent / "models" / "risk_model.pkl"

def train_xgboost():
    print("🚀 Загрузка датасета CICIDS2017...")
    
    df = pd.read_csv(DATA_PATH)
    print(f"✅ Датасет загружен. Размер: {df.shape}")
    
    target_col = "Attack Type"
    
    print(f"Целевая колонка: '{target_col}'")
    print(f"Классы: {df[target_col].unique()}")
    
    # Преобразуем в binary: Normal Traffic = 0, Attack = 1 (для risk prediction)
    df['risk_label'] = df[target_col].apply(lambda x: 0 if x == 'Normal Traffic' else 1)
    
    X = df.drop(columns=[target_col, 'risk_label'])
    y = df['risk_label']
    
    print(f"Задача: Binary Classification (Normal vs Attack)")
    print(f"Распределение классов:\n{y.value_counts()}")
    
    # Разделение
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # XGBoost модель
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='logloss',
        use_label_encoder=False
    )
    
    print("\nОбучение XGBoost модели...")
    model.fit(X_train, y_train)
    
    # Оценка
    pred = model.predict(X_test)
    print("\n" + "="*70)
    print("РЕЗУЛЬТАТЫ МОДЕЛИ:")
    print(classification_report(y_test, pred))
    print(f"Accuracy: {accuracy_score(y_test, pred):.4f}")
    print("="*70)
    
    # Сохранение модели
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump({
        "model": model,
        "feature_names": X.columns.tolist(),
        "target_column": target_col,
        "is_binary": True,
        "accuracy": accuracy_score(y_test, pred)
    }, MODEL_PATH)
    
    print(f"\n✅ XGBoost модель успешно сохранена в: {MODEL_PATH}")

if __name__ == "__main__":
    train_xgboost()
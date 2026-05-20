import random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib


def generate_data(n=500):
    data = []

    for _ in range(n):
        port_count = random.randint(0, 10)
        has_22 = random.randint(0, 1)
        has_3389 = random.randint(0, 1)
        has_3306 = random.randint(0, 1)
        has_https = random.randint(0, 1)
        has_server = random.randint(0, 1)
        finding_count = random.randint(0, 8)

        score = (
            port_count
            + has_22 * 3
            + has_3389 * 4
            + has_3306 * 4
            + (0 if has_https else 2)
            + has_server
            + finding_count
        )

        if score > 12:
            label = "High"
        elif score > 6:
            label = "Medium"
        else:
            label = "Low"

        data.append([
            port_count,
            has_22,
            has_3389,
            has_3306,
            has_https,
            has_server,
            finding_count,
            label
        ])

    df = pd.DataFrame(data, columns=[
        "port_count",
        "has_22",
        "has_3389",
        "has_3306",
        "has_https",
        "has_server",
        "finding_count",
        "label"
    ])

    return df


def train():
    df = generate_data()

    X = df.drop("label", axis=1)
    y = df["label"]

    model = RandomForestClassifier()
    model.fit(X, y)

    joblib.dump(model, "risk_model.pkl")

    print("Model trained and saved")


if __name__ == "__main__":
    train()
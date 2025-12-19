from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

@dataclass
class IFModel:
    model: IsolationForest
    feature_order: List[str]

def train_isolation_forest(rows: List[Dict[str, float]], feature_order: List[str], contamination: float) -> IFModel:
    X = np.array([[r.get(f, 0.0) for f in feature_order] for r in rows], dtype=float)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    return IFModel(model=model, feature_order=feature_order)

def score_isolation_forest(ifm: IFModel, row: Dict[str, float]) -> float:
    X = np.array([[row.get(f, 0.0) for f in ifm.feature_order]], dtype=float)
    normality = float(ifm.model.decision_function(X)[0])
    return -normality

def save_if_model(path: Path, ifm: IFModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": ifm.model, "feature_order": ifm.feature_order}, path)

def load_if_model(path: Path) -> IFModel:
    obj = joblib.load(path)
    return IFModel(model=obj["model"], feature_order=obj["feature_order"])
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import os
import joblib
import numpy as np

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

logger = logging.getLogger(__name__)

class ModelPipeline(ABC):
    """Abstract base class for all ML Models in the pipeline."""
    
    @abstractmethod
    def fit(self, X: Any, y: Optional[Any] = None) -> None:
        pass
        
    @abstractmethod
    def predict(self, X: Any) -> Any:
        pass
        
    def save(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        
    @classmethod
    def load(cls, filepath: str) -> 'ModelPipeline':
        return joblib.load(filepath)


class AnomalyDetector(ModelPipeline):
    """Uses Isolation Forest to detect anomalous behavior vectors."""
    def __init__(self):
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.model = IsolationForest(contamination=0.05, random_state=42) if HAS_SKLEARN else None
        self._is_fitted = False

    def fit(self, X: Any, y: Optional[Any] = None) -> None:
        if not HAS_SKLEARN or len(X) == 0:
            return
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._is_fitted = True

    def predict(self, X: Any) -> List[int]:
        
        if not self._is_fitted or not HAS_SKLEARN or len(X) == 0:
            return [0] * len(X)
        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)
        
        return [1 if p == -1 else 0 for p in preds]


class ThreatClassifier(ModelPipeline):
    
    def __init__(self):
       
        self.model = RandomForestClassifier(n_estimators=100, random_state=42) if HAS_SKLEARN else None
        self._is_fitted = False

    def fit(self, X: Any, y: Any) -> None:
        if not HAS_SKLEARN or len(X) == 0:
            return
        self.model.fit(X, y)
        self._is_fitted = True

    def predict(self, X: Any) -> List[str]:
        if not self._is_fitted or not HAS_SKLEARN or len(X) == 0:
            return ["benign"] * len(X)
        return self.model.predict(X)
        
    def predict_proba(self, X: Any) -> List[float]:
        
        if not self._is_fitted or not HAS_SKLEARN or len(X) == 0:
            return [0.0] * len(X)
        probs = self.model.predict_proba(X)
        return [float(max(p)) for p in probs]



class DeepLearningSequenceModel(ModelPipeline):
    
    def __init__(self):
        logger.warning("DeepLearningSequenceModel is a placeholder and requires deep learning weights.")
        
    def fit(self, X: Any, y: Optional[Any] = None) -> None:
        pass
        
    def predict(self, X: Any) -> Any:
        return ["benign"] * len(X)

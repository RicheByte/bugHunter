#!/usr/bin/env python3
"""
ML Vulnerability Predictor for BugHunter Pro
Uses RandomForest classifier for vulnerability scoring and pattern recognition
"""

import logging
import pickle
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ML imports (optional)
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML libraries not available. Install: pip install numpy scikit-learn joblib")


@dataclass
class VulnerabilityPrediction:
    """Vulnerability prediction result"""
    is_vulnerable: bool
    confidence: float
    vulnerability_type: str
    features: Dict[str, Any]


class MLVulnPredictor:
    """ML-based vulnerability prediction"""
    
    def __init__(self, model_path: str = "models/vuln_classifier.pkl"):
        """
        Initialize ML predictor
        
        Args:
            model_path: Path to saved model
        """
        self.model_path = Path(model_path)
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        
        if ML_AVAILABLE:
            self._load_or_create_model()
        else:
            logger.warning("ML not available - using rule-based fallback")
    
    def _load_or_create_model(self):
        """Load existing model or create new one"""
        if self.model_path.exists():
            try:
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.scaler = data['scaler']
                logger.info(f"Loaded ML model from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}, creating new one")
                self._create_default_model()
        else:
            self._create_default_model()
    
    def _create_default_model(self):
        """Create and train default model"""
        if not ML_AVAILABLE:
            return
        
        logger.info("Creating default ML model...")
        
        # Create model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.scaler = StandardScaler()
        
        # Train with synthetic data
        X_train, y_train = self._generate_training_data()
        
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled, y_train)
        
        logger.info("Default model trained")
        self.save_model()
    
    def _generate_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data"""
        # Features: [response_length, error_markers, special_chars, time_diff, status_code]
        
        # Vulnerable patterns
        vulnerable = np.array([
            [5000, 3, 15, 2.5, 200],  # SQL error in response
            [3000, 2, 20, 3.0, 500],  # Server error
            [8000, 5, 25, 1.5, 200],  # XSS reflection
            [2000, 1, 30, 5.0, 200],  # Time-based SQLi
            [4000, 4, 18, 2.0, 200],  # XXE response
        ] * 20)
        
        # Non-vulnerable patterns
        not_vulnerable = np.array([
            [1000, 0, 5, 0.5, 200],   # Normal response
            [800, 0, 3, 0.3, 200],    # Clean response
            [1200, 0, 6, 0.4, 404],   # Not found
            [900, 0, 4, 0.6, 403],    # Forbidden
            [1100, 0, 5, 0.5, 301],   # Redirect
        ] * 20)
        
        X = np.vstack([vulnerable, not_vulnerable])
        y = np.array([1] * len(vulnerable) + [0] * len(not_vulnerable))
        
        # Add noise
        X += np.random.normal(0, 100, X.shape)
        
        return X, y
    
    def extract_features(self, response: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from HTTP response
        
        Args:
            response: Response dictionary with keys: text, status, elapsed, headers
        
        Returns:
            Feature vector
        """
        text = response.get('text', '')
        status = response.get('status', 200)
        elapsed = response.get('elapsed', 0)
        
        # Error markers
        error_markers = sum([
            text.lower().count('error'),
            text.lower().count('warning'),
            text.lower().count('exception'),
            text.lower().count('sql'),
            text.lower().count('mysql'),
            text.lower().count('postgresql'),
            text.lower().count('oracle'),
        ])
        
        # Special characters
        special_chars = sum(c in text for c in ['<', '>', '"', "'", '\\', '`', '{', '}'])
        
        features = np.array([
            len(text),          # Response length
            error_markers,      # Error markers count
            special_chars,      # Special chars count
            elapsed,            # Response time
            status,             # Status code
        ])
        
        return features.reshape(1, -1)
    
    def predict(
        self,
        baseline_response: Dict[str, Any],
        test_response: Dict[str, Any]
    ) -> VulnerabilityPrediction:
        """
        Predict vulnerability based on response differences
        
        Args:
            baseline_response: Normal response
            test_response: Response with payload
        
        Returns:
            VulnerabilityPrediction
        """
        if not ML_AVAILABLE or self.model is None:
            return self._rule_based_prediction(baseline_response, test_response)
        
        try:
            # Extract features
            features = self.extract_features(test_response)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            confidence = probabilities[1] if prediction == 1 else probabilities[0]
            
            return VulnerabilityPrediction(
                is_vulnerable=bool(prediction),
                confidence=float(confidence),
                vulnerability_type=self._classify_vuln_type(test_response),
                features={
                    'response_length': len(test_response.get('text', '')),
                    'status_code': test_response.get('status', 0),
                    'elapsed': test_response.get('elapsed', 0)
                }
            )
        
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return self._rule_based_prediction(baseline_response, test_response)
    
    def _rule_based_prediction(
        self,
        baseline_response: Dict[str, Any],
        test_response: Dict[str, Any]
    ) -> VulnerabilityPrediction:
        """Fallback rule-based prediction"""
        test_text = test_response.get('text', '').lower()
        baseline_text = baseline_response.get('text', '').lower()
        
        # Check for error indicators
        error_indicators = ['error', 'exception', 'warning', 'sql', 'syntax']
        error_count = sum(test_text.count(indicator) for indicator in error_indicators)
        
        # Time-based detection
        time_diff = abs(test_response.get('elapsed', 0) - baseline_response.get('elapsed', 0))
        
        # Length difference
        length_diff = abs(len(test_text) - len(baseline_text))
        
        is_vulnerable = (
            error_count > 2 or
            time_diff > 3.0 or
            length_diff > 1000
        )
        
        confidence = min(
            (error_count * 0.2 + (time_diff / 10) + (length_diff / 2000)),
            1.0
        )
        
        return VulnerabilityPrediction(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            vulnerability_type=self._classify_vuln_type(test_response),
            features={
                'error_count': error_count,
                'time_diff': time_diff,
                'length_diff': length_diff
            }
        )
    
    def _classify_vuln_type(self, response: Dict[str, Any]) -> str:
        """Classify vulnerability type from response"""
        text = response.get('text', '').lower()
        
        if any(word in text for word in ['sql', 'mysql', 'postgresql', 'syntax']):
            return 'SQL Injection'
        elif any(word in text for word in ['<script', 'alert(', 'onerror=']):
            return 'XSS'
        elif any(word in text for word in ['xml', 'entity', 'doctype']):
            return 'XXE'
        elif response.get('elapsed', 0) > 5.0:
            return 'Time-based'
        else:
            return 'Unknown'
    
    def save_model(self):
        """Save model to disk"""
        if not ML_AVAILABLE or self.model is None:
            return
        
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                'model': self.model,
                'scaler': self.scaler
            }
            
            joblib.dump(data, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
        
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Train model with custom data
        
        Args:
            X: Feature matrix
            y: Labels (0 = not vulnerable, 1 = vulnerable)
        
        Returns:
            Training metrics
        """
        if not ML_AVAILABLE:
            logger.error("ML libraries not available")
            return {}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0)
        }
        
        logger.info(f"Model trained - Accuracy: {metrics['accuracy']:.2%}")
        
        self.save_model()
        return metrics


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n" + "="*70)
    print("ML Vulnerability Predictor Demo")
    print("="*70)
    
    predictor = MLVulnPredictor()
    
    # Simulate responses
    baseline = {
        'text': 'Welcome to the site',
        'status': 200,
        'elapsed': 0.5
    }
    
    vulnerable = {
        'text': 'MySQL error: syntax error near line 1',
        'status': 200,
        'elapsed': 0.8
    }
    
    print("\n🔍 Testing vulnerability prediction...")
    prediction = predictor.predict(baseline, vulnerable)
    
    print(f"\nPrediction:")
    print(f"  Vulnerable: {prediction.is_vulnerable}")
    print(f"  Confidence: {prediction.confidence:.2%}")
    print(f"  Type: {prediction.vulnerability_type}")
    print(f"  Features: {prediction.features}")

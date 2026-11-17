"""
Anomaly Detection Engine
Statistical and ML-based anomaly detection for logs and metrics
"""
import asyncio
import numpy as np
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from collections.abc import Iterable
import statistics
import math

logger = logging.getLogger(__name__)


@dataclass
class AnomalyAlert:
    alert_id: str
    timestamp: datetime
    severity: str
    category: str
    metric_name: str
    expected_value: float
    actual_value: float
    deviation: float
    method: str
    details: Dict = field(default_factory=dict)
    context: Dict = field(default_factory=dict)


class StatisticalAnomalyDetector:
    """
    Statistical anomaly detection using multiple methods
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.window_size = config.get("window_size", 1000)
        self.sensitivity = config.get("sensitivity", 3.0)  # Z-score threshold
        self.min_samples = config.get("min_samples", 30)
        
        # Time series data
        self.time_series: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.models: Dict[str, Dict] = {}
        
        # Alert callbacks
        self.alert_callbacks: List[Callable] = []
        
    def add_data_point(self, metric_name: str, value: float, timestamp: datetime = None, metadata: Dict = None):
        """Add data point to time series"""
        ts = timestamp or datetime.now()
        self.time_series[metric_name].append({
            "timestamp": datetime.now() if timestamp is None else timestamp,
            "value": value,
            "metadata": metadata or {}
        })
    
    def add_alert_callback(self, callback: Callable):
        self.alert_callbacks.append(callback)
    
    async def detect_anomalies(self) -> List[Dict]:
        """Run anomaly detection on all metrics"""
        anomalies = []
        
        for metric_name, data_points in self.time_series.items():
            if len(data_points) < self.min_samples:
                continue
            
            values = [dp["value"] for dp in data_points]
            timestamps = [dp["timestamp"] for dp in data_points]
            
            # Run multiple detection methods
            anomalies.extend(await self._z_score_detection(metric_name, values, timestamps))
            anomalies.extend(await self._iqr_detection(metric_name, values, timestamps))
            anomalies.extend(await self._ewma_detection(metric_name, values, timestamps))
            anomalies.extend(await self._change_point_detection(metric_name, values, timestamps))
            anomalies.extend(await self._seasonal_detection(metric_name, values, timestamps))
        
        return anomalies
    
    async def _z_score_detection(self, metric_name: str, values: List[float], timestamps: List[datetime]) -> List[Dict]:
        """Z-score based anomaly detection"""
        anomalies = []
        if len(values) < 2:
            return anomalies
        
        mean = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0
        
        if stdev == 0:
            return anomalies
        
        for i, (value, timestamp) in enumerate(zip(values, timestamps)):
            z_score = abs(value - mean) / stdev
            if z_score > self.sensitivity:
                alert = {
                    "alert_id": f"ZSCORE-{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(f'{timestamp}{metric_name}')}",
                    "timestamp": timestamp,
                    "severity": "HIGH" if z_score > 4 else "MEDIUM",
                    "category": "STATISTICAL_ANOMALY",
                    "metric_name": metric_name,
                    "expected_value": mean,
                    "actual_value": value,
                    "deviation": z_score,
                    "method": "z_score",
                    "details": {"z_score": z_score, "mean": mean, "stdev": stdev}
                }
                yield alert
    
    async def _iqr_detection(self, metric_name: str, values: List[float], timestamps: List[datetime]) -> List[Dict]:
        """Interquartile Range (IQR) based detection"""
        anomalies = []
        if len(values) < 4:
            return anomalies
        
        sorted_values = sorted(values)
        q1 = np.percentile(sorted_values, 25)
        q3 = np.percentile(sorted_values, 75)
        iqr = q3 - q1
        
        if iqr == 0:
            return anomalies
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        for i, (value, timestamp) in enumerate(zip(values, timestamps)):
            if value < lower_bound or value > upper_bound:
                deviation = max(abs(value - q1), abs(value - q3)) / (iqr / 2) if iqr > 0 else 0
                alert = {
                    "alert_id": f"IQR-{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(str(metric_name))}",
                    "timestamp": timestamps[i] if i < len(timestamps) else datetime.now(),
                    "severity": "HIGH" if abs(value - np.median(values)) > 3 * iqr else "MEDIUM",
                    "category": "STATISTICAL_ANOMALY",
                    "metric_name": metric_name,
                    "expected_value": (q1 + q3) / 2,
                    "actual_value": value,
                    "deviation": deviation,
                    "method": "iqr",
                    "details": {"q1": q1, "q3": q3, "iqr": iqr, "lower_bound": lower_bound, "upper_bound": upper_bound}
                }
                yield alert
    
    async def _ewma_detection(self, metric_name: str, values: List[float], timestamps: List[datetime]) -> List[Dict]:
        """Exponentially Weighted Moving Average detection"""
        anomalies = []
        if len(values) < 10:
            return anomalies
        
        alpha = 0.3
        ewma = values[0]
        ewma_var = 0
        
        for i, (value, timestamp) in enumerate(zip(values, timestamps)):
            if i == 0:
                continue
            
            # Update EWMA
            ewma = alpha * value + (1 - alpha) * ewma
            ewma_var = alpha * (value - ewma) ** 2 + (1 - alpha) * ewma_var
            
            # Control limits
            if ewma_var > 0:
                std = np.sqrt(ewma_var)
                upper = ewma + 3 * std
                lower = ewma - 3 * std
                
                if value > upper or value < lower:
                    deviation = max(abs(value - upper), abs(value - lower)) / std
                    alert = {
                        "alert_id": f"EWMA-{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(str(metric_name))}",
                        "timestamp": timestamp,
                        "severity": "HIGH" if deviation > 4 else "MEDIUM",
                        "category": "STATISTICAL_ANOMALY",
                        "metric_name": metric_name,
                        "expected_value": ewma,
                        "actual_value": value,
                        "deviation": deviation,
                        "method": "ewma",
                        "details": {"ewma": ewma, "std": std, "upper": upper, "lower": lower}
                    }
                    yield alert
            
            # Update EWMA for next iteration
            ewma = alpha * value + (1 - alpha) * ewma
            ewma_var = alpha * (value - ewma) ** 2 + (1 - alpha) * ewma_var
    
    async def _change_point_detection(self, metric_name: str, values: List[float], timestamps: List[datetime]) -> List[Dict]:
        """Detect sudden changes in metric behavior"""
        anomalies = []
        if len(values) < 20:
            return anomalies
        
        window = min(50, len(values) // 4)
        step = max(1, window // 2)
        
        for i in range(window, len(values) - window, step):
            before = values[i-window:i]
            after = values[i:i+window]
            
            if len(before) < 5 or len(after) < 5:
                continue
            
            # Statistical test for mean shift
            mean_before = statistics.mean(before)
            mean_after = statistics.mean(after)
            std_before = statistics.stdev(before) if len(before) > 1 else 0
            std_after = statistics.stdev(after) if len(after) > 1 else 0
            
            if std_before > 0 and std_after > 0:
                # Welch's t-test
                t_stat = abs(mean_after - mean_before) / np.sqrt(std_before**2/len(before) + std_after**2/len(after))
                
                if t_stat > 4:  # Significant change
                    alert = {
                        "alert_id": f"CHANGEPOINT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        "timestamp": timestamps[i] if i < len(timestamps) else datetime.now(),
                        "severity": "HIGH",
                        "category": "CHANGE_POINT",
                        "metric_name": "change_point",
                        "expected_value": statistics.mean(values[:i]),
                        "actual_value": statistics.mean(values[i:i+window]),
                        "deviation": abs(statistics.mean(after) - statistics.mean(before)),
                        "method": "change_point",
                        "details": {
                            "mean_before": mean_before,
                            "mean_after": mean_after,
                            "t_statistic": t_stat
                        }
                    }
                    yield alert
    
    async def _seasonal_detection(self, metric_name: str, values: List[float], timestamps: List[datetime]) -> List[Dict]:
        """Detect seasonal anomalies"""
        # Simplified seasonal detection - would use proper seasonal decomposition in production
        return []


class MLAnomalyDetector:
    """
    Machine Learning based anomaly detection
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.models: Dict[str, Any] = {}
        self.scalers: Dict[str, Any] = {}
        
    async def train_isolation_forest(self, metric_name: str, data: List[float], contamination: float = 0.1):
        """Train Isolation Forest for anomaly detection"""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        X = np.array(data).reshape(-1, 1)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)
        
        self.models[metric_name] = model
        self.scalers[metric_name] = scaler
    
    async def detect(self, metric_name: str, values: List[float]) -> List[int]:
        """Detect anomalies using trained model"""
        if metric_name not in self.models:
            return []
        
        model = self.models[metric_name]
        scaler = self.scalers[metric_name]
        
        X = np.array(values).reshape(-1, 1)
        X_scaled = scaler.transform(X)
        
        predictions = model.predict(X_scaled)
        # -1 for anomalies, 1 for normal
        return [1 if p == -1 else 0 for p in predictions]


class AnomalyDetectionSystem:
    """
    Complete anomaly detection system combining multiple methods
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.statistical = StatisticalAnomalyDetector(config)
        self.ml = MLAnomalyDetector(config)
        self.alert_callbacks: List[Callable] = []
        
    def add_alert_callback(self, callback: Callable):
        self.alert_callbacks.append(callback)
        self.statistical.add_alert_callback(callback)
    
    async def process_metric(self, metric_name: str, value: float, timestamp: datetime = None, metadata: Dict = None):
        """Process single metric value"""
        self.statistical.add_data_point(metric_name, value, timestamp)
    
    async def process_batch(self, metrics: Dict[str, List[float]], timestamps: List[datetime] = None):
        """Process batch of metrics"""
        for metric_name, values in metrics.items():
            ts_list = timestamps or [datetime.now()] * len(values)
            for value, ts in zip(values, ts_list):
                self.statistical.add_data_point(metric_name, value, ts)
    
    async def run_detection(self) -> List[Dict]:
        """Run all detection methods"""
        all_anomalies = []
        
        # Statistical methods
        statistical_anomalies = []
        async for anomaly in self.statistical.detect_anomalies():
            all_anomalies.append(anomaly)
        
        # ML methods
        ml_anomalies = []
        # ML detection would be called here
        
        # Combine and deduplicate
        all_anomalies.extend(statistical_anomalies)
        all_anomalies.extend(ml_anomalies)
        
        # Deduplicate
        unique_anomalies = self._deduplicate(all_anomalies)
        
        # Trigger callbacks
        for anomaly in unique_anomalies:
            for callback in self.alert_callbacks:
                try:
                    await callback(anomaly)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
        
        return unique_anomalies
    
    def _deduplicate(self, anomalies: List[Dict]) -> List[Dict]:
        """Remove duplicate anomalies"""
        seen = set()
        unique = []
        for anomaly in anomalies:
            key = f"{anomaly['metric_name']}_{anomaly['method']}_{anomaly['timestamp'].strftime('%Y%m%d%H%M')}"
            if anomaly.get('alert_id') not in seen:
                seen.add(anomaly.get('alert_id', ''))
                unique.append(anomaly)
        return unique
    
    def get_model_status(self) -> Dict:
        return {
            "statistical_windows": {k: len(v) for k, v in self.statistical.time_series.items()},
            "ml_models": list(self.ml.models.keys()),
            "total_data_points": sum(len(v) for v in self.statistical.time_series.values())
        }


# Real-time anomaly detection pipeline
class RealTimeAnomalyPipeline:
    """
    Real-time anomaly detection pipeline
    """
    
    def __init__(self, config: Dict = None):
        self.detector = AnomalyDetectionSystem()
        self.buffer = defaultdict(list)
        self.batch_size = 100
        self.flush_interval = 60  # seconds
        self.running = False
        
    async def ingest(self, metric_name: str, value: float, timestamp: datetime = None, tags: Dict = None):
        """Ingest metric for real-time detection"""
        ts = datetime.now() if datetime is None else timestamp
        self.detector.statistical.add_data_point(metric_name, value, datetime.now())
    
    async def start(self):
        """Start real-time detection"""
        self.running = True
        asyncio.create_task(self._periodic_detection())
    
    async def _periodic_detection(self):
        while True:
            await asyncio.sleep(60)  # Check every minute
            anomalies = await self.detector.run_detection()
            for anomaly in anomalies:
                logger.warning(f"Anomaly detected: {anomaly}")
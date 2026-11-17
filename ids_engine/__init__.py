"""
Network Intrusion Detection System
Real-time network traffic analysis for attack detection
"""
from .ids_engine import IDSEngine
from .rules import load_rules, Rule
from .alerts import AlertManager

__all__ = ["IDSEngine", "Rule", "AlertManager"]
"""
Advanced Threat Detection Engine - Malwarebytes Style
Implements multi-layer threat detection with behavioral analysis
"""

import os
import math
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Tuple

class ThreatSignature:
    """Known malware signatures and threat patterns"""
    
    MALWARE_SIGNATURES = {
        # Ransomware patterns
        'ransomware': ['encrypt', 'ransom', 'bitcoin', 'wallet', 'pay', '.key', 'locked'],
        # Trojan patterns
        'trojan': ['trojan', 'backdoor', 'rat', 'remote', 'keylog', 'steal'],
        # Spyware patterns
        'spyware': ['spy', 'monitor', 'track', 'record', 'browser', 'cookie'],
        # Adware patterns
        'adware': ['ad', 'popup', 'click', 'advertis', 'banner'],
    }
    
    DANGEROUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar',
        '.dll', '.sys', '.drv', '.pif', '.zip', '.rar'
    ]
    
    DANGEROUS_APIs = [
        'CreateRemoteThread', 'SetWindowsHookEx', 'WriteProcessMemory',
        'VirtualAllocEx', 'RegSetValue', 'WinExec', 'ShellExecute',
        'InternetOpenUrl', 'URLDownloadToFile', 'CreateProcess'
    ]

class BehavioralAnalyzer:
    """Analyzes file behavior patterns"""
    
    @staticmethod
    def check_encryption_pattern(entropy: float) -> Tuple[bool, str, float]:
        """Detect encrypted/packed content"""
        threat_score = 0.0
        threat_type = ""
        
        if entropy > 7.8:
            threat_score = 0.85
            threat_type = "HIGH_ENTROPY_PACK"
        elif entropy > 7.5:
            threat_score = 0.65
            threat_type = "SUSPICIOUS_COMPRESSION"
        elif entropy > 7.0:
            threat_score = 0.35
            threat_type = "POSSIBLE_ENCRYPTION"
            
        return threat_score > 0.5, threat_type, threat_score

    @staticmethod
    def check_file_size_anomaly(file_size_kb: float, file_type: str) -> Tuple[bool, str, float]:
        """Detect abnormal file sizes"""
        threat_score = 0.0
        threat_type = ""
        
        if file_type == 'executable':
            # Unusually large executables
            if file_size_kb > 50000:
                threat_score = 0.55
                threat_type = "OVERSIZED_EXECUTABLE"
            # Unusually small executables (stub)
            elif file_size_kb < 5:
                threat_score = 0.45
                threat_type = "MINI_EXECUTABLE"
                
        return threat_score > 0.4, threat_type, threat_score

    @staticmethod
    def check_hidden_attributes(filename: str, is_hidden: int) -> Tuple[bool, str, float]:
        """Detect hidden/suspicious attributes"""
        threat_score = 0.0
        threat_type = ""
        
        if is_hidden:
            threat_score = 0.40
            threat_type = "HIDDEN_FILE"
            
        # Double extension (e.g., file.txt.exe)
        if filename.count('.') > 1:
            parts = filename.split('.')
            if parts[-1] in ['exe', 'bat', 'cmd', 'vbs']:
                threat_score += 0.35
                threat_type = "DOUBLE_EXTENSION_MASQUERADE"
                
        return threat_score > 0.35, threat_type, threat_score

class AdvancedThreatDetector:
    """Complete multi-layer threat detection system"""
    
    def __init__(self, ai_model=None, scaler=None):
        self.ai_model = ai_model
        self.scaler = scaler
        self.threat_log = []
        self.threat_database = self._load_threat_database()
        
    def _load_threat_database(self) -> Dict:
        """Load known threats database"""
        db_file = 'threat_database.json'
        if os.path.exists(db_file):
            try:
                with open(db_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return ""
    
    def _check_hash_database(self, file_hash: str) -> Tuple[bool, str]:
        """Check if file hash matches known malware"""
        if file_hash in self.threat_database:
            threat_info = self.threat_database[file_hash]
            return True, threat_info.get('threat_name', 'UNKNOWN_MALWARE')
        return False, ""
    
    def _check_signature_patterns(self, file_path: str, filename: str) -> Tuple[bool, str, float]:
        """Check for signature-based threats"""
        threat_score = 0.0
        threat_type = ""
        is_threat = False
        
        # Extension check
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in ThreatSignature.DANGEROUS_EXTENSIONS:
            threat_score += 0.25
            threat_type = "DANGEROUS_EXTENSION"
            
        # Check file content for patterns
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read(10000)  # Read first 10KB
                
                for threat_category, patterns in ThreatSignature.MALWARE_SIGNATURES.items():
                    for pattern in patterns:
                        if pattern.lower() in content.lower():
                            threat_score += 0.15
                            threat_type = f"SIGNATURE_{threat_category.upper()}"
                            
        except:
            pass
            
        return threat_score > 0.30, threat_type, threat_score
    
    def calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file"""
        try:
            with open(file_path, 'rb') as f:
                byteArr = list(f.read())
            fileSize = len(byteArr)
            if fileSize == 0:
                return 0.0
                
            freqList = [0] * 256
            for b in byteArr:
                freqList[b] += 1
                
            ent = 0.0
            for f in freqList:
                if f > 0:
                    prob = float(f) / fileSize
                    ent = ent + prob * math.log(prob, 2)
            return -ent
        except:
            return 0.0
    
    def scan_file(self, file_path: str) -> Dict:
        """Comprehensive file threat analysis"""
        result = {
            'file_path': file_path,
            'filename': os.path.basename(file_path),
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'is_threat': False,
            'threat_level': 'SAFE',
            'threat_type': '',
            'confidence': 0.0,
            'risk_score': 0.0,
            'detection_methods': [],
            'recommendations': []
        }
        
        try:
            # Get file properties
            file_size_kb = os.path.getsize(file_path) / 1024
            filename = result['filename']
            is_hidden = 1 if filename.startswith('.') else 0
            entropy = self.calculate_entropy(file_path)
            
            overall_threat_score = 0.0
            detection_count = 0
            
            # 1. Hash-based detection
            file_hash = self._calculate_file_hash(file_path)
            is_known_malware, threat_name = self._check_hash_database(file_hash)
            if is_known_malware:
                result['is_threat'] = True
                result['threat_type'] = threat_name
                result['threat_level'] = 'CRITICAL'
                result['confidence'] = 0.99
                result['risk_score'] = 1.0
                result['detection_methods'].append('HASH_DATABASE')
                result['recommendations'].append('QUARANTINE_IMMEDIATELY')
                return result
            
            # 2. Signature-based detection
            sig_threat, sig_type, sig_score = self._check_signature_patterns(file_path, filename)
            if sig_threat:
                result['detection_methods'].append('SIGNATURE_ANALYSIS')
                overall_threat_score += sig_score
                detection_count += 1
                if result['threat_type'] == '':
                    result['threat_type'] = sig_type
            
            # 3. Behavioral analysis - Encryption
            enc_threat, enc_type, enc_score = BehavioralAnalyzer.check_encryption_pattern(entropy)
            if enc_threat:
                result['detection_methods'].append('ENCRYPTION_PATTERN')
                overall_threat_score += enc_score
                detection_count += 1
                if result['threat_type'] == '':
                    result['threat_type'] = enc_type
            
            # 4. Behavioral analysis - File size
            file_type = 'executable' if filename.lower().endswith(('.exe', '.dll', '.sys')) else 'other'
            size_threat, size_type, size_score = BehavioralAnalyzer.check_file_size_anomaly(file_size_kb, file_type)
            if size_threat:
                result['detection_methods'].append('ANOMALY_SIZE')
                overall_threat_score += size_score
                detection_count += 1
                if result['threat_type'] == '':
                    result['threat_type'] = size_type
            
            # 5. Behavioral analysis - Hidden attributes
            hidden_threat, hidden_type, hidden_score = BehavioralAnalyzer.check_hidden_attributes(filename, is_hidden)
            if hidden_threat:
                result['detection_methods'].append('SUSPICIOUS_ATTRIBUTES')
                overall_threat_score += hidden_score
                detection_count += 1
                if result['threat_type'] == '':
                    result['threat_type'] = hidden_type
            
            # 6. AI Model Detection (if available)
            if self.ai_model and self.scaler:
                try:
                    suspicious_api = 15 if filename.lower().endswith(('.exe', '.dll', '.bat')) else 2
                    features = [[file_size_kb, entropy, suspicious_api, is_hidden]]
                    import numpy as np
                    features_scaled = self.scaler.transform(features)
                    prediction = self.ai_model.predict(features_scaled)[0]
                    prob = self.ai_model.predict_proba(features_scaled)[0][1]
                    
                    if prediction == 1:
                        result['detection_methods'].append('AI_MODEL')
                        overall_threat_score += prob
                        detection_count += 1
                except:
                    pass
            
            # Calculate final threat assessment
            if detection_count > 0:
                avg_threat_score = overall_threat_score / detection_count
            else:
                avg_threat_score = 0.0
            
            result['risk_score'] = min(avg_threat_score, 1.0)
            result['confidence'] = min(detection_count * 0.20, 0.99)  # Confidence increases with more detections
            
            # Determine threat level
            if avg_threat_score > 0.75:
                result['is_threat'] = True
                result['threat_level'] = 'CRITICAL'
                result['recommendations'].append('QUARANTINE_IMMEDIATELY')
            elif avg_threat_score > 0.60:
                result['is_threat'] = True
                result['threat_level'] = 'HIGH'
                result['recommendations'].append('QUARANTINE_RECOMMENDED')
            elif avg_threat_score > 0.40:
                result['threat_level'] = 'MEDIUM'
                result['recommendations'].append('MONITOR_CLOSELY')
            elif avg_threat_score > 0.20:
                result['threat_level'] = 'LOW'
                result['recommendations'].append('UNDER_OBSERVATION')
            
        except Exception as e:
            result['threat_level'] = 'UNKNOWN'
            result['recommendations'].append('ERROR_IN_SCAN')
            
        # Log threat
        self.threat_log.append(result)
        return result
    
    def batch_scan(self, file_paths: List[str]) -> List[Dict]:
        """Scan multiple files"""
        results = []
        for file_path in file_paths:
            results.append(self.scan_file(file_path))
        return results
    
    def get_threat_report(self) -> Dict:
        """Generate comprehensive threat report"""
        report = {
            'total_scans': len(self.threat_log),
            'critical_threats': 0,
            'high_threats': 0,
            'medium_threats': 0,
            'safe_files': 0,
            'scan_timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'threat_breakdown': {}
        }
        
        for log in self.threat_log:
            if log['threat_level'] == 'CRITICAL':
                report['critical_threats'] += 1
            elif log['threat_level'] == 'HIGH':
                report['high_threats'] += 1
            elif log['threat_level'] == 'MEDIUM':
                report['medium_threats'] += 1
            elif log['threat_level'] == 'SAFE':
                report['safe_files'] += 1
                
            threat_type = log['threat_type']
            if threat_type not in report['threat_breakdown']:
                report['threat_breakdown'][threat_type] = 0
            report['threat_breakdown'][threat_type] += 1
            
        return report

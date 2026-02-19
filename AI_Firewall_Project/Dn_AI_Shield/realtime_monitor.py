"""
Real-Time File Monitoring System - Malwarebytes Style
Monitors folder/drive for suspicious file activities
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Callable
from threading import Thread, Event
import hashlib

class FileMonitor:
    """Real-time file system monitoring"""
    
    def __init__(self, threat_detector=None):
        self.threat_detector = threat_detector
        self.monitored_paths = []
        self.file_baseline = {}  # Stores file hashes for change detection
        self.alerts = []
        self.is_monitoring = False
        self.stop_event = Event()
        
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash for change detection"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return ""
    
    def create_baseline(self, folder_path: str) -> Dict:
        """Create baseline of existing files"""
        baseline = {}
        try:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_hash = self.calculate_file_hash(file_path)
                        file_size = os.path.getsize(file_path)
                        mod_time = os.path.getmtime(file_path)
                        
                        baseline[file_path] = {
                            'hash': file_hash,
                            'size': file_size,
                            'mod_time': mod_time,
                            'status': 'baseline'
                        }
                    except:
                        pass
        except:
            pass
        return baseline
    
    def detect_suspicious_activity(self, file_path: str) -> Dict:
        """Detect suspicious file modifications"""
        alert = {
            'file_path': file_path,
            'filename': os.path.basename(file_path),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'activity_type': 'UNKNOWN',
            'threat_level': 'LOW',
            'details': {}
        }
        
        try:
            if not os.path.exists(file_path):
                # File was deleted
                if file_path in self.file_baseline:
                    alert['activity_type'] = 'FILE_DELETED'
                    alert['threat_level'] = 'MEDIUM'
                    del self.file_baseline[file_path]
                return alert
            
            current_hash = self.calculate_file_hash(file_path)
            current_size = os.path.getsize(file_path)
            
            if file_path not in self.file_baseline:
                # New file created
                alert['activity_type'] = 'NEW_FILE_CREATED'
                alert['threat_level'] = 'LOW'
                
                # Scan new file with threat detector
                if self.threat_detector:
                    scan_result = self.threat_detector.scan_file(file_path)
                    alert['threat_level'] = self._map_threat_level(scan_result['threat_level'])
                    alert['details']['scan_result'] = scan_result
                
                self.file_baseline[file_path] = {
                    'hash': current_hash,
                    'size': current_size,
                    'mod_time': os.path.getmtime(file_path),
                    'status': 'new'
                }
            else:
                # Existing file modified
                baseline = self.file_baseline[file_path]
                
                if baseline['hash'] != current_hash:
                    alert['activity_type'] = 'FILE_MODIFIED'
                    alert['threat_level'] = 'MEDIUM'
                    alert['details']['hash_changed'] = True
                    alert['details']['old_hash'] = baseline['hash']
                    alert['details']['new_hash'] = current_hash
                    
                    # Suspicious modifications
                    if baseline['size'] < 100 and current_size > baseline['size'] * 5:
                        alert['activity_type'] = 'SUSPICIOUS_SIZE_INCREASE'
                        alert['threat_level'] = 'HIGH'
                        
                    # Rescan with threat detector
                    if self.threat_detector:
                        scan_result = self.threat_detector.scan_file(file_path)
                        alert['threat_level'] = max(alert['threat_level'], 
                                                   self._map_threat_level(scan_result['threat_level']))
                        if scan_result['is_threat']:
                            alert['details']['threat_detected'] = True
                            alert['details']['threat_type'] = scan_result['threat_type']
                    
                    baseline['hash'] = current_hash
                    baseline['size'] = current_size
                    baseline['mod_time'] = os.path.getmtime(file_path)
                    
        except Exception as e:
            alert['activity_type'] = 'MONITOR_ERROR'
            alert['details']['error'] = str(e)
            
        return alert
    
    def _map_threat_level(self, threat_str: str) -> str:
        """Map threat level string to alert level"""
        mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW',
            'SAFE': 'SAFE',
            'UNKNOWN': 'LOW'
        }
        return mapping.get(threat_str, 'LOW')
    
    def watch_folder(self, folder_path: str, interval: int = 5) -> None:
        """Watch folder for changes"""
        if not os.path.exists(folder_path):
            print(f"Folder not found: {folder_path}")
            return
            
        print(f"Creating baseline for {folder_path}...")
        self.file_baseline = self.create_baseline(folder_path)
        
        self.is_monitoring = True
        print(f"Started monitoring {folder_path}")
        
        try:
            while self.is_monitoring and not self.stop_event.is_set():
                current_files = set()
                
                try:
                    for root, dirs, files in os.walk(folder_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            current_files.add(file_path)
                            
                            # Check for modifications
                            alert = self.detect_suspicious_activity(file_path)
                            if alert['activity_type'] != 'UNKNOWN':
                                self.alerts.append(alert)
                                print(f"[ALERT] {alert['activity_type']}: {alert['filename']}")
                                
                except Exception as e:
                    print(f"Monitor error: {e}")
                
                # Check for deleted files
                removed_files = set(self.file_baseline.keys()) - current_files
                for removed_file in removed_files:
                    if self.file_baseline[removed_file]['status'] != 'baseline':
                        alert = self.detect_suspicious_activity(removed_file)
                        self.alerts.append(alert)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def start_background_monitoring(self, folder_path: str, interval: int = 5) -> Thread:
        """Start monitoring in background thread"""
        monitor_thread = Thread(
            target=self.watch_folder,
            args=(folder_path, interval),
            daemon=True
        )
        monitor_thread.start()
        return monitor_thread
    
    def stop_monitoring(self) -> None:
        """Stop all monitoring"""
        self.is_monitoring = False
        self.stop_event.set()
        print("Monitoring stopped")
    
    def get_alerts(self, threat_level: str = None) -> List[Dict]:
        """Get monitoring alerts, optionally filtered by threat level"""
        if threat_level:
            return [a for a in self.alerts if a['threat_level'] == threat_level]
        return self.alerts
    
    def clear_alerts(self) -> None:
        """Clear all alerts"""
        self.alerts = []
    
    def get_alert_summary(self) -> Dict:
        """Get summary of alerts"""
        summary = {
            'total_alerts': len(self.alerts),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'activity_breakdown': {}
        }
        
        for alert in self.alerts:
            level = alert['threat_level']
            if level == 'CRITICAL':
                summary['critical'] += 1
            elif level == 'HIGH':
                summary['high'] += 1
            elif level == 'MEDIUM':
                summary['medium'] += 1
            else:
                summary['low'] += 1
                
            activity = alert['activity_type']
            summary['activity_breakdown'][activity] = summary['activity_breakdown'].get(activity, 0) + 1
        
        return summary

class ProcessMonitor:
    """Monitor running processes for suspicious behavior"""
    
    def __init__(self):
        self.monitored_processes = []
        self.suspicious_activities = []
        
    def detect_suspicious_behavior(self, process_name: str) -> Dict:
        """Check process for suspicious behaviors"""
        alert = {
            'process': process_name,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'behavior': [],
            'risk_level': 'LOW'
        }
        
        # Suspicious process names
        suspicious_names = [
            'svchost.exe', 'csrss.exe', 'lsass.exe', 'rundll32.exe',
            'regsvcs.exe', 'calc.exe', 'notepad.exe'
        ]
        
        if any(suspicious in process_name.lower() for suspicious in suspicious_names):
            alert['behavior'].append('SUSPICIOUS_PROCESS_NAME')
            alert['risk_level'] = 'MEDIUM'
        
        return alert

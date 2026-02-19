"""
Notification System - Malwarebytes Style
Manages threat alerts and notifications
"""

import json
import os
from datetime import datetime
from typing import List, Dict
from enum import Enum

class NotificationLevel(Enum):
    """Notification severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class NotificationManager:
    """Manage notifications and alerts"""
    
    def __init__(self):
        self.notifications = []
        self.notification_db = 'notifications.json'
        self.load_notifications()
        
    def load_notifications(self) -> None:
        """Load notifications from database"""
        if os.path.exists(self.notification_db):
            try:
                with open(self.notification_db, 'r') as f:
                    self.notifications = json.load(f)
            except:
                self.notifications = []
    
    def save_notifications(self) -> None:
        """Save notifications to database"""
        try:
            with open(self.notification_db, 'w') as f:
                json.dump(self.notifications, f, indent=2)
        except:
            pass
    
    def create_notification(self, title: str, message: str, level: str = "INFO",
                          notification_type: str = "GENERAL", data: Dict = None) -> Dict:
        """Create a new notification"""
        notification = {
            'id': int(datetime.now().timestamp() * 1000),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'title': title,
            'message': message,
            'level': level,
            'type': notification_type,
            'is_read': False,
            'action_required': level in ["CRITICAL", "HIGH"],
            'data': data or {}
        }
        
        self.notifications.append(notification)
        self.save_notifications()
        return notification
    
    def threat_notification(self, filename: str, threat_type: str, risk_score: float) -> Dict:
        """Create threat detection notification"""
        level = "CRITICAL" if risk_score > 0.75 else "HIGH" if risk_score > 0.6 else "MEDIUM"
        
        return self.create_notification(
            title=f"Threat Detected: {threat_type}",
            message=f"Suspicious file '{filename}' detected (Risk: {risk_score*100:.1f}%)",
            level=level,
            notification_type="THREAT_DETECTED",
            data={
                'filename': filename,
                'threat_type': threat_type,
                'risk_score': risk_score
            }
        )
    
    def scan_complete_notification(self, scanned_files: int, threats_found: int) -> Dict:
        """Create scan completion notification"""
        level = "HIGH" if threats_found > 0 else "INFO"
        
        return self.create_notification(
            title="Scan Complete",
            message=f"Scanned {scanned_files} files. Threats found: {threats_found}",
            level=level,
            notification_type="SCAN_COMPLETE",
            data={
                'scanned_files': scanned_files,
                'threats_found': threats_found
            }
        )
    
    def quarantine_notification(self, filename: str, quarantine_id: str) -> Dict:
        """Create quarantine notification"""
        return self.create_notification(
            title="File Quarantined",
            message=f"File '{filename}' has been safely quarantined.",
            level="MEDIUM",
            notification_type="FILE_QUARANTINED",
            data={
                'filename': filename,
                'quarantine_id': quarantine_id
            }
        )
    
    def protection_enabled_notification(self, protection_type: str) -> Dict:
        """Create protection enabled notification"""
        return self.create_notification(
            title=f"{protection_type} Enabled",
            message=f"Real-time {protection_type} is now active.",
            level="INFO",
            notification_type="PROTECTION_ENABLED",
            data={'protection_type': protection_type}
        )
    
    def protection_disabled_warning(self, protection_type: str) -> Dict:
        """Create protection disabled warning"""
        return self.create_notification(
            title=f"Warning: {protection_type} Disabled",
            message=f"Real-time {protection_type} is currently disabled. Your system may be at risk.",
            level="HIGH",
            notification_type="PROTECTION_DISABLED",
            data={'protection_type': protection_type}
        )
    
    def get_notifications(self, unread_only: bool = False, level_filter: str = None) -> List[Dict]:
        """Get notifications with optional filtering"""
        notifications = self.notifications
        
        if unread_only:
            notifications = [n for n in notifications if not n['is_read']]
        
        if level_filter:
            notifications = [n for n in notifications if n['level'] == level_filter]
        
        # Return newest first
        return sorted(notifications, key=lambda x: x['timestamp'], reverse=True)
    
    def mark_as_read(self, notification_id: int) -> Dict:
        """Mark notification as read"""
        result = {'success': False, 'message': ''}
        
        notification = next((n for n in self.notifications if n['id'] == notification_id), None)
        
        if notification:
            notification['is_read'] = True
            self.save_notifications()
            result['success'] = True
            result['message'] = "Notification marked as read"
        else:
            result['message'] = "Notification not found"
        
        return result
    
    def mark_all_as_read(self) -> Dict:
        """Mark all notifications as read"""
        for notification in self.notifications:
            notification['is_read'] = True
        
        self.save_notifications()
        return {'success': True, 'message': 'All notifications marked as read'}
    
    def delete_notification(self, notification_id: int) -> Dict:
        """Delete a notification"""
        result = {'success': False, 'message': ''}
        
        notification = next((n for n in self.notifications if n['id'] == notification_id), None)
        
        if notification:
            self.notifications.remove(notification)
            self.save_notifications()
            result['success'] = True
            result['message'] = "Notification deleted"
        else:
            result['message'] = "Notification not found"
        
        return result
    
    def delete_old_notifications(self, days: int = 7) -> Dict:
        """Delete notifications older than specified days"""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        original_count = len(self.notifications)
        
        self.notifications = [
            n for n in self.notifications
            if datetime.strptime(n['timestamp'], "%Y-%m-%d %H:%M:%S") > cutoff_date
        ]
        
        self.save_notifications()
        
        return {
            'success': True,
            'deleted': original_count - len(self.notifications),
            'message': f"Deleted {original_count - len(self.notifications)} old notifications"
        }
    
    def get_notification_summary(self) -> Dict:
        """Get summary of notifications"""
        summary = {
            'total': len(self.notifications),
            'unread': len([n for n in self.notifications if not n['is_read']]),
            'critical': len([n for n in self.notifications if n['level'] == 'CRITICAL']),
            'high': len([n for n in self.notifications if n['level'] == 'HIGH']),
            'medium': len([n for n in self.notifications if n['level'] == 'MEDIUM']),
            'low': len([n for n in self.notifications if n['level'] == 'LOW']),
            'info': len([n for n in self.notifications if n['level'] == 'INFO']),
            'action_required': len([n for n in self.notifications if n['action_required'] and not n['is_read']])
        }
        return summary
    
    def clear_all_notifications(self) -> Dict:
        """Clear all notifications"""
        count = len(self.notifications)
        self.notifications = []
        self.save_notifications()
        return {
            'success': True,
            'cleared': count,
            'message': f"Cleared {count} notifications"
        }

"""
Advanced Quarantine Management System - Malwarebytes Style
Handles isolation, analysis, and restoration of suspicious files
"""

import os
import shutil
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import hashlib

class QuarantineManager:
    """Professional quarantine file management"""
    
    def __init__(self, quarantine_root: str = None):
        if quarantine_root is None:
            quarantine_root = os.path.join(os.path.expanduser('~'), '.dn_security', 'quarantine')
        
        self.quarantine_root = quarantine_root
        self.quarantine_db = os.path.join(quarantine_root, 'quarantine_db.json')
        self.quarantine_list = self._load_quarantine_db()
        
        # Create quarantine directory if not exists
        os.makedirs(quarantine_root, exist_ok=True)
        
    def _load_quarantine_db(self) -> List[Dict]:
        """Load quarantine database"""
        if os.path.exists(self.quarantine_db):
            try:
                with open(self.quarantine_db, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_quarantine_db(self) -> None:
        """Save quarantine database"""
        try:
            with open(self.quarantine_db, 'w') as f:
                json.dump(self.quarantine_list, f, indent=2)
        except:
            pass
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return ""
    
    def quarantine_file(self, file_path: str, reason: str = "MANUAL", 
                       threat_type: str = "UNKNOWN", risk_score: float = 0.0) -> Dict:
        """Quarantine a file"""
        result = {
            'success': False,
            'message': '',
            'quarantine_id': '',
            'quarantine_path': ''
        }
        
        if not os.path.exists(file_path):
            result['message'] = f"File not found: {file_path}"
            return result
        
        try:
            # Generate quarantine ID
            file_hash = self._calculate_file_hash(file_path)
            quarantine_id = file_hash[:16] if file_hash else str(int(datetime.now().timestamp() * 1000))
            
            # Create subdirectory in quarantine
            quarantine_subdir = os.path.join(self.quarantine_root, quarantine_id)
            os.makedirs(quarantine_subdir, exist_ok=True)
            
            # Copy file to quarantine
            original_name = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_subdir, original_name + '.quarantine')
            shutil.copy2(file_path, quarantine_path)
            
            # Create metadata
            metadata = {
                'quarantine_id': quarantine_id,
                'original_path': file_path,
                'original_name': original_name,
                'quarantine_path': quarantine_path,
                'quarantine_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'file_size': os.path.getsize(file_path),
                'file_hash': file_hash,
                'reason': reason,
                'threat_type': threat_type,
                'risk_score': risk_score,
                'is_restored': False,
                'status': 'ISOLATED'
            }
            
            # Save metadata
            metadata_file = os.path.join(quarantine_subdir, 'metadata.json')
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Add to quarantine list
            self.quarantine_list.append(metadata)
            self._save_quarantine_db()
            
            # Remove original file
            try:
                os.remove(file_path)
            except:
                pass
            
            result['success'] = True
            result['message'] = f"File quarantined successfully"
            result['quarantine_id'] = quarantine_id
            result['quarantine_path'] = quarantine_path
            
        except Exception as e:
            result['message'] = f"Error quarantining file: {str(e)}"
        
        return result
    
    def batch_quarantine(self, file_paths: List[str], reason: str = "BATCH_SCAN") -> Dict:
        """Quarantine multiple files"""
        results = {
            'total': len(file_paths),
            'successful': 0,
            'failed': 0,
            'details': []
        }
        
        for file_path in file_paths:
            result = self.quarantine_file(file_path, reason)
            if result['success']:
                results['successful'] += 1
            else:
                results['failed'] += 1
            results['details'].append(result)
        
        return results
    
    def restore_file(self, quarantine_id: str) -> Dict:
        """Restore file from quarantine"""
        result = {
            'success': False,
            'message': '',
            'restored_path': ''
        }
        
        # Find quarantine record
        record = next((r for r in self.quarantine_list if r['quarantine_id'] == quarantine_id), None)
        
        if not record:
            result['message'] = "Quarantine record not found"
            return result
        
        if record['is_restored']:
            result['message'] = "File already restored"
            return result
        
        try:
            quarantine_path = record['quarantine_path']
            original_path = record['original_path']
            
            # Create directory if needed
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Restore file
            shutil.copy2(quarantine_path, original_path)
            
            # Update record
            record['is_restored'] = True
            record['restore_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            record['status'] = 'RESTORED'
            self._save_quarantine_db()
            
            result['success'] = True
            result['message'] = f"File restored to {original_path}"
            result['restored_path'] = original_path
            
        except Exception as e:
            result['message'] = f"Error restoring file: {str(e)}"
        
        return result
    
    def permanently_delete(self, quarantine_id: str) -> Dict:
        """Permanently delete quarantined file"""
        result = {
            'success': False,
            'message': ''
        }
        
        # Find quarantine record
        record = next((r for r in self.quarantine_list if r['quarantine_id'] == quarantine_id), None)
        
        if not record:
            result['message'] = "Quarantine record not found"
            return result
        
        try:
            quarantine_subdir = os.path.dirname(record['quarantine_path'])
            
            # Delete entire quarantine directory
            if os.path.exists(quarantine_subdir):
                shutil.rmtree(quarantine_subdir)
            
            # Remove from list
            self.quarantine_list.remove(record)
            self._save_quarantine_db()
            
            result['success'] = True
            result['message'] = "File permanently deleted"
            
        except Exception as e:
            result['message'] = f"Error deleting file: {str(e)}"
        
        return result
    
    def get_quarantined_files(self, status: str = None, threat_type: str = None) -> List[Dict]:
        """Get list of quarantined files with optional filtering"""
        files = self.quarantine_list
        
        if status:
            files = [f for f in files if f['status'] == status]
        
        if threat_type:
            files = [f for f in files if f['threat_type'] == threat_type]
        
        return files
    
    def get_quarantine_stats(self) -> Dict:
        """Get quarantine statistics"""
        stats = {
            'total_quarantined': len(self.quarantine_list),
            'isolated': len([f for f in self.quarantine_list if f['status'] == 'ISOLATED']),
            'restored': len([f for f in self.quarantine_list if f['status'] == 'RESTORED']),
            'total_size_mb': 0.0,
            'threat_breakdown': {},
            'oldest_item': None,
            'newest_item': None
        }
        
        if self.quarantine_list:
            # Calculate total size
            total_size = 0
            for item in self.quarantine_list:
                total_size += item.get('file_size', 0)
            stats['total_size_mb'] = round(total_size / (1024 * 1024), 2)
            
            # Threat breakdown
            for item in self.quarantine_list:
                threat = item['threat_type']
                stats['threat_breakdown'][threat] = stats['threat_breakdown'].get(threat, 0) + 1
            
            # Oldest and newest
            sorted_list = sorted(self.quarantine_list, 
                               key=lambda x: datetime.strptime(x['quarantine_date'], "%Y-%m-%d %H:%M:%S"))
            stats['oldest_item'] = sorted_list[0]['quarantine_date']
            stats['newest_item'] = sorted_list[-1]['quarantine_date']
        
        return stats
    
    def auto_cleanup_old_items(self, days: int = 30) -> Dict:
        """Automatically delete quarantined items older than specified days"""
        result = {
            'deleted': 0,
            'message': ''
        }
        
        cutoff_date = datetime.now() - timedelta(days=days)
        items_to_delete = []
        
        for item in self.quarantine_list:
            item_date = datetime.strptime(item['quarantine_date'], "%Y-%m-%d %H:%M:%S")
            if item_date < cutoff_date:
                items_to_delete.append(item['quarantine_id'])
        
        for quarantine_id in items_to_delete:
            del_result = self.permanently_delete(quarantine_id)
            if del_result['success']:
                result['deleted'] += 1
        
        result['message'] = f"Deleted {result['deleted']} items older than {days} days"
        return result
    
    def export_quarantine_report(self, output_file: str = None) -> str:
        """Export quarantine report to JSON/CSV"""
        if output_file is None:
            output_file = os.path.join(self.quarantine_root, 
                                      f"quarantine_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        report = {
            'report_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_items': len(self.quarantine_list),
            'statistics': self.get_quarantine_stats(),
            'items': self.quarantine_list
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            return output_file
        except Exception as e:
            print(f"Error exporting report: {e}")
            return ""

"""
Scheduled Scanning System - Malwarebytes Style
Allows users to schedule scans at specific times
"""

import json
import os
from datetime import datetime, time, timedelta
from typing import List, Dict, Callable
import threading

class ScanScheduler:
    """Schedule automatic scans"""
    
    def __init__(self):
        self.schedules = []
        self.schedule_db = 'scan_schedules.json'
        self.is_running = False
        self.scheduler_thread = None
        self.scan_callback = None
        self.load_schedules()
        
    def load_schedules(self) -> None:
        """Load schedules from database"""
        if os.path.exists(self.schedule_db):
            try:
                with open(self.schedule_db, 'r') as f:
                    self.schedules = json.load(f)
            except:
                self.schedules = []
        else:
            self.schedules = []
    
    def save_schedules(self) -> None:
        """Save schedules to database"""
        try:
            with open(self.schedule_db, 'w') as f:
                json.dump(self.schedules, f, indent=2)
        except:
            pass
    
    def add_schedule(self, schedule_name: str, days: List[str], time_str: str, 
                    scan_type: str = "quick", auto_quarantine: bool = True) -> Dict:
        """
        Add a new scan schedule
        
        Args:
            schedule_name: Name of the schedule
            days: List of days (e.g., ['Monday', 'Wednesday', 'Friday'])
            time_str: Time in HH:MM format (e.g., '14:30')
            scan_type: 'quick' or 'full'
            auto_quarantine: Auto-quarantine threats found
        """
        result = {
            'success': False,
            'message': '',
            'schedule_id': ''
        }
        
        try:
            # Validate time format
            datetime.strptime(time_str, '%H:%M')
            
            schedule_id = f"{schedule_name}_{datetime.now().timestamp()}"
            
            new_schedule = {
                'schedule_id': schedule_id,
                'name': schedule_name,
                'days': days,
                'time': time_str,
                'scan_type': scan_type,
                'auto_quarantine': auto_quarantine,
                'created_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'last_run': None,
                'next_run': self._calculate_next_run(days, time_str),
                'is_enabled': True,
                'run_count': 0
            }
            
            self.schedules.append(new_schedule)
            self.save_schedules()
            
            result['success'] = True
            result['message'] = f"Schedule '{schedule_name}' added successfully"
            result['schedule_id'] = schedule_id
            
        except ValueError as e:
            result['message'] = f"Invalid time format. Use HH:MM format. Error: {e}"
        except Exception as e:
            result['message'] = f"Error adding schedule: {str(e)}"
        
        return result
    
    def _calculate_next_run(self, days: List[str], time_str: str) -> str:
        """Calculate next run time"""
        day_map = {
            'Monday': 0, 'Tuesday': 1, 'Wednesday': 2, 'Thursday': 3,
            'Friday': 4, 'Saturday': 5, 'Sunday': 6
        }
        
        try:
            scan_time = datetime.strptime(time_str, '%H:%M').time()
            today = datetime.now()
            
            # Find next scheduled day
            for day_name in days:
                day_num = day_map.get(day_name)
                if day_num is not None:
                    next_date = today
                    days_ahead = (day_num - today.weekday()) % 7
                    if days_ahead == 0:
                        next_date_time = datetime.combine(today.date(), scan_time)
                        if next_date_time > today:
                            next_date = next_date_time
                    if days_ahead > 0 or next_date == today:
                        next_date = today.replace(hour=scan_time.hour, minute=scan_time.minute)
                    if days_ahead > 0:
                        import datetime as dt
                        next_date = today + dt.timedelta(days=days_ahead)
                        next_date = next_date.replace(hour=scan_time.hour, minute=scan_time.minute)
            
            return next_date.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def update_schedule(self, schedule_id: str, **kwargs) -> Dict:
        """Update existing schedule"""
        result = {'success': False, 'message': ''}
        
        schedule = next((s for s in self.schedules if s['schedule_id'] == schedule_id), None)
        
        if not schedule:
            result['message'] = "Schedule not found"
            return result
        
        try:
            # Update allowed fields
            allowed_fields = ['name', 'days', 'time', 'scan_type', 'auto_quarantine', 'is_enabled']
            for key, value in kwargs.items():
                if key in allowed_fields:
                    schedule[key] = value
                    if key in ['days', 'time']:
                        schedule['next_run'] = self._calculate_next_run(schedule['days'], schedule['time'])
            
            self.save_schedules()
            result['success'] = True
            result['message'] = "Schedule updated successfully"
            
        except Exception as e:
            result['message'] = f"Error updating schedule: {str(e)}"
        
        return result
    
    def remove_schedule(self, schedule_id: str) -> Dict:
        """Remove a schedule"""
        result = {'success': False, 'message': ''}
        
        schedule = next((s for s in self.schedules if s['schedule_id'] == schedule_id), None)
        
        if not schedule:
            result['message'] = "Schedule not found"
            return result
        
        try:
            self.schedules.remove(schedule)
            self.save_schedules()
            result['success'] = True
            result['message'] = "Schedule removed successfully"
        except Exception as e:
            result['message'] = f"Error removing schedule: {str(e)}"
        
        return result
    
    def get_schedules(self, enabled_only: bool = False) -> List[Dict]:
        """Get all schedules"""
        if enabled_only:
            return [s for s in self.schedules if s['is_enabled']]
        return self.schedules
    
    def get_schedule(self, schedule_id: str) -> Dict:
        """Get specific schedule"""
        return next((s for s in self.schedules if s['schedule_id'] == schedule_id), None)
    
    def set_scan_callback(self, callback: Callable) -> None:
        """Set callback function to execute when scan is triggered"""
        self.scan_callback = callback
    
    def start_scheduler(self) -> None:
        """Start the scheduler in background thread"""
        if self.is_running:
            return
        
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        print("Scan scheduler started")
    
    def _run_scheduler(self) -> None:
        """Run scheduler loop"""
        while self.is_running:
            try:
                # Check if any scheduled scans should run
                current_time = datetime.now()
                current_day = current_time.strftime("%A")
                current_time_str = current_time.strftime("%H:%M")
                
                for sched in self.schedules:
                    if not sched['is_enabled']:
                        continue
                    
                    if current_day in sched['days'] and current_time_str == sched['time']:
                        if self.scan_callback:
                            self.scan_callback(sched)
                            sched['run_count'] += 1
                            sched['last_run'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            self.save_schedules()
                
                threading.Event().wait(10)  # Check every 10 seconds
            except Exception as e:
                print(f"Scheduler error: {e}")
    
    def stop_scheduler(self) -> None:
        """Stop the scheduler"""
        self.is_running = False
        print("Scan scheduler stopped")
    
    def get_next_scheduled_scans(self, count: int = 5) -> List[Dict]:
        """Get upcoming scheduled scans"""
        enabled = [s for s in self.schedules if s['is_enabled']]
        
        # Sort by next_run time
        sorted_scans = sorted(
            enabled, 
            key=lambda x: datetime.strptime(x['next_run'], "%Y-%m-%d %H:%M:%S")
        )
        
        return sorted_scans[:count]
    
    def get_schedule_stats(self) -> Dict:
        """Get scheduler statistics"""
        stats = {
            'total_schedules': len(self.schedules),
            'enabled': len([s for s in self.schedules if s['is_enabled']]),
            'disabled': len([s for s in self.schedules if not s['is_enabled']]),
            'quick_scans': len([s for s in self.schedules if s['scan_type'] == 'quick']),
            'full_scans': len([s for s in self.schedules if s['scan_type'] == 'full']),
            'total_runs': sum(s.get('run_count', 0) for s in self.schedules)
        }
        return stats
    
    def manually_trigger_scan(self, schedule_id: str) -> Dict:
        """Manually trigger a scheduled scan"""
        result = {'success': False, 'message': ''}
        
        schedule = next((s for s in self.schedules if s['schedule_id'] == schedule_id), None)
        
        if not schedule:
            result['message'] = "Schedule not found"
            return result
        
        try:
            if self.scan_callback:
                self.scan_callback(schedule)
                schedule['run_count'] += 1
                schedule['last_run'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.save_schedules()
                
                result['success'] = True
                result['message'] = f"Scan triggered: {schedule['name']}"
            else:
                result['message'] = "Scan callback not set"
                
        except Exception as e:
            result['message'] = f"Error triggering scan: {str(e)}"
        
        return result

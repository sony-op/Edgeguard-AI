# EdgeGuard AI - file_guard.py
# Watchdog-based file monitoring and simple backup-restore (ransomware rollback simulation)
# Comments: Hindi (Latin) + English mix for clarity

import time, os, shutil, datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Thresholds
MODIFICATION_THRESHOLD = 15      # number of modifications within window considered suspicious
MOD_WINDOW_SECONDS = 6          # sliding window time for modifications

class GuardEventHandler(FileSystemEventHandler):
    def __init__(self, backup_dir, secure_dir, alert_fn, restore_fn):
        self.backup_dir = backup_dir
        self.secure_dir = secure_dir
        self.alert_fn = alert_fn
        self.restore_fn = restore_fn
        self.mod_times = []

    def _record_mod(self, path):
        now = time.time()
        self.mod_times.append(now)
        # prune old
        cutoff = now - MOD_WINDOW_SECONDS
        self.mod_times = [t for t in self.mod_times if t >= cutoff]
        if len(self.mod_times) >= MODIFICATION_THRESHOLD:
            # suspicious rapid modifications => possible ransomware
            self.alert_fn('ALERT', f'Potential ransomware activity detected in {self.secure_dir} (rapid file changes). Initiating restore.')
            # perform restore from backup
            self.restore_fn()

    def on_modified(self, event):
        if event.is_directory:
            return
        self._record_mod(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._record_mod(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._record_mod(event.dest_path)

def restore_from_backup(backup_dir, secure_dir, alert_fn):
    """
    Copy files from backup_dir to secure_dir, preserving structure.
    This is a simple rollback strategy: overwrite files in secure_dir with backups.
    """
    try:
        if not os.path.exists(backup_dir):
            alert_fn('WARN', f'Backup directory not found: {backup_dir} — cannot restore.')
            return
        # Walk backup_dir
        for root, dirs, files in os.walk(backup_dir):
            rel = os.path.relpath(root, backup_dir)
            target_root = os.path.join(secure_dir, rel) if rel != '.' else secure_dir
            os.makedirs(target_root, exist_ok=True)
            for f in files:
                src = os.path.join(root, f)
                dst = os.path.join(target_root, f)
                try:
                    shutil.copy2(src, dst)
                except Exception as e:
                    alert_fn('WARN', f'Failed to restore {dst}: {e}')
        alert_fn('INFO', f'Automatic restore completed from backup ({backup_dir}) to {secure_dir}.')
    except Exception as e:
        alert_fn('WARN', f'Restore operation failed: {e}')

def start_file_guard(app, db, socketio, backup_dir, secure_dir, add_log_fn):
    """
    Start a watchdog observer watching secure_dir and trigger restore when suspicious activity is detected.
    add_log_fn: function(level, message) to record events
    """
    # Ensure directories exist
    os.makedirs(backup_dir, exist_ok=True)
    os.makedirs(secure_dir, exist_ok=True)

    def socket_alert(level, message):
        add_log_fn(level, message)
        # also push an alert to frontend
        socketio.emit('fileguard_alert', {
            'time': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,
            'message': message
        })

    event_handler = GuardEventHandler(backup_dir, secure_dir, socket_alert, lambda: restore_from_backup(backup_dir, secure_dir, socket_alert))
    observer = Observer()
    observer.schedule(event_handler, path=secure_dir, recursive=True)
    observer.start()
    add_log_fn('INFO', f'FileGuard: monitoring {secure_dir} with backups at {backup_dir}')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
import time
import os
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class RansomwareHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            print(f"[ALERT] File modified: {event.src_path}")
            # Yahan hum rollback logic trigger kar sakte hain
            self.trigger_rollback(event.src_path)

    def trigger_rollback(self, filepath):
        print(f"[*] Starting Rollback for {filepath}...")
        # Note: Marathon demo ke liye hum yahan backup se file copy karne ka logic likhenge
        filename = os.path.basename(filepath)
        backup_path = os.path.join("Backup_Folder", filename)
        
        if os.path.exists(backup_path):
            shutil.copy(backup_path, filepath)
            print(f"[+] ROLLBACK SUCCESS: {filename} restored from backup!")
        else:
            print(f"[-] No backup found for {filename}")

def start_file_monitor():
    # Demo ke liye directories banayein
    os.makedirs("Secure_Folder", exist_ok=True)
    os.makedirs("Backup_Folder", exist_ok=True)
    
    # Dummy file banayein test karne ke liye
    with open("Secure_Folder/important_data.txt", "w") as f:
        f.write("Dn Infosolution - Top Secret Data")
    with open("Backup_Folder/important_data.txt", "w") as f:
        f.write("Dn Infosolution - Top Secret Data")

    print("[+] File Guard Active. Monitoring 'Secure_Folder'...")
    event_handler = RansomwareHandler()
    observer = Observer()
    observer.schedule(event_handler, path="Secure_Folder", recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_file_monitor()
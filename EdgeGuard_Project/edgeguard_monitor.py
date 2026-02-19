# EdgeGuard AI - edgeguard_monitor.py
# Process monitoring with psutil + IsolationForest anomaly detection
# Comments: Hindi (Latin) + English mix for team readability

import time, datetime
import psutil


# Minimal safe defaults
INITIAL_TRAIN_SECONDS = 6  # seconds to collect initial process snapshot for training
MONITOR_INTERVAL = 2.0     # seconds between scans
ANOMALY_SCORE_THRESHOLD = -0.25  # lower (more negative) => more anomalous (tunable)

def process_features(p):
    # Collect a numeric feature vector for a psutil.Process instance
    try:
        cpu = p.cpu_percent(interval=None)  # non-blocking when called frequently
        mem = p.memory_percent()
        threads = p.num_threads()
        try:
            open_files = len(p.open_files())
        except Exception:
            open_files = 0
        nice = p.nice() if hasattr(p, 'nice') else 0
        return [float(cpu), float(mem), float(threads), float(open_files), float(nice)]
    except Exception:
        return None

def start_edgeguard_monitor(app, db, socketio, kill_suspicious, add_log_fn, add_metric_fn):
    """
    app: Flask app (so we can push app.app_context())
    db: SQLAlchemy instance
    socketio: SocketIO instance
    kill_suspicious: boolean flag (default False) to actually kill processes
    add_log_fn: function to write logs
    add_metric_fn: function to write metrics
    """
    # Collect initial dataset to fit IsolationForest
    X = []
    proc_map = []
    start_time = time.time()
    add_log_fn('INFO', 'EdgeGuard Monitor: collecting initial process snapshot for ML model (Model training start)')
    # Warm up psutil CPU counters
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    while time.time() - start_time < INITIAL_TRAIN_SECONDS:
        for p in psutil.process_iter():
            try:
                feats = process_features(p)
                if feats:
                    X.append(feats)
                    proc_map.append(p.pid)
            except Exception:
                continue
        time.sleep(0.6)

    if len(X) < 5:
        # fallback: create a trivial dataset to avoid training failures
        X = X + [[0.0, 0.0, 1.0, 0.0, 0.0]] * (5 - len(X))

    X = X
    # Try to import sklearn's IsolationForest; if unavailable, fall back to heuristic mode
    try:
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(n_estimators=128, contamination='auto', random_state=42)
        try:
            model.fit(X)
            add_log_fn('INFO', f'EdgeGuard Monitor: IsolationForest trained on {len(X)} samples.')
        except Exception as e:
            add_log_fn('WARN', f'EdgeGuard Monitor: model training failed: {e}')
            model = None
    except Exception:
        model = None
        add_log_fn('WARN', 'IsolationForest not available — running in heuristic-only mode.')

    # Continuous monitoring loop
    add_log_fn('INFO', 'EdgeGuard Monitor: entering continuous monitoring loop.')
    while True:
        # System-level metrics (for dashboard)
        try:
            cpu_total = psutil.cpu_percent(interval=None)
            mem_total = psutil.virtual_memory().percent
            add_metric_fn(cpu_total, mem_total)
        except Exception:
            pass

        # Inspect processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                feats = process_features(proc)
                if feats is None:
                    continue
                if model is not None:
                    # sklearn expects 2D array
                    score = model.decision_function([feats])[0]  # higher -> more normal; lower -> anomalous
                    pred = model.predict([feats])[0]  # -1 anomaly, 1 normal
                    # If flagged as anomaly by model and score below threshold, raise alert
                    if pred == -1 or score < ANOMALY_SCORE_THRESHOLD:
                        msg = f"Suspicious process detected: pid={proc.pid} name={proc.name()} user={proc.info.get('username','?')} score={score:.3f}"
                        add_log_fn('ALERT', msg)
                        # emit alert via socket
                        socketio.emit('alert', {
                            'time': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                            'pid': proc.pid,
                            'name': proc.name(),
                            'score': float(score),
                            'message': msg
                        })
                        # Attempt to terminate (only if enabled)
                        if kill_suspicious:
                            try:
                                proc.terminate()
                                proc.wait(timeout=3)
                                add_log_fn('INFO', f'Process terminated by EdgeGuard: pid={proc.pid} name={proc.name()}')
                            except Exception as e:
                                add_log_fn('WARN', f'Failed to kill suspicious process pid={proc.pid}: {e}')
                else:
                    # If no model, just do lightweight heuristic checks
                    if feats[0] > 80.0 and feats[1] > 30.0:
                        msg = f"High resource process: pid={proc.pid} name={proc.name()} cpu={feats[0]:.1f}% mem={feats[1]:.1f}%"
                        add_log_fn('WARN', msg)
                        socketio.emit('alert', {'time': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), 'message': msg})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                add_log_fn('WARN', f'EdgeGuard Monitor exception: {e}')
                continue

        # Sleep before next cycle
        time.sleep(MONITOR_INTERVAL)
import psutil
import time
import os
import signal

class EdgeGuardMonitor:
    def __init__(self):
        print("[+] EdgeGuard AI - Process Monitor Initialized.")
        print("[*] Monitoring for suspicious behaviors...")
        
        # Define suspicious parent-child relationships (The "Storyline")
        # Example: Word document opening a powershell script is highly suspicious
        self.suspicious_chains = {
            "winword.exe": ["powershell.exe", "cmd.exe"],
            "excel.exe": ["powershell.exe", "cmd.exe"],
            "chrome.exe": ["cmd.exe"] # Chrome generally shouldn't spawn cmd
        }

    def kill_process(self, proc, reason):
        """
        Malicious process ko force kill karne ka logic.
        """
        try:
            pid = proc.pid
            name = proc.name()
            # Windows aur Linux ke liye alag kill signals hote hain
            if os.name == 'nt': # For Windows
                proc.kill()
            else: # For Linux/Mac
                os.kill(pid, signal.SIGKILL)
            
            print(f"\n[ALERT - DANGER] Suspicious Activity Detected!")
            print(f"[-] Reason: {reason}")
            print(f"[-] ACTION TAKEN: Process '{name}' (PID: {pid}) has been KILLED automatically.")
            
        except psutil.NoSuchProcess:
            print(f"[*] Process pehle hi terminate ho chuka hai.")
        except psutil.AccessDenied:
            print(f"[!] ERROR: Process '{name}' kill karne ka access nahi hai (Run as Administrator/Root).")

    def scan_processes(self):
        """
        System par chal rahe har process ko scan karta hai.
        """
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                # Parent process ki ID nikali
                ppid = proc.info['ppid']
                if ppid == 0 or ppid is None:
                    continue # System idle process ko ignore karo
                
                # Parent process ka object aur naam get karna
                parent_proc = psutil.Process(ppid)
                parent_name = parent_proc.name().lower()
                child_name = proc.info['name'].lower()

                # Rule Check: Agar parent name humari blacklist dictionary mein hai
                if parent_name in self.suspicious_chains:
                    # Aur child name bhi uski list mein match karta hai
                    if child_name in self.suspicious_chains[parent_name]:
                        reason = f"'{parent_name}' tried to execute '{child_name}'"
                        self.kill_process(proc, reason)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Kuch processes OS ke hote hain jinhe read karne ki permission nahi milti
                continue

    def run(self):
        """
        Continuous monitoring loop (Runs every 1 second)
        """
        try:
            while True:
                self.scan_processes()
                time.sleep(1) # CPU bachaane ke liye 1 sec ka delay
        except KeyboardInterrupt:
            print("\n[+] EdgeGuard AI Monitor stopped by user.")

if __name__ == "__main__":
    monitor = EdgeGuardMonitor()
    monitor.run()

# EdgeGuard AI - app.py
# Senior Cybersecurity Architect style: main Flask app, DB models, SocketIO, background threads
# Comments: Hindi (Latin) + English mix for clarity

from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
import time, datetime, os

# local modules
from edgeguard_monitor import start_edgeguard_monitor
from file_guard import start_file_guard

# Config
DB_PATH = 'sqlite:///edgeguard.db'

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Safety flag: set True to allow the monitor to attempt to kill suspicious processes.
# Default False to avoid accidental kills during testing.
app.config['KILL_SUSPICIOUS'] = False

# Paths for file guard
app.config['SECURE_DIR'] = os.path.join(os.getcwd(), 'Secure_Folder')
app.config['BACKUP_DIR'] = os.path.join(os.getcwd(), 'Backup_Folder')

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# -------------------------
# Database models
# -------------------------
class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    level = db.Column(db.String(16))  # INFO / WARN / ALERT
    message = db.Column(db.Text)

class SystemMetric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    cpu_percent = db.Column(db.Float)
    mem_percent = db.Column(db.Float)

# -------------------------
# Helper utilities
# -------------------------
def add_log(level, message):
    # DB write must be inside app context when called from threads
    with app.app_context():
        log = SystemLog(level=level, message=message)
        db.session.add(log)
        db.session.commit()
        # emit to frontend
        socketio.emit('log', {
            'time': log.time.strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,
            'message': message
        })

def add_metric(cpu, mem):
    with app.app_context():
        metric = SystemMetric(cpu_percent=cpu, mem_percent=mem)
        db.session.add(metric)
        db.session.commit()
        socketio.emit('metric', {
            'time': metric.time.strftime('%Y-%m-%d %H:%M:%S'),
            'cpu_percent': cpu,
            'mem_percent': mem
        })

# -------------------------
# Routes
# -------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/logs')
def api_logs():
    # Return latest 200 logs
    logs = SystemLog.query.order_by(SystemLog.time.desc()).limit(200).all()
    return jsonify([{
        'time': l.time.strftime('%Y-%m-%d %H:%M:%S'),
        'level': l.level,
        'message': l.message
    } for l in logs])

@app.route('/api/metrics')
def api_metrics():
    # Return latest 200 metrics (for graphing)
    metrics = SystemMetric.query.order_by(SystemMetric.time.desc()).limit(200).all()
    return jsonify([{
        'time': m.time.strftime('%Y-%m-%d %H:%M:%S'),
        'cpu_percent': m.cpu_percent,
        'mem_percent': m.mem_percent
    } for m in metrics])

# -------------------------
# Startup: DB create and background services
# -------------------------
def start_background_services():
    # Start edgeguard process monitor as background task
    socketio.start_background_task(start_edgeguard_monitor, app, db, socketio, app.config['KILL_SUSPICIOUS'], add_log, add_metric)
    # Start file guard (watchdog) as background task
    socketio.start_background_task(start_file_guard, app, db, socketio, app.config['BACKUP_DIR'], app.config['SECURE_DIR'], add_log)

if __name__ == '__main__':
    # Initialize DB
    with app.app_context():
        db.create_all()
    add_log('INFO', 'EdgeGuard AI service starting - initializing components (Service start)')
    # start background services and run SocketIO
    start_background_services()
    # Using eventlet for WebSocket support and background threads
    socketio.run(app, host='0.0.0.0', port=5000)
    
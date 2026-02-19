# Dn AI Shield - Advanced Malwarebytes-Style Security Suite

A comprehensive AI-powered antivirus and security enhancement system featuring enterprise-grade threat detection, advanced quarantine management, real-time file monitoring, and more.

## 🚀 New Malwarebytes-Style Features

### 1. **Advanced Threat Detection System** 🔍
**File:** `advanced_threat_detector.py`

Multi-layer threat detection engine that uses:
- **Hash-Based Detection**: SHA256 hash comparison against known malware database
- **Signature-Based Detection**: Pattern matching for known threat signatures
- **Behavioral Analysis**:
  - Encryption pattern detection (high entropy analysis)
  - File size anomaly detection
  - Hidden attribute detection (masqueraded extensions)
  - Suspicious permissions analysis
- **AI Model Detection**: Machine learning-based classification
- **Risk Scoring**: Comprehensive confidence rating system

**Risk Levels:**
- 🔴 **CRITICAL** (>75%): Immediate quarantine required
- 🟠 **HIGH** (60-75%): Quarantine recommended
- 🟡 **MEDIUM** (40-60%): Monitor closely
- 🟢 **LOW** (20-40%): Under observation
- ✅ **SAFE** (<20%): Clean

### 2. **Real-Time File Monitoring** 📡
**File:** `realtime_monitor.py`

Real-time file system monitoring with:
- **Baseline Creation**: Establishes file baseline for comparison
- **Change Detection**: Identifies file modifications in real-time
- **Suspicious Activity Detection**:
  - New files created
  - Existing file modifications
  - Sudden file size increases
  - File deletions
  - Hash changes
- **Background Monitoring**: Runs as independent thread
- **Activity Alerts**: Categorized by threat level

**Features:**
- Create file baseline at folder level
- Monitor Windows folder for suspicious activities
- Background thread operation
- Alert history tracking
- Activity summary statistics

### 3. **Advanced Quarantine Management** 🛡️
**File:** `quarantine_manager.py`

Professional-grade quarantine system with:
- **Secure Isolation**: Files moved to isolated quarantine directory
- **Metadata Tracking**: Complete information about quarantined files
- **Restore Functionality**: Recover files if needed
- **Permanent Deletion**: Secure file removal
- **Batch Operations**: Manage multiple files at once
- **Statistics Tracking**:
  - Total quarantined items
  - Total size occupied
  - Threat breakdown
  - Age of items (oldest/newest)
- **Auto-Cleanup**: Remove items older than X days
- **Report Export**: JSON reports of quarantine status

**Features:**
- Metadata JSON database (`quarantine_db.json`)
- File size and hash tracking
- Quarantine date and reason logging
- Risk score preservation
- Status tracking (ISOLATED/RESTORED)
- Batch quarantine operations

### 4. **Scan Scheduler** 📅
**File:** `scan_scheduler.py`

Schedule automated scans at specific times:
- **Custom Schedules**: Multiple named schedules
- **Day Selection**: Choose specific days of the week
- **Time Configuration**: Set exact scan times
- **Scan Types**: Choose between quick or full scans
- **Auto-Quarantine**: Auto-handle threats in scheduled scans
- **Statistics**:
  - Total runs tracking
  - Last run timestamp
  - Next scheduled run
  - Run count per schedule
- **Manual Trigger**: Execute scheduled scans on-demand
- **Enable/Disable**: Toggle schedules on/off

**Features:**
- Persistent schedule storage (`scan_schedules.json`)
- Background scheduler thread
- Callback system for scan execution
- Next run calculation
- Schedule statistics and reporting

### 5. **Notification Management System** 🔔
**File:** `notification_manager.py`

Comprehensive notification and alert system:
- **Threat Notifications**: Threat detection alerts
- **Scan Notifications**: Scan completion status
- **Quarantine Notifications**: File isolation alerts
- **Protection Notifications**: Status changes
- **Severity Levels**:
  - 🔴 CRITICAL
  - 🟠 HIGH
  - 🟡 MEDIUM
  - 🟢 LOW
  - ℹ️ INFO

**Features:**
- Read/unread status tracking
- Action-required flag
- Notification filtering by level and type
- Automatic cleanup (delete old notifications)
- Per-notification data payloads
- Summary statistics
- JSON persistence (`notifications.json`)

## 📊 Dashboard Features

### Real-Time Protection Status
- 🌐 Web Protection
- 🦠 Malware Protection
- 🔒 Ransomware Protection
- ⚙️ Exploit Protection

### Key Metrics
- Quick scan capability
- Threat detection summary
- System health overview
- Protection status

## 🔍 Scanner Enhancements

### Advanced Scanning
- **Multi-layer detection**: Uses all detection methods simultaneously
- **Detailed threat analysis**: Comprehensive examination of suspicious files
- **Progress tracking**: Real-time scan progress display
- **Auto-quarantine**: Automatically isolate detected threats
- **Exclusions**: Skip specified files/patterns

### Scan Configuration
- Quick Scan (Downloads folder)
- Custom Folder Scan
- Auto-scan with configurable interval
- Auto-quarantine threats option

## 📁 Quarantine Management

### Advanced Features
- View detailed quarantine statistics
- Manage individual items
- Restore files with single click
- Permanent deletion option
- Batch restore operations
- Batch clear entire quarantine
- Export quarantine reports

## 📈 Advanced Reports

### Scan Analysis
- Scan history with threat breakdown
- Detailed threat information
- Detection methods used
- Risk scores and confidence ratings
- Threat type statistics
- Multi-layer detection results

## 🔴 Real-Time Monitor

### File Activity Monitoring
- Create baseline for monitored folders
- Track file modifications in real-time
- Detect new file creation
- Alert on suspicious size changes
- Monitor file deletions
- Activity-based alert summary

## 📅 Scheduler Management

### Schedule Management
- Create multiple named schedules
- Set days and times
- Choose scan types
- Enable/disable schedules
- View upcoming scans
- Manual execution
- Track schedule statistics

## ⚙️ Advanced Settings

### Protection Layers
- Toggle individual protection types
- Real-time status display

### System Health
- View threat statistics
- Monitor quarantine status
- Database integrity check
- Clear old logs
- Clean stale quarantine items

## 📦 Project Structure

```
Dn_AI_Shield/
├── Dn_Antivirus.py              # Main Streamlit app
├── advanced_threat_detector.py  # Multi-layer threat detection
├── realtime_monitor.py          # Real-time file monitoring
├── quarantine_manager.py        # Advanced quarantine management
├── scan_scheduler.py            # Scheduled scanning system
├── notification_manager.py      # Notification system
├── backend_server.py            # Flask backend (existing)
├── train_antivirus.py           # AI model training (existing)
├── manifest.json                # Chrome Extension manifest
├── popup.html/popup.js          # Extension UI
└── background.js                # Extension background script
```

## 🗂️ Data Storage

### Persistent Storage Files
- `quarantine_db.json`: Quarantine item metadata
- `scan_schedules.json`: Scheduler configuration
- `notifications.json`: Notification history
- `av_model.pkl`: AI model
- `av_scaler.pkl`: Feature scaler
- `scanned_urls.csv`: Scanned URL log
- `threat_database.json`: Known malware signatures

## 🔧 Installation & Setup

### Prerequisites
```bash
pip install streamlit pandas joblib scikit-learn numpy
```

### Run the Application
```bash
streamlit run Dn_Antivirus.py
```

### Train AI Model
```bash
python train_antivirus.py
```

### Start Backend Server
```bash
python backend_server.py
```

## 🎯 Key Capabilities

### Detection Methods
✅ Hash-based detection (SHA256)
✅ Signature pattern matching
✅ Encryption detection
✅ File size anomalies
✅ Hidden attribute detection
✅ AI model classification
✅ Behavioral analysis

### Protection Layers
✅ Web protection
✅ Malware protection
✅ Ransomware protection
✅ Exploit protection

### Management Features
✅ Threat quarantine
✅ File restoration
✅ Auto-cleanup old items
✅ Batch operations
✅ Report generation
✅ Schedule management
✅ Real-time monitoring

## 🚀 Usage Examples

### Basic Scanning
1. Navigate to Scanner tab
2. Choose scan type (Quick or Custom)
3. Enable auto-quarantine if needed
4. Click "START SCAN"

### Scheduled Scanning
1. Go to Scan Scheduler tab
2. Create new schedule
3. Select days and time
4. Choose scan type
5. Enable/disable as needed

### Real-Time Monitoring
1. Open Real-Time Monitor tab
2. Select folder to monitor
3. Click "Start Monitoring"
4. View alerts in real-time

### Threat Management
1. View Quarantine section
2. Select quarantined file
3. Restore, delete, or view details
4. Export report if needed

## 📊 Threat Risk Scoring

**Risk Score Calculation:**
- Hash match: +1.0 (if known malware)
- Signature detection: +0.15 per match
- High entropy: +0.85
- Compression artifacts: +0.65
- File size anomaly: +0.55
- Hidden attributes: +0.40
- Double extension: +0.35
- AI model confidence: +variable

**Final Score:** Average of all detections × number of detection methods

## 🎨 UI Features

- Dark theme compatible
- Responsive layout
- Color-coded threat levels
- Real-time progress bars
- Interactive data tables
- Expandable details
- Button quick actions

## 🔐 Security Considerations

- Files quarantined with original path preservation
- SHA256 hashing for integrity
- Metadata tracking for audit trail
- JSON persistence for reliability
- Automatic old data cleanup
- Risk score confidence rating

## 🤝 Integration

### Chrome Extension
Connected backend server for URL scanning
PDF manifest for extension configuration

### AI Model
Uses pre-trained RandomForest classifier
Feature scaling with StandardScaler
Entropy calculation for file analysis

## 📝 Notes

- Quartine directory: `~/.dn_security/quarantine/`
- All data stored locally for privacy
- No cloud dependencies
- Configurable retention policies
- Extensible architecture

## 🎚️ Performance

- Efficient file hashing with 4KB blocks
- Background thread operations
- Streamlined database lookups
- Minimal memory footprint
- Fast threat detection pipeline

---

**Dn AI Shield** - Comprehensive Security with Malwarebytes-Level Features ✨

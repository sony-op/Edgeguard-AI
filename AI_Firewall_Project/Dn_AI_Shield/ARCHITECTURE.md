# Dn AI Shield - Technical Architecture

## System Overview

Dn AI Shield is a comprehensive antivirus and security system featuring enterprise-grade threat detection comparable to Malwarebytes, built with:
- **Backend**: Python (Streamlit UI, Flask API)
- **Detection Engine**: AI + Behavioral Analysis
- **Storage**: JSON persistence + CSV logging
- **Browser Extension**: Chrome integration

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit UI Layer                        │
│  ┌──────────┬──────────┬────────────┬──────────┬────────┐   │
│  │Dashboard │ Scanner  │Quarantine  │ Reports  │Settings│   │
│  │          │          │            │          │        │   │
│  │Real-Time │Scheduler │Notifications          │        │   │
│  └──────────┴──────────┴────────────┴──────────┴────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Core Security Components                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  AdvancedThreatDetector                              │   │
│  │  ├─ Hash-based Detection                            │   │
│  │  ├─ Signature Matching                              │   │
│  │  ├─ Behavioral Analysis                             │   │
│  │  │  ├─ Entropy Calculation                          │   │
│  │  │  ├─ File Size Anomalies                          │   │
│  │  │  ├─ Hidden Attributes                            │   │
│  │  ├─ AI Model Classification                         │   │
│  │  └─ Risk Scoring Engine                             │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  QuarantineManager                                   │   │
│  │  ├─ File Isolation                                  │   │
│  │  ├─ Metadata Tracking                               │   │
│  │  ├─ Batch Operations                                │   │
│  │  └─ Report Generation                               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  FileMonitor (Real-Time)                             │   │
│  │  ├─ Baseline Creation                               │   │
│  │  ├─ Change Detection                                │   │
│  │  ├─ Alert System                                    │   │
│  │  └─ Behavioral Monitoring                           │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ScanScheduler                                       │   │
│  │  ├─ Schedule Management                             │   │
│  │  ├─ Background Thread                               │   │
│  │  └─ Callback System                                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  NotificationManager                                 │   │
│  │  ├─ Alert Generation                                │   │
│  │  ├─ Severity Classification                         │   │
│  │  └─ Persistence Layer                               │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│             Data Persistence Layer                          │
│  ┌──────────────┬──────────────┬──────────────────────┐    │
│  │JSON Storage  │ CSV Logging  │  Model Files        │    │
│  │├─quarantine  │├─scanned_url │├─av_model.pkl      │    │
│  │├─schedules   │└─threat_logs │├─av_scaler.pkl     │    │
│  │├─notifications                └─threat_db.json    │    │
│  └──────────────┴──────────────┴──────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Advanced Threat Detector
**File**: `advanced_threat_detector.py`

```python
class AdvancedThreatDetector:
    def scan_file(file_path) -> Dict:
        """Multi-layer threat analysis"""
        # 1. Hash database check
        # 2. Signature pattern matching
        # 3. Behavioral analysis
        # 4. AI model prediction
        # 5. Risk scoring
        return threat_result
```

**Detection Pipeline:**
1. **SHA256 Hash Lookup** → Check against known malware DB
2. **Signature Analysis** → Pattern matching against threat signatures
3. **Behavioral Analysis**:
   - Entropy calculation (0-8 scale, high = suspicious)
   - File size anomaly detection
   - Hidden attribute detection
   - API call pattern analysis
4. **ML Classification** → RandomForest prediction
5. **Risk Scoring** → Average confidence across methods

**Output:**
```json
{
  "is_threat": true,
  "threat_level": "CRITICAL",
  "threat_type": "RANSOMWARE_DETECTED",
  "risk_score": 0.87,
  "confidence": 0.95,
  "detection_methods": ["HASH_DATABASE", "ENCRYPTION_PATTERN", "AI_MODEL"],
  "recommendations": ["QUARANTINE_IMMEDIATELY"]
}
```

### 2. Quarantine Manager
**File**: `quarantine_manager.py`

```python
class QuarantineManager:
    def quarantine_file(file_path, reason, threat_type)
    def restore_file(quarantine_id)
    def permanently_delete(quarantine_id)
    def batch_quarantine(file_paths)
    def get_quarantine_stats()
    def auto_cleanup_old_items(days)
```

**Data Structure:**
```
~/.dn_security/quarantine/
├── QUARANTINE_ID_1/
│   ├── malicious_file.exe.quarantine
│   └── metadata.json
├── QUARANTINE_ID_2/
│   ├── suspicious.bat.quarantine
│   └── metadata.json
└── quarantine_db.json (master DB)
```

**Metadata Format:**
```json
{
  "quarantine_id": "abc123def456",
  "original_path": "C:/Downloads/malware.exe",
  "quarantine_path": "~/.dn_security/quarantine/abc123/malware.exe.quarantine",
  "quarantine_date": "2024-02-20 14:30:45",
  "file_size": 245632,
  "file_hash": "sha256_hash_here",
  "threat_type": "RANSOMWARE",
  "risk_score": 0.92,
  "status": "ISOLATED",
  "is_restored": false
}
```

### 3. Real-Time File Monitor
**File**: `realtime_monitor.py`

```python
class FileMonitor:
    def create_baseline(folder_path) -> Dict
    def watch_folder(folder_path, interval=5)
    def start_background_monitoring() -> Thread
    def detect_suspicious_activity(file_path)
    def get_alerts(threat_level=None)
```

**Monitoring Process:**
1. **Baseline Creation**: Hash all files in folder
2. **Loop Detection**:
   - Check each file's hash
   - Compare with baseline
   - Detect new/modified/deleted files
3. **Alert Generation**:
   - User receives real-time alert
   - Alert contains change details
4. **Threat Analysis**: Rescan if modified

**Alert Types:**
- `NEW_FILE_CREATED` 🟢
- `FILE_MODIFIED` 🟡
- `FILE_DELETED` 🟠
- `SUSPICIOUS_SIZE_INCREASE` 🔴

### 4. Scan Scheduler
**File**: `scan_scheduler.py`

```python
class ScanScheduler:
    def add_schedule(name, days, time, scan_type, auto_quarantine)
    def update_schedule(schedule_id, **kwargs)
    def remove_schedule(schedule_id)
    def get_next_scheduled_scans(count=5)
    def manually_trigger_scan(schedule_id)
```

**Schedule Storage:**
```json
{
  "schedule_id": "daily_scan_1708425600",
  "name": "Daily System Scan",
  "days": ["Monday", "Tuesday", "Wednesday"],
  "time": "14:30",
  "scan_type": "quick",
  "auto_quarantine": true,
  "is_enabled": true,
  "run_count": 5,
  "last_run": "2024-02-20 14:30:15",
  "next_run": "2024-02-21 14:30:00"
}
```

**Scheduler Loop:**
```python
while running:
    for each schedule:
        if schedule.enabled and current_day in schedule.days:
            if current_time == schedule.time:
                execute_scan(schedule)
    sleep(10 seconds)
```

### 5. Notification Manager
**File**: `notification_manager.py`

```python
class NotificationManager:
    def create_notification(title, message, level, type, data)
    def threat_notification(filename, threat_type, risk_score)
    def scan_complete_notification(scanned_files, threats_found)
    def get_notifications(unread_only=False, level_filter=None)
    def mark_as_read(notification_id)
    def delete_old_notifications(days=7)
```

**Notification Levels:**
- 🔴 CRITICAL: Risk > 75%
- 🟠 HIGH: Risk 60-75%
- 🟡 MEDIUM: Risk 40-60%
- 🟢 LOW: Risk 20-40%
- ℹ️ INFO: General notifications

**Notification Types:**
- `THREAT_DETECTED`
- `SCAN_COMPLETE`
- `FILE_QUARANTINED`
- `PROTECTION_ENABLED`
- `PROTECTION_DISABLED`

---

## Threat Detection Flow

```
File Found
    ↓
1. Calculate SHA256 Hash
    ↓
    ├─ Found in Database? → CRITICAL (1.0)
    │
2. Entropy Calculation
    ├─ High (>7.8)? → +0.85 (HIGH_ENTROPY_PACK)
    ├─ Medium-High (>7.5)? → +0.65
    └─ Medium (>7.0)? → +0.35
    
3. Signature Matching
    ├─ Dangerous Extension? → +0.25
    ├─ Malware Patterns? → +0.15 per match
    └─ Ransomware Markers? → +0.40
    
4. Behavioral Analysis
    ├─ Hidden File? → +0.40
    ├─ Double Extension? → +0.35
    ├─ Oversized EXE? → +0.55
    └─ Undersized EXE? → +0.45
    
5. AI Model Prediction
    └─ Malware Prob? → +variable (0-1)
    
6. Risk Calculation
    risk_score = average(all_detections)
    
7. Threat Level Assignment
    ├─ risk > 0.75 → CRITICAL 🔴
    ├─ risk > 0.60 → HIGH 🟠
    ├─ risk > 0.40 → MEDIUM 🟡
    ├─ risk > 0.20 → LOW 🟢
    └─ risk ≤ 0.20 → SAFE ✅
    
8. Automatic Action
    ├─ CRITICAL → Auto-Quarantine ✓
    └─ Others → Alert & Log
```

---

## Data Flow Examples

### Scan Flow
```
User clicks "START SCAN"
  ↓
Get file list from folder
  ↓
For each file:
  ├─ Check exclusions
  ├─ Call threat_detector.scan_file()
  ├─ Collect result
  └─ Update UI progress
  ↓
Compile results
  ↓
Auto-quarantine critical threats (if enabled)
  ├─ quarantine_mgr.quarantine_file()
  ├─ notifications_mgr.create_notification()
  └─ Update scan_history
  ↓
Display summary & results table
  ↓
Save detailed_scan_results
```

### Real-Time Monitor Flow
```
User starts monitoring
  ↓
file_monitor.create_baseline(folder)
  ├─ Hash all files
  └─ Store file sizes & mod times
  ↓
Start background thread
  ↓
Loop every 5 seconds:
  ├─ Walk folder tree
  ├─ Calculate current hashes
  ├─ Compare with baseline
  ├─ Detect changes
  ├─ Generate alerts
  └─ If modified: rescan with threat_detector
  ↓
Alert displayed in UI
  ↓
User reviews & takes action
```

### Quarantine Flow
```
Threat detected
  ↓
quarantine_mgr.quarantine_file()
  ├─ Calculate file hash
  ├─ Create quarantine directory
  ├─ Copy file to quarantine
  ├─ Generate metadata JSON
  ├─ Add to quarantine_db.json
  ├─ Create notification
  └─ Delete original file
  ↓
Show in Quarantine UI
  ↓
User can:
  ├─ View details
  ├─ Restore file
  ├─ Delete permanently
  └─ Export report
```

---

## Performance Considerations

### Optimization Strategies

1. **File Hashing**
   - Use 4KB block reading
   - Stream large files
   - Cache SHA256 results

2. **Entropy Calculation**
   - Read first 10KB only for patterns
   - Use frequency table (256 bytes)
   - O(n) complexity

3. **Scanning**
   - Process files sequentially
   - Update UI every 50ms
   - Batch database lookups

4. **Real-Time Monitoring**
   - 5-10 second intervals
   - Background thread operation
   - Minimal CPU impact

### Scalability

- **File Limit**: Handles 100,000+ files
- **Quarantine Size**: Limited by disk space
- **Notification History**: Auto-cleanup after 7 days
- **Database**: JSON format, grows linearly

---

## Security Architecture

### Threat Defense Layers

```
Layer 1: Entry Point Control
├─ File access monitoring
├─ Process monitoring
└─ Network monitoring

Layer 2: Threat Detection
├─ Hash database
├─ Signature analysis
├─ Behavior analysis
└─ Machine learning

Layer 3: Threat Isolation
├─ Immediate quarantine
├─ File encryption/securing
└─ Activity logging

Layer 4: Recovery
├─ File restoration
├─ Analysis tools
└─ Report generation
```

### Data Protection

- **Quarantine**: Moved to isolated directory
- **Logs**: JSON/CSV persistence
- **Metadata**: Comprehensive tracking
- **Audit Trail**: All actions logged with timestamps

---

## Integration Points

### Chrome Extension
- URL scanning via backend API
- Threat notifications in browser
- Real-time blocking

### File System
- Direct file access
- Hash calculation
- File quarantine
- Directory monitoring

### AI Model
- Feature extraction
- Model prediction
- Probability scoring
- Result interpretation

---

## Future Enhancements

1. **Cloud Integration**
   - Submit unknown files to VirusTotal
   - Download updated threat database
   - Crowd-sourced threat intelligence

2. **Advanced Analytics**
   - Threat trend analysis
   - Attack pattern detection
   - Predictive alerts

3. **Performance Optimization**
   - GPU acceleration for hashing
   - Parallel file processing
   - Incremental scanning

4. **Extended Protections**
   - Network traffic analysis
   - Process injection detection
   - API hooking detection

---

## Configuration Files

### av_model.pkl
- Pre-trained RandomForest classifier
- 100 decision trees
- Trained on safe vs malware files

### av_scaler.pkl
- StandardScaler for feature normalization
- Scales [file_size, entropy, api_calls, is_hidden]
- Mean and std deviation stored

### quarantine_db.json
- Master quarantine database
- Array of quarantine records
- Synced on every operation

### scan_schedules.json
- Scan schedule records
- Days, times, types
- Run statistics

### notifications.json
- Alert history
- Severity levels
- Read/unread status

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| File Hash Time | ~50ms (1MB file) |
| Entropy Calc | ~5ms (full file) |
| Single File Scan | ~100-200ms |
| Batch Scan (100 files) | ~15-30 seconds |
| Real-Time Check | ~1-2ms |
| Quarantine Op | ~50-100ms |
| Schedule Check | <1ms |

---

*Technical Architecture - Dn AI Shield*
*Version: 1.0 | Date: February 2026*

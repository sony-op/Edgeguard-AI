# Dn AI Shield - Quick Start Guide

## 🎯 Getting Started

### Installation
```bash
# Install dependencies
pip install streamlit pandas joblib scikit-learn numpy

# Optional: For enhanced UI
pip install plotly
```

### Launch Application
```bash
streamlit run Dn_Antivirus.py
```

The dashboard will open in your browser at `http://localhost:8501`

---

## 📋 Feature Overview

### 1️⃣ Dashboard
**Your security overview at a glance**
- Real-time protection status for 4 layers
- Quick scan button
- System protection status
- All protections must be enabled for full coverage

### 2️⃣ Scanner
**Find and isolate threats**

**Quick Start:**
1. Select scan type (Quick or Custom)
2. For custom scans, enter folder path
3. Toggle "Auto-Quarantine Threats" (recommended: ON)
4. Click "🚀 START SCAN"

**What it does:**
- Analyzes files with 6 detection methods
- Shows risk level for each file
- Auto-quarantines critical threats
- Creates scan history

**Understanding Results:**
- 🔴 CRITICAL: Immediate action needed
- 🟠 HIGH: Quarantine recommended  
- 🟡 MEDIUM: Monitor closely
- 🟢 SAFE: No threats detected

### 3️⃣ Quarantine
**Where threats are safely locked away**

**To restore/delete a file:**
1. Select file from list
2. Click "♻️ Restore" or "🗑️ Delete"
3. Or use batch operations

**Statistics show:**
- Total quarantined items
- Storage used
- When oldest/newest items were added

### 4️⃣ Real-Time Monitor
**Watch your system for suspicious activity**

**To set up monitoring:**
1. Enter folder path to monitor
2. Adjust check interval (1-30 seconds)
3. Click "▶️ Start Monitoring"
4. View alerts as they happen

**Alerts include:**
- New files created
- Files modified
- Suspicious size changes
- File deletions

### 5️⃣ Scan Scheduler
**Automate your protection**

**Create a schedule:**
1. Go to "Add Schedule" tab
2. Name your schedule
3. Pick days (Mon-Sun)
4. Set scan time
5. Choose quick or full scan
6. Toggle auto-quarantine
7. Click "➕ Add Schedule"

**Examples:**
- Weekly full scan every Sunday at 2 AM
- Daily quick scan Monday-Friday at 6 PM
- Nightly scans during off-hours

### 6️⃣ Notifications
**Stay informed of threats**

**View Types:**
- **All Notifications**: Complete history
- **Unread Only**: Action items
- **Statistics**: Summary dashboard

**Actions:**
- Mark notifications as read
- Filter by level (Critical, High, etc.)
- Clear old notifications

### 7️⃣ Reports
**Detailed threat analysis**

**Two views:**
- **Scan History**: Log of all scans performed
- **Detailed Threats**: Deep dive into detected threats

**For each threat, see:**
- Threat type identified
- Risk score (percentage)
- Detection methods used
- Recommended actions

### 8️⃣ Settings
**Fine-tune your security**

**Exclusions:**
- Add filenames to skip scanning
- One per line (e.g., `game_mod.exe`)
- Useful for known-safe files

**Protection Layers:**
- Toggle individual protections
- Recommended: Keep all enabled
- Shows activation status

**System Health:**
- View threat statistics
- Check quarantine status
- Maintenance options:
  - Clear old logs
  - Clean old quarantine
  - Export data

---

## 🎓 Understanding Threat Levels

### CRITICAL 🔴
- **Risk Score**: > 75%
- **What it means**: Definitely malware
- **Action**: Automatically quarantined
- **Examples**: Known ransomware, trojan

### HIGH 🟠  
- **Risk Score**: 60-75%
- **What it means**: Very likely malware
- **Action**: Recommended to quarantine
- **Examples**: Suspicious executables, encrypted files

### MEDIUM 🟡
- **Risk Score**: 40-60%
- **What it means**: Suspicious, needs monitoring
- **Action**: Keep watching
- **Examples**: Unusual file patterns, suspicious names

### LOW 🟢
- **Risk Score**: 20-40%
- **What it means**: Somewhat suspicious
- **Action**: Just monitor
- **Examples**: Packed/compressed files

### SAFE ✅
- **Risk Score**: < 20%
- **What it means**: Clean, no threats detected
- **Action**: None needed
- **Examples**: Known safe files

---

## 🚨 Emergency Actions

### If Malware is Detected
1. ✅ **Don't panic** - System automatically handles critical threats
2. ✅ **Check Quarantine** - See what was isolated
3. ✅ **Review details** - Understand what was detected
4. ✅ **Report** - Export data for analysis

### If Suspicious Activity is Detected
1. ✅ **Check Real-Time Alerts** - See what file was modified
2. ✅ **Review changes** - Understand what changed
3. ✅ **Quarantine if needed** - Remove if suspicious

### If System Feels Slow
1. ✅ **Enable Auto-Cleanup** - Remove old quarantine
2. ✅ **Clear notifications** - Clean old alerts
3. ✅ **Schedule off-peak scans** - Don't scan during work

---

## 💡 Pro Tips

### Security Best Practices
- ✅ Run weekly full scans
- ✅ Schedule scans during off-hours
- ✅ Monitor Downloads folder in real-time
- ✅ Keep all protections enabled
- ✅ Review quarantine monthly

### Performance Tips
- 📊 Quick scans for daily use (faster)
- 📊 Full scans weekly (comprehensive)
- 📊 Monitor only critical folders
- 📊 Auto-cleanup old items after 30 days
- 📊 Review logs quarterly

### Troubleshooting
- ❓ **Slow scanning**: Reduce file count or run at off-hours
- ❓ **False positives**: Add to exclusions if safe
- ❓ **Missing files**: Check quarantine
- ❓ **No alerts**: Ensure monitoring is started

---

## 🗂️ File Locations

```
~/.dn_security/
├── quarantine/              # Isolated threat files
│   ├── [quarantine_id]/
│   │   ├── [file].quarantine
│   │   └── metadata.json
│   └── quarantine_db.json   # Master database
├── notifications.json       # Alert history
└── scan_schedules.json      # Schedule config
```

Current folder: `Dn_AI_Shield/`
```
├── av_model.pkl            # AI model
├── av_scaler.pkl           # Feature scaler  
├── scan_schedules.json     # Schedules
├── notifications.json      # Notifications
└── scanned_urls.csv        # URL log
```

---

## 🔧 Customization

### Adjust AI Sensitivity
Edit thresholds in `advanced_threat_detector.py`:
```python
if avg_threat_score > 0.75:  # Change this value
    result['threat_level'] = 'CRITICAL'
```

### Change Quarantine Location
In `quarantine_manager.py`:
```python
quarantine_root = "C:/path/to/quarantine"  # Your path
```

### Modify Detection Methods
In `advanced_threat_detector.py`, adjust:
- Entropy threshold
- File size limits
- API call thresholds
- Hidden file penalties

---

## 📊 Reports & Analytics

### Export Quarantine Report
1. Go to Quarantine section
2. Click "📄 Export Quarantine Report"
3. JSON file saved with timestamp

### View Scan History
1. Go to Reports section
2. See table of all scans
3. Click "Detailed Threats" for deep dive

### Track Statistics
- Settings → System Health shows:
  - Total scans run
  - Threats by level
  - Quarantine statistics
  - Data trends

---

## 🆘 Support & FAQ

### "Why did my file get quarantined?"
- Check threat level and detection methods
- Review in Reports section  
- If legitimate, add to Exclusions

### "Can I restore a quarantined file?"
- Yes! Go to Quarantine section
- Select file
- Click "♻️ Restore File"
- File returns to original location

### "How often should I scan?"
- Quick scans: Daily or several times weekly
- Full scans: Weekly or as needed
- Real-time: Always on for critical folders

### "What's the difference between scan types?"
- **Quick**: Scans Downloads, common locations
- **Full**: Scans entire selected folder recursively

### "Can I exclude files from scanning?"
- Yes! Go to Settings → Exclusions
- Add filenames (one per line)
- They'll be skipped in all scans

---

## 🎉 Enjoy Complete Protection!

Your system is now protected with military-grade threat detection powered by advanced AI and behavioral analysis.

**Stay safe!** 🛡️

---

*Last Updated: February 2026*
*Dn AI Shield - Advanced Security Suite*

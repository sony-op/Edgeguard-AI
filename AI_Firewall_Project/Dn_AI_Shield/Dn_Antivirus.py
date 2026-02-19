import streamlit as st
import os
import math
import time
import pandas as pd
import joblib
import numpy as np
from datetime import datetime
import shutil

# Import advanced security modules
from advanced_threat_detector import AdvancedThreatDetector
from quarantine_manager import QuarantineManager
from realtime_monitor import FileMonitor
from scan_scheduler import ScanScheduler
from notification_manager import NotificationManager

# --- Dn Infosolution Brand Theme Setup ---
st.set_page_config(page_title="Dn Antivirus | Premium Security", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    /* Dn Infosolution Colors */
    :root {
      --color-primary-navy:    #1A2B3C;
      --color-primary-emerald: #0A3E3C;
      --color-bg-light-gray:   #F5F5F5;
      --color-func-blue:       #4A8B9D;
      --color-func-green:      #8EB998;
      --color-func-peach:      #E6A689;
    }
    .stApp { background-color: var(--color-bg-light-gray); }
    h1, h2, h3, h4 { color: var(--color-primary-navy) !important; }
    
    /* Metrics Box - Emerald Green */
    div[data-testid="metric-container"] {
        background-color: var(--color-primary-emerald); 
        color: #FFFFFF;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid var(--color-func-blue);
        box-shadow: 2px 2px 10px rgba(0,0,0,0.1);
    }
    div[data-testid="metric-container"] > div { color: #FFFFFF !important; }
    
    /* Protection Cards */
    .protection-card {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #ddd;
        text-align: center;
        margin-bottom: 15px;
        box-shadow: 2px 2px 10px rgba(0,0,0,0.05);
    }
    .status-on { color: var(--color-func-green); font-weight: bold; font-size: 1.2em;}
    .status-off { color: var(--color-func-peach); font-weight: bold; font-size: 1.2em;}
</style>
""", unsafe_allow_html=True)

# --- Initialize Session States (Malwarebytes Features) ---
if 'scan_data' not in st.session_state: st.session_state.scan_data = None
if 'quarantine_list' not in st.session_state: st.session_state.quarantine_list = []
if 'scan_history' not in st.session_state: st.session_state.scan_history = []
if 'exclusions' not in st.session_state: st.session_state.exclusions = []

# Protection Layers States
if 'prot_web' not in st.session_state: st.session_state.prot_web = True
if 'prot_malware' not in st.session_state: st.session_state.prot_malware = True
if 'prot_ransomware' not in st.session_state: st.session_state.prot_ransomware = True
if 'prot_exploit' not in st.session_state: st.session_state.prot_exploit = True

# Advanced Malwarebytes-style components
if 'threat_detector' not in st.session_state: st.session_state.threat_detector = None
if 'quarantine_manager' not in st.session_state: st.session_state.quarantine_manager = None
if 'file_monitor' not in st.session_state: st.session_state.file_monitor = None
if 'scan_scheduler' not in st.session_state: st.session_state.scan_scheduler = None
if 'notification_manager' not in st.session_state: st.session_state.notification_manager = None
if 'monitoring_active' not in st.session_state: st.session_state.monitoring_active = False
if 'detailed_scan_results' not in st.session_state: st.session_state.detailed_scan_results = []

# --- Load AI Model & Initialize Advanced Components ---
@st.cache_resource
def load_ai():
    try:
        model = joblib.load('av_model.pkl')
        scaler = joblib.load('av_scaler.pkl')
        return model, scaler, True
    except:
        return None, None, False

model, scaler, ai_ready = load_ai()

@st.cache_resource
def initialize_security_components():
    """Initialize all security components"""
    threat_detector = AdvancedThreatDetector(model, scaler)
    quarantine_mgr = QuarantineManager()
    file_monitor = FileMonitor(threat_detector)
    scan_sched = ScanScheduler()
    notif_mgr = NotificationManager()
    
    return threat_detector, quarantine_mgr, file_monitor, scan_sched, notif_mgr

# Initialize components
if st.session_state.threat_detector is None:
    components = initialize_security_components()
    st.session_state.threat_detector, st.session_state.quarantine_manager, \
    st.session_state.file_monitor, st.session_state.scan_scheduler, \
    st.session_state.notification_manager = components

def calculate_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            byteArr = list(f.read())
        fileSize = len(byteArr)
        if fileSize == 0: return 0.0
        
        freqList = [0] * 256
        for b in byteArr: freqList[b] += 1
        
        ent = 0.0
        for f in freqList:
            if f > 0:
                prob = float(f) / fileSize
                ent = ent + prob * math.log(prob, 2)
        return -ent
    except:
        return 0.0

# --- SIDEBAR NAVIGATION ---
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
st.sidebar.title("Dn Security")
nav_selection = st.sidebar.radio("Navigation", [
    "Dashboard", "Scanner", "Quarantine", "Reports", 
    "Real-Time Monitor", "Scan Scheduler", "Notifications", "Settings"
])
st.sidebar.markdown("---")

if not ai_ready:
    st.error("⚠️ AI Model not found! Please run 'train_antivirus.py' first.")
    st.stop()

# ==========================================
# 1. DASHBOARD (Real-Time Protection Status)
# ==========================================
if nav_selection == "Dashboard":
    st.title("💻 Security Dashboard")
    st.markdown("Monitor your real-time protection and system health.")
    
    # System Status Banner
    all_protected = all([st.session_state.prot_web, st.session_state.prot_malware, 
                         st.session_state.prot_ransomware, st.session_state.prot_exploit])
    if all_protected:
        st.success("✅ Awesome! You're fully protected.")
    else:
        st.warning("⚠️ Warning: One or more real-time protection layers are disabled.")

    st.markdown("### Real-Time Protection")
    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        st.markdown("<div class='protection-card'>", unsafe_allow_html=True)
        st.markdown("#### 🌐 Web Protection")
        st.session_state.prot_web = st.toggle("Web Protection", st.session_state.prot_web, key="t1", label_visibility="collapsed")
        st.markdown(f"<span class='{'status-on' if st.session_state.prot_web else 'status-off'}'>{'ON' if st.session_state.prot_web else 'OFF'}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
    with c2:
        st.markdown("<div class='protection-card'>", unsafe_allow_html=True)
        st.markdown("#### 🦠 Malware")
        st.session_state.prot_malware = st.toggle("Malware Protection", st.session_state.prot_malware, key="t2", label_visibility="collapsed")
        st.markdown(f"<span class='{'status-on' if st.session_state.prot_malware else 'status-off'}'>{'ON' if st.session_state.prot_malware else 'OFF'}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with c3:
        st.markdown("<div class='protection-card'>", unsafe_allow_html=True)
        st.markdown("#### 🔒 Ransomware")
        st.session_state.prot_ransomware = st.toggle("Ransomware Protection", st.session_state.prot_ransomware, key="t3", label_visibility="collapsed")
        st.markdown(f"<span class='{'status-on' if st.session_state.prot_ransomware else 'status-off'}'>{'ON' if st.session_state.prot_ransomware else 'OFF'}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with c4:
        st.markdown("<div class='protection-card'>", unsafe_allow_html=True)
        st.markdown("#### ⚙️ Exploit")
        st.session_state.prot_exploit = st.toggle("Exploit Protection", st.session_state.prot_exploit, key="t4", label_visibility="collapsed")
        st.markdown(f"<span class='{'status-on' if st.session_state.prot_exploit else 'status-off'}'>{'ON' if st.session_state.prot_exploit else 'OFF'}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
    st.markdown("---")
    st.markdown("### Quick Actions")
    if st.button("🔍 Run Quick Scan Now", type="primary"):
        st.info("Please navigate to the 'Scanner' tab to configure and start your scan.")

# ==========================================
# 2. SCANNER (Scanning & Auto-System)
# ==========================================
elif nav_selection == "Scanner":
    st.title("🔍 Threat Scanner")
    st.markdown("Powered by Dn Infosolution Deep Learning Engine")
    
    col_settings, col_scan = st.columns([1, 2])
    
    with col_settings:
        st.markdown("#### Scan Configuration")
        scan_type = st.radio("Scan Type", ["Quick Scan (Downloads)", "Custom Folder Scan"])
        
        folder_to_scan = ""
        if scan_type == "Custom Folder Scan":
            folder_to_scan = st.text_input("Enter folder path:", value=os.path.join(os.path.expanduser('~'), 'Desktop'))
        else:
            folder_to_scan = os.path.join(os.path.expanduser('~'), 'Downloads')
            st.info(f"Target: {folder_to_scan}")

        st.markdown("#### 🤖 Automation")
        auto_scan = st.checkbox("Enable Auto-Scan (Loop)")
        # Changed "Auto-Remove" to "Auto-Quarantine" as per Malwarebytes standard
        auto_quarantine = st.checkbox("Auto-Quarantine Threats")
        scan_interval = st.number_input("Scan Interval (Seconds)", min_value=5, value=15, step=5)
        
        start_manual_scan = st.button("🚀 START SCAN", type="primary", use_container_width=True)

    with col_scan:
        if start_manual_scan or auto_scan:
            if not os.path.exists(folder_to_scan) and folder_to_scan != "":
                st.error("❌ Folder not found! Please enter a valid path.")
            elif folder_to_scan != "":
                st.markdown("### 🔄 Advanced Threat Scanning in progress...")
                progress_bar = st.progress(0)
                status_text = st.empty()
                threat_detector = st.session_state.threat_detector
                quarantine_mgr = st.session_state.quarantine_manager
                
                files_list = []
                for root, dirs, files in os.walk(folder_to_scan):
                    for file in files:
                        files_list.append(os.path.join(root, file))
                        if len(files_list) > 100: break # Demo limit increased
                    if len(files_list) > 100: break
                    
                total_files = len(files_list)
                results = []
                critical_threats = []
                high_threats = []
                
                for i, file_path in enumerate(files_list):
                    filename = os.path.basename(file_path)
                    status_text.text(f"Analyzing: {filename}")
                    
                    # Check Exclusions
                    if filename in st.session_state.exclusions:
                        results.append({
                            "File Name": filename,
                            "Path": file_path,
                            "Size (KB)": round(os.path.getsize(file_path)/1024, 2),
                            "Status": "IGNORED ⚪",
                            "Threat Level": "N/A",
                            "Confidence": "0%"
                        })
                    elif file_path.endswith('.quarantine'):
                        results.append({
                            "File Name": filename,
                            "Path": file_path,
                            "Size (KB)": round(os.path.getsize(file_path)/1024, 2),
                            "Status": "IGNORED ⚪",
                            "Threat Level": "N/A",
                            "Confidence": "0%"
                        })
                    else:
                        # Use advanced threat detector
                        scan_result = threat_detector.scan_file(file_path)
                        st.session_state.detailed_scan_results.append(scan_result)
                        
                        if scan_result['is_threat']:
                            status = f"{scan_result['threat_type']} 🚨"
                            if scan_result['threat_level'] == 'CRITICAL':
                                critical_threats.append(file_path)
                            elif scan_result['threat_level'] == 'HIGH':
                                high_threats.append(file_path)
                        else:
                            status = "SAFE ✅"
                        
                        results.append({
                            "File Name": filename,
                            "Path": file_path,
                            "Size (KB)": round(os.path.getsize(file_path)/1024, 2),
                            "Status": status,
                            "Threat Level": scan_result['threat_level'],
                            "Confidence": f"{scan_result['confidence']*100:.1f}%"
                        })
                    
                    progress_bar.progress((i + 1) / total_files)
                    time.sleep(0.03)
                    
                status_text.text("✅ Advanced Scan Complete!")
                time.sleep(1)
                
                # Auto-Quarantine threats
                auto_quarantined_count = 0
                quarantine_threats = critical_threats if auto_quarantine else []
                if auto_quarantine and len(quarantine_threats) > 0:
                    with st.spinner(f"🛡️ Auto-quarantining {len(quarantine_threats)} threats..."):
                        for threat_path in quarantine_threats:
                            q_result = quarantine_mgr.quarantine_file(
                                threat_path, 
                                reason="AUTO_SCAN",
                                threat_type="DETECTED_THREAT"
                            )
                            if q_result['success']:
                                auto_quarantined_count += 1
                
                # Save Scan History
                scan_record = {
                    "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Scanned": total_files,
                    "Critical": len(critical_threats),
                    "High": len(high_threats),
                    "Type": scan_type
                }
                st.session_state.scan_history.append(scan_record)

                st.session_state.scan_data = {
                    "total_files": total_files,
                    "critical_count": len(critical_threats),
                    "high_count": len(high_threats),
                    "results": results,
                    "auto_quarantined": auto_quarantined_count
                }

        # Show Scan Results
        if st.session_state.scan_data is not None:
            data = st.session_state.scan_data
            st.markdown("### 📊 Advanced Scan Summary")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Scanned Files", data["total_files"])
            m2.metric("🔴 Critical Threats", data["critical_count"])
            m3.metric("🟠 High Threats", data["high_count"])
            m4.metric("Auto-Quarantined", data.get("auto_quarantined", 0))
            
            if data.get("auto_quarantined", 0) > 0:
                st.success(f"🤖 Advanced Auto-System successfully quarantined {data['auto_quarantined']} threats!")
            
            df_results = pd.DataFrame(data["results"])
            def color_threats(val):
                if 'CRITICAL' in str(val): return 'background-color: #FF4444; color: white; font-weight: bold;'
                elif 'HIGH' in str(val): return 'background-color: #FF8C00; color: white; font-weight: bold;'
                elif 'MEDIUM' in str(val): return 'background-color: #FFD700; color: black; font-weight: bold;'
                elif 'SAFE' in val: return 'background-color: #8EB998; color: #1A2B3C; font-weight: bold;'
                elif 'IGNORED' in val: return 'color: gray;'
                else: return ''
                
            st.dataframe(df_results.style.map(color_threats, subset=['Status']), use_container_width=True, height=300)

        if auto_scan:
            st.markdown("---")
            countdown_placeholder = st.empty()
            for i in range(scan_interval, 0, -1):
                countdown_placeholder.info(f"⏳ Next auto-scan in {i} seconds...")
                time.sleep(1)
            st.rerun()

# ==========================================
# 3. QUARANTINE (Isolate and Restore - Advanced Management)
# ==========================================
elif nav_selection == "Quarantine":
    st.title("🛡️ Quarantine - Advanced Threat Isolation")
    st.markdown("Threats are securely isolated here. They cannot harm your computer.")
    
    quarantine_mgr = st.session_state.quarantine_manager
    quarantined_files = quarantine_mgr.get_quarantined_files()
    
    if len(quarantined_files) == 0:
        st.info("✅ Your quarantine is empty. Your system is protected!")
    else:
        # Quarantine Statistics
        stats = quarantine_mgr.get_quarantine_stats()
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Isolated", stats['total_quarantined'])
        s2.metric("Size (MB)", stats['total_size_mb'])
        s3.metric("Oldest", stats['oldest_item'][:10] if stats['oldest_item'] else "N/A")
        s4.metric("Newest", stats['newest_item'][:10] if stats['newest_item'] else "N/A")
        
        st.markdown("---")
        st.markdown("### Quarantine Details")
        
        # Display quarantined files
        q_data = []
        for file in quarantined_files:
            q_data.append({
                "Filename": file['original_name'],
                "Original Path": file['original_path'],
                "Quarantine Date": file['quarantine_date'],
                "Threat Type": file['threat_type'],
                "Risk Score": f"{file['risk_score']*100:.1f}%",
                "Status": file['status'],
                "ID": file['quarantine_id'][:8] + "..."
            })
        
        q_df = pd.DataFrame(q_data)
        st.dataframe(q_df, use_container_width=True, height=300)
        
        st.markdown("---")
        st.markdown("### Manage Quarantined Items")
        
        selected_file_idx = st.selectbox(
            "Select a file:",
            range(len(quarantined_files)),
            format_func=lambda x: quarantined_files[x]['original_name']
        )
        
        selected_file = quarantined_files[selected_file_idx]
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("♻️ Restore File", use_container_width=True, key="restore_btn"):
                restore_result = quarantine_mgr.restore_file(selected_file['quarantine_id'])
                if restore_result['success']:
                    st.success(f"✅ {restore_result['message']}")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"❌ {restore_result['message']}")
        
        with col2:
            if st.button("🗑️ Delete Permanently", use_container_width=True, key="delete_btn"):
                delete_result = quarantine_mgr.permanently_delete(selected_file['quarantine_id'])
                if delete_result['success']:
                    st.success(f"✅ {delete_result['message']}")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"❌ {delete_result['message']}")
        
        with col3:
            if st.button("📊 View Details", use_container_width=True, key="details_btn"):
                with st.expander("File Details", expanded=True):
                    st.json(selected_file)
        
        st.markdown("---")
        st.markdown("### Batch Operations")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("♻️ Restore All", use_container_width=True):
                success_count = 0
                for file in quarantined_files:
                    if file['status'] == 'ISOLATED':
                        result = quarantine_mgr.restore_file(file['quarantine_id'])
                        if result['success']:
                            success_count += 1
                st.success(f"✅ Successfully restored {success_count} files")
                time.sleep(1)
                st.rerun()
        
        with col2:
            if st.button("🔥 Clear Entire Quarantine", use_container_width=True):
                success_count = 0
                for file in quarantined_files:
                    result = quarantine_mgr.permanently_delete(file['quarantine_id'])
                    if result['success']:
                        success_count += 1
                st.warning(f"⚠️ Permanently deleted {success_count} items")
                time.sleep(1)
                st.rerun()
        
        st.markdown("---")
        st.markdown("### Export Report")
        if st.button("📄 Export Quarantine Report", use_container_width=True):
            report_path = quarantine_mgr.export_quarantine_report()
            st.success(f"Report exported to: {report_path}")

# ==========================================
# 5. REAL-TIME MONITOR (File Monitoring)
# ==========================================
elif nav_selection == "Real-Time Monitor":
    st.title("🔴 Real-Time File Monitor")
    st.markdown("Monitor your system for suspicious file modifications in real-time")
    
    file_monitor = st.session_state.file_monitor
    
    st.markdown("### Monitor Configuration")
    monitor_folder = st.text_input("Folder to monitor:", value=os.path.join(os.path.expanduser('~'), 'Downloads'))
    monitor_interval = st.slider("Check interval (seconds)", 1, 30, 5)
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("▶️ Start Monitoring", type="primary", use_container_width=True):
            if os.path.exists(monitor_folder):
                st.session_state.monitoring_active = True
                st.success("✅ Real-time monitoring started!")
                st.info(f"Monitoring: {monitor_folder}")
            else:
                st.error("❌ Folder not found")
    
    with col2:
        if st.button("⏹️ Stop Monitoring", use_container_width=True):
            st.session_state.monitoring_active = False
            st.info("⛔ Monitoring stopped")
    
    st.markdown("---")
    
    if st.session_state.monitoring_active:
        st.warning("🔴 MONITORING IS ACTIVE")
        alerts = file_monitor.get_alerts()
        alert_summary = file_monitor.get_alert_summary()
        
        st.markdown("### Alert Summary")
        a1, a2, a3, a4 = st.columns(4)
        a1.metric("Total Alerts", alert_summary['total_alerts'])
        a2.metric("🔴 Critical", alert_summary['critical'])
        a3.metric("🟠 High", alert_summary['high'])
        a4.metric("🟡 Medium", alert_summary['medium'])
        
        if alerts:
            st.markdown("### Recent Alerts")
            for alert in alerts[-10:]:
                with st.expander(f"{alert['activity_type']} - {alert['filename']}"):
                    col1, col2 = st.columns(2)
                    col1.write(f"**Activity:** {alert['activity_type']}")
                    col2.write(f"**Risk Level:** {alert['threat_level']}")
                    st.write(f"**Time:** {alert['timestamp']}")
                    st.write(f"**Path:** {alert['file_path']}")
                    if alert['details']:
                        st.json(alert['details'])
    else:
        st.info("ℹ️ Start monitoring to track file changes in real-time")

# ==========================================
# 6. SCAN SCHEDULER (Scheduled Scans)
# ==========================================
elif nav_selection == "Scan Scheduler":
    st.title("📅 Scan Scheduler")
    st.markdown("Schedule automated scans at specific times")
    
    scan_scheduler = st.session_state.scan_scheduler
    
    tab1, tab2, tab3 = st.tabs(["Add Schedule", "View Schedules", "Upcoming Scans"])
    
    with tab1:
        st.markdown("### Create New Schedule")
        sched_name = st.text_input("Schedule name:", placeholder="Daily System Scan")
        sched_days = st.multiselect("Days to scan:", 
            ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
            default=["Monday", "Wednesday", "Friday"])
        sched_time = st.time_input("Scan time:")
        sched_type = st.radio("Scan type:", ["quick", "full"])
        sched_quarantine = st.checkbox("Auto-quarantine threats", value=True)
        
        if st.button("➕ Add Schedule", type="primary", use_container_width=True):
            if sched_name and sched_days:
                result = scan_scheduler.add_schedule(
                    sched_name,
                    sched_days,
                    sched_time.strftime("%H:%M"),
                    sched_type,
                    sched_quarantine
                )
                if result['success']:
                    st.success(result['message'])
                else:
                    st.error(result['message'])
            else:
                st.warning("Please fill all fields")
    
    with tab2:
        schedules = scan_scheduler.get_schedules()
        if schedules:
            st.markdown("### Configured Schedules")
            for sched in schedules:
                with st.expander(f"📅 {sched['name']} - {sched['time']}", expanded=False):
                    col1, col2 = st.columns(2)
                    col1.write(f"**Days:** {', '.join(sched['days'])}")
                    col2.write(f"**Type:** {sched['scan_type'].upper()}")
                    st.write(f"**Auto-Quarantine:** {'Yes' if sched['auto_quarantine'] else 'No'}")
                    st.write(f"**Enabled:** {'✅ Yes' if sched['is_enabled'] else '❌ No'}")
                    st.write(f"**Last Run:** {sched.get('last_run', 'Never')}")
                    st.write(f"**Run Count:** {sched.get('run_count', 0)}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("▶️ Run Now", key=f"run_{sched['schedule_id']}"):
                            st.info(f"Started manual scan: {sched['name']}")
                    with col2:
                        if st.button("🗑️ Delete", key=f"del_{sched['schedule_id']}"):
                            scan_scheduler.remove_schedule(sched['schedule_id'])
                            st.success("Schedule deleted")
                            time.sleep(1)
                            st.rerun()
        else:
            st.info("No schedules configured yet")
    
    with tab3:
        stats = scan_scheduler.get_schedule_stats()
        st.markdown("### Scheduler Statistics")
        s1, s2, s3 = st.columns(3)
        s1.metric("Total Schedules", stats['total_schedules'])
        s2.metric("Enabled", stats['enabled'])
        s3.metric("Total Runs", stats['total_runs'])
        
        upcoming = scan_scheduler.get_next_scheduled_scans(5)
        if upcoming:
            st.markdown("### Next 5 Scheduled Scans")
            for scan in upcoming:
                st.write(f"⏰ **{scan['name']}** - {scan['next_run']} ({scan['scan_type']})")

# ==========================================
# 7. NOTIFICATIONS (Threat Alerts)
# ==========================================
elif nav_selection == "Notifications":
    st.title("🔔 Notifications & Alerts")
    st.markdown("Track all security notifications and threats detected")
    
    notif_mgr = st.session_state.notification_manager
    
    tab1, tab2, tab3 = st.tabs(["All Notifications", "Unread Only", "Statistics"])
    
    with tab1:
        notifications = notif_mgr.get_notifications()
        if notifications:
            for notif in notifications:
                level_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                    'INFO': 'ℹ️'
                }
                
                emoji = level_emoji.get(notif['level'], '•')
                read_status = "✓" if notif['is_read'] else "●"
                
                with st.expander(f"{emoji} {read_status} {notif['title']}", expanded=notif['action_required']):
                    st.write(notif['message'])
                    col1, col2 = st.columns([3, 1])
                    col1.write(f"**Time:** {notif['timestamp']}")
                    col1.write(f"**Type:** {notif['type']}")
                    if col2.button("✓ Mark Read", key=f"read_{notif['id']}"):
                        notif_mgr.mark_as_read(notif['id'])
                        st.rerun()
                    
                    if notif['data']:
                        st.json(notif['data'])
        else:
            st.info("No notifications")
    
    with tab2:
        unread = notif_mgr.get_notifications(unread_only=True)
        if unread:
            st.warning(f"You have {len(unread)} unread notifications")
            for notif in unread:
                level_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                    'INFO': 'ℹ️'
                }
                emoji = level_emoji.get(notif['level'], '•')
                
                st.write(f"{emoji} **{notif['title']}**")
                st.write(notif['message'])
                if st.button("✓ Mark Read", key=f"mark_{notif['id']}"):
                    notif_mgr.mark_as_read(notif['id'])
                    st.rerun()
                st.divider()
        else:
            st.success("✅ All caught up! No unread notifications")
    
    with tab3:
        summary = notif_mgr.get_notification_summary()
        st.markdown("### Notification Summary")
        c1, c2, c3 = st.columns(3)
        c1.metric("Total", summary['total'])
        c2.metric("Unread", summary['unread'])
        c3.metric("Action Required", summary['action_required'])
        
        st.markdown("### By Level")
        level_data = {
            'CRITICAL': summary['critical'],
            'HIGH': summary['high'],
            'MEDIUM': summary['medium'],
            'LOW': summary['low'],
            'INFO': summary['info']
        }
        
        level_df = pd.DataFrame(list(level_data.items()), columns=['Level', 'Count'])
        st.bar_chart(level_df.set_index('Level'))
elif nav_selection == "Reports":
    st.title("📄 Scan Reports & Advanced Analysis")
    st.markdown("Detailed analysis of all system scans and threats detected")
    
    threat_detector = st.session_state.threat_detector
    detailed_results = st.session_state.detailed_scan_results
    
    if len(st.session_state.scan_history) == 0:
        st.info("No scans have been performed yet.")
    else:
        tab1, tab2 = st.tabs(["Scan History", "Detailed Threats"])
        
        with tab1:
            history_df = pd.DataFrame(st.session_state.scan_history)
            st.dataframe(history_df.iloc[::-1], use_container_width=True)
        
        with tab2:
            if detailed_results:
                st.markdown("### Threat Detection Details")
                for result in detailed_results[-20:]:
                    if result['is_threat']:
                        with st.expander(f"🚨 {result['threat_type']} - {result['filename']}", expanded=False):
                            col1, col2 = st.columns(2)
                            col1.metric("Threat Level", result['threat_level'])
                            col2.metric("Risk Score", f"{result['risk_score']*100:.1f}%")
                            
                            st.write(f"**Detection Methods:**")
                            for method in result['detection_methods']:
                                st.write(f"  • {method}")
                            
                            st.write(f"**Recommendations:**")
                            for rec in result['recommendations']:
                                st.write(f"  • {rec}")
            else:
                st.info("No threats detected in recent scans")
        
        if st.button("Clear History"):
            st.session_state.scan_history = []
            st.session_state.detailed_scan_results = []
            st.rerun()

# ==========================================
# 8. SETTINGS (Advanced Security Settings)
# ==========================================
elif nav_selection == "Settings":
    st.title("⚙️ Advanced Security Settings")
    
    tab1, tab2, tab3 = st.tabs(["Exclusions", "Protection Layers", "System Health"])
    
    with tab1:
        st.markdown("### Allow List / Exclusions")
        st.markdown("Files listed here will be **ignored** by the scanner and will not be quarantined.")
        
        current_exclusions = "\n".join(st.session_state.exclusions)
        new_exclusions = st.text_area("Enter filenames to exclude (one per line, e.g., game_mod.exe):", value=current_exclusions, height=150)
        
        if st.button("Save Exclusions", type="primary", use_container_width=True):
            clean_list = [e.strip() for e in new_exclusions.split('\n') if e.strip() != ""]
            st.session_state.exclusions = clean_list
            st.success("✅ Exclusions list updated successfully!")
    
    with tab2:
        st.markdown("### Real-Time Protection Layers")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Web Protection")
            st.session_state.prot_web = st.toggle("🌐 Web Protection", st.session_state.prot_web)
            if st.session_state.prot_web:
                st.success("✅ Web Protection: ENABLED")
            else:
                st.warning("❌ Web Protection: DISABLED")
        
        with col2:
            st.markdown("#### Malware Protection")
            st.session_state.prot_malware = st.toggle("🦠 Malware Protection", st.session_state.prot_malware)
            if st.session_state.prot_malware:
                st.success("✅ Malware Protection: ENABLED")
            else:
                st.warning("❌ Malware Protection: DISABLED")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Ransomware Protection")
            st.session_state.prot_ransomware = st.toggle("🔒 Ransomware Protection", st.session_state.prot_ransomware)
            if st.session_state.prot_ransomware:
                st.success("✅ Ransomware Protection: ENABLED")
            else:
                st.warning("❌ Ransomware Protection: DISABLED")
        
        with col2:
            st.markdown("#### Exploit Protection")
            st.session_state.prot_exploit = st.toggle("⚙️ Exploit Protection", st.session_state.prot_exploit)
            if st.session_state.prot_exploit:
                st.success("✅ Exploit Protection: ENABLED")
            else:
                st.warning("❌ Exploit Protection: DISABLED")
    
    with tab3:
        st.markdown("### System & Database Health")
        
        col1, col2 = st.columns(2)
        
        with col1:
            threat_report = st.session_state.threat_detector.get_threat_report()
            st.write("**Threat Statistics:**")
            st.write(f"• Total Scans: {threat_report['total_scans']}")
            st.write(f"• Critical: {threat_report['critical_threats']}")
            st.write(f"• High: {threat_report['high_threats']}")
            st.write(f"• Medium: {threat_report['medium_threats']}")
        
        with col2:
            quarantine_stats = st.session_state.quarantine_manager.get_quarantine_stats()
            st.write("**Quarantine Status:**")
            st.write(f"• Total Items: {quarantine_stats['total_quarantined']}")
            st.write(f"• Size: {quarantine_stats['total_size_mb']} MB")
            st.write(f"• Isolated: {quarantine_stats['isolated']}")
            st.write(f"• Restored: {quarantine_stats['restored']}")
        
        st.markdown("---")
        st.markdown("### Maintenance")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🧹 Clear Old Logs", use_container_width=True):
                days = st.slider("Age (days):", 1, 30, 7)
                cleanup = st.session_state.notification_manager.delete_old_notifications(days)
                st.success(f"✅ {cleanup['deleted']} old notifications deleted")
        
        with col2:
            if st.button("🗑️ Clear Old Quarantine", use_container_width=True):
                cleanup = st.session_state.quarantine_manager.auto_cleanup_old_items(30)
                st.success(cleanup['message'])
        
        with col3:
            if st.button("💾 Export All Data", use_container_width=True):
                report_path = st.session_state.quarantine_manager.export_quarantine_report()
                st.success(f"✅ Report saved: {report_path}")
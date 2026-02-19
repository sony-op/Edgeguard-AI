import streamlit as st
import pandas as pd
import time

# --- Dn Infosolution Brand Theme Setup ---
st.set_page_config(page_title="Dn AI Shield Dashboard", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #F5F5F5; }
    h1, h2, h3 { color: #1A2B3C !important; }
    
    div[data-testid="metric-container"] {
        background-color: #0A3E3C; 
        color: #FFFFFF;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #4A8B9D;
    }
    div[data-testid="metric-container"] > div { color: #FFFFFF !important; }
    .dataframe th { background-color: #1A2B3C !important; color: white !important; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Dn AI Shield - Live Web Traffic Monitor")
st.markdown("**Real-time Browser Extension Logs | Innovation Marathon**")
st.markdown("---")

LOG_FILE = 'scanned_urls.csv'

placeholder = st.empty()

with placeholder.container():
    try:
        # CSV file se data read karna
        df = pd.read_csv(LOG_FILE)
        df = df.tail(50) # Aakhiri 50 requests dikhayenge
        
        total_scans = len(df)
        blocked = len(df[df['Status'] == 'malicious'])
        safe = total_scans - blocked
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Web Pages Scanned", total_scans)
        with col2:
            st.metric("Threats Detected 🚨", blocked)
        with col3:
            st.metric("Safe Pages ✅", safe)
            
        st.markdown("### 🌐 Live URL Scan History")
        
        # Color coding rows based on Status (Dn Infosolution colors)
        def color_status(val):
            color = '#E6A689' if val == 'malicious' else '#8EB998' 
            return f'background-color: {color}; color: #1A2B3C; font-weight: bold;'
            
        styled_df = df.style.map(color_status, subset=['Status'])
        st.dataframe(styled_df, use_container_width=True, height=400)
        
    except FileNotFoundError:
        st.warning("Abhi tak koi URL scan nahi hua hai. Kripya apna extension chalu karein aur kisi website par jayein.")

# Har 3 second me dashboard update hoga
time.sleep(3)
st.rerun()
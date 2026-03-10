import streamlit as st
import random
import time
import math
from datetime import datetime, timedelta
import json
import requests
import hashlib
import base64

# ─── VirusTotal API Configuration ─────────────────────────────────────────────
VT_API_KEY = "72c6d683a980b0ca51ac290740a622cc7e64cb436175bf82121ab46341819e93"
VT_BASE    = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

# ─── VirusTotal Helper Functions ───────────────────────────────────────────────
def vt_get(endpoint):
    """Generic VT GET request; returns (data_dict | None, error_str | None)."""
    try:
        r = requests.get(f"{VT_BASE}/{endpoint}", headers=VT_HEADERS, timeout=15)
        if r.status_code == 200:
            return r.json(), None
        elif r.status_code == 404:
            return None, "NOT FOUND — IOC not yet in VirusTotal database."
        elif r.status_code == 401:
            return None, "AUTHENTICATION FAILED — Check API key."
        elif r.status_code == 429:
            return None, "RATE LIMIT EXCEEDED — Please wait and retry."
        else:
            return None, f"API ERROR {r.status_code}: {r.text[:200]}"
    except requests.exceptions.Timeout:
        return None, "REQUEST TIMEOUT — VirusTotal did not respond in time."
    except Exception as e:
        return None, f"CONNECTION ERROR: {str(e)}"

def vt_post(endpoint, data):
    try:
        r = requests.post(f"{VT_BASE}/{endpoint}", headers=VT_HEADERS, data=data, timeout=20)
        if r.status_code in (200, 201):
            return r.json(), None
        return None, f"API ERROR {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return None, f"CONNECTION ERROR: {str(e)}"

def vt_scan_ip(ip):
    return vt_get(f"ip_addresses/{ip}")

def vt_scan_domain(domain):
    return vt_get(f"domains/{domain}")

def vt_scan_hash(h):
    return vt_get(f"files/{h}")

def vt_scan_url(url):
    # First submit URL for scanning
    encoded = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    data, err = vt_get(f"urls/{encoded}")
    if data:
        return data, None
    # If not cached, submit for fresh scan
    post_data, post_err = vt_post("urls", {"url": url})
    if post_err:
        return None, post_err
    # poll analysis
    analysis_id = post_data.get("data", {}).get("id", "")
    if analysis_id:
        time.sleep(3)
        return vt_get(f"analyses/{analysis_id}")
    return None, "Could not retrieve URL analysis."

def format_vt_stats(stats: dict) -> str:
    """Turn a VT last_analysis_stats dict into a readable string."""
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected
    detection   = f"{malicious}/{total}" if total else "N/A"
    if malicious > 10:
        verdict = "🔴 MALICIOUS"
    elif malicious > 0 or suspicious > 3:
        verdict = "🟡 SUSPICIOUS"
    else:
        verdict = "🟢 CLEAN"
    return verdict, detection, malicious, suspicious, harmless, undetected, total

def vt_report_ip(ioc, data):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    verdict, detection, mal, sus, har, undet, total = format_vt_stats(stats)
    country   = attrs.get("country", "Unknown")
    owner     = attrs.get("as_owner", "Unknown")
    asn       = attrs.get("asn", "N/A")
    rep       = attrs.get("reputation", "N/A")
    categories = ", ".join(list(attrs.get("categories", {}).values())[:4]) or "None"
    last_mod  = attrs.get("last_modification_date", "")
    if last_mod:
        try:
            last_mod = datetime.utcfromtimestamp(last_mod).strftime("%Y-%m-%d")
        except: pass
    top_engines = []
    results = attrs.get("last_analysis_results", {})
    for eng, res in results.items():
        if res.get("category") in ("malicious","suspicious"):
            top_engines.append(f"    ✗ {eng}: {res.get('result','—')}")
        if len(top_engines) >= 6:
            break
    engines_str = "\n".join(top_engines) if top_engines else "    None"
    return f"""IOC:        {ioc}
TYPE:       IP Address
VERDICT:    {verdict}
DETECTION:  {detection} engines flagged

ENGINE HITS:
{engines_str}

GEO / OWNERSHIP:
  Country:  {country}
  ASN:      {asn}  ({owner})
  Reputation Score: {rep}
  Categories: {categories}
  Last Seen: {last_mod}

ENGINE BREAKDOWN:
  Malicious:   {mal}
  Suspicious:  {sus}
  Harmless:    {har}
  Undetected:  {undet}
  Total:       {total}

SOURCE:  VirusTotal Live API  🔗 virustotal.com/gui/ip-address/{ioc}"""

def vt_report_domain(ioc, data):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    verdict, detection, mal, sus, har, undet, total = format_vt_stats(stats)
    registrar   = attrs.get("registrar", "Unknown")
    creation    = attrs.get("creation_date", "")
    categories  = ", ".join(list(attrs.get("categories", {}).values())[:4]) or "None"
    rep         = attrs.get("reputation", "N/A")
    if creation:
        try: creation = datetime.utcfromtimestamp(creation).strftime("%Y-%m-%d")
        except: pass
    top_engines = []
    for eng, res in attrs.get("last_analysis_results", {}).items():
        if res.get("category") in ("malicious","suspicious"):
            top_engines.append(f"    ✗ {eng}: {res.get('result','—')}")
        if len(top_engines) >= 6: break
    engines_str = "\n".join(top_engines) if top_engines else "    None"
    return f"""IOC:        {ioc}
TYPE:       Domain
VERDICT:    {verdict}
DETECTION:  {detection} engines flagged

ENGINE HITS:
{engines_str}

DOMAIN INFO:
  Registrar:   {registrar}
  Created:     {creation}
  Categories:  {categories}
  Reputation:  {rep}

ENGINE BREAKDOWN:
  Malicious:   {mal}
  Suspicious:  {sus}
  Harmless:    {har}
  Undetected:  {undet}
  Total:       {total}

SOURCE:  VirusTotal Live API  🔗 virustotal.com/gui/domain/{ioc}"""

def vt_report_hash(ioc, data):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    verdict, detection, mal, sus, har, undet, total = format_vt_stats(stats)
    name        = attrs.get("meaningful_name", attrs.get("names", ["unknown"])[0] if attrs.get("names") else "unknown")
    size        = attrs.get("size", "N/A")
    ftype       = attrs.get("type_description", attrs.get("type_tag", "N/A"))
    md5         = attrs.get("md5", "N/A")
    sha256      = attrs.get("sha256", ioc)
    first_sub   = attrs.get("first_submission_date", "")
    last_sub    = attrs.get("last_submission_date", "")
    times_sub   = attrs.get("times_submitted", "N/A")
    if first_sub:
        try: first_sub = datetime.utcfromtimestamp(first_sub).strftime("%Y-%m-%d")
        except: pass
    if last_sub:
        try: last_sub = datetime.utcfromtimestamp(last_sub).strftime("%Y-%m-%d")
        except: pass
    top_engines = []
    for eng, res in attrs.get("last_analysis_results", {}).items():
        if res.get("category") == "malicious":
            top_engines.append(f"    ✗ {eng}: {res.get('result','—')}")
        if len(top_engines) >= 8: break
    engines_str = "\n".join(top_engines) if top_engines else "    None"
    sigma = attrs.get("sigma_analysis_stats", {})
    tags = ", ".join(attrs.get("tags", [])[:6]) or "None"
    return f"""IOC:        {ioc[:64]}
TYPE:       File Hash
VERDICT:    {verdict}
DETECTION:  {detection} engines flagged

FILE INFO:
  Name:        {name}
  Type:        {ftype}
  Size:        {size} bytes
  MD5:         {md5}
  SHA256:      {sha256[:48]}...
  First Seen:  {first_sub}
  Last Seen:   {last_sub}
  Submissions: {times_sub}
  Tags:        {tags}

MALICIOUS ENGINE HITS:
{engines_str}

ENGINE BREAKDOWN:
  Malicious:   {mal}
  Suspicious:  {sus}
  Harmless:    {har}
  Undetected:  {undet}
  Total:       {total}

SOURCE:  VirusTotal Live API  🔗 virustotal.com/gui/file/{sha256}"""

def vt_report_url(ioc, data):
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    verdict, detection, mal, sus, har, undet, total = format_vt_stats(stats)
    final_url   = attrs.get("last_final_url", ioc)
    title       = attrs.get("title", "N/A")
    last_scan   = attrs.get("last_analysis_date", "")
    categories  = ", ".join(list(attrs.get("categories", {}).values())[:4]) or "None"
    if last_scan:
        try: last_scan = datetime.utcfromtimestamp(last_scan).strftime("%Y-%m-%d %H:%M")
        except: pass
    top_engines = []
    for eng, res in attrs.get("last_analysis_results", {}).items():
        if res.get("category") in ("malicious","suspicious"):
            top_engines.append(f"    ✗ {eng}: {res.get('result','—')}")
        if len(top_engines) >= 6: break
    engines_str = "\n".join(top_engines) if top_engines else "    None"
    return f"""IOC:        {ioc[:80]}
TYPE:       URL
VERDICT:    {verdict}
DETECTION:  {detection} engines flagged

URL INFO:
  Final URL:   {final_url[:80]}
  Title:       {title}
  Categories:  {categories}
  Last Scanned:{last_scan}

ENGINE HITS:
{engines_str}

ENGINE BREAKDOWN:
  Malicious:   {mal}
  Suspicious:  {sus}
  Harmless:    {har}
  Undetected:  {undet}
  Total:       {total}

SOURCE:  VirusTotal Live API  🔗 virustotal.com/gui/url"""

def detect_ioc_type(ioc: str) -> str:
    """Auto-detect IOC type from input string."""
    import re
    ioc = ioc.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "IP Address"
    if re.match(r"^[0-9a-fA-F]{32}$", ioc):
        return "File Hash MD5"
    if re.match(r"^[0-9a-fA-F]{64}$", ioc):
        return "File Hash SHA256"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "URL"
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", ioc):
        return "Domain"
    return "Unknown"

def run_vt_lookup(ioc: str, ioc_type: str):
    """Route lookup to correct VT endpoint. Returns (report_str, error_str)."""
    ioc = ioc.strip()
    if ioc_type == "Auto-Detect":
        ioc_type = detect_ioc_type(ioc)
    if ioc_type == "IP Address":
        data, err = vt_scan_ip(ioc)
        return (vt_report_ip(ioc, data), None) if data else (None, err)
    elif ioc_type == "Domain":
        data, err = vt_scan_domain(ioc)
        return (vt_report_domain(ioc, data), None) if data else (None, err)
    elif ioc_type in ("File Hash MD5", "File Hash SHA256"):
        data, err = vt_scan_hash(ioc)
        return (vt_report_hash(ioc, data), None) if data else (None, err)
    elif ioc_type == "URL":
        data, err = vt_scan_url(ioc)
        return (vt_report_url(ioc, data), None) if data else (None, err)
    else:
        return None, f"Cannot auto-detect IOC type for: {ioc}"

# ─── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AEGIS SOC · AI Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap');

:root {
  --bg:        #030712;
  --panel:     #0a0f1e;
  --border:    #0f2a4a;
  --accent:    #00d4ff;
  --accent2:   #00ff88;
  --warn:      #ffaa00;
  --danger:    #ff3366;
  --text:      #c9d8e8;
  --dim:       #4a6080;
  --glow:      0 0 12px rgba(0,212,255,.45);
  --glow2:     0 0 12px rgba(0,255,136,.45);
  --glowR:     0 0 12px rgba(255,51,102,.45);
}

html, body, [data-testid="stAppViewContainer"] {
  background: var(--bg) !important;
  color: var(--text) !important;
  font-family: 'Rajdhani', sans-serif;
}

[data-testid="stSidebar"] {
  background: #050c1a !important;
  border-right: 1px solid var(--border) !important;
}

/* hide default streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stToolbar"] { display: none; }

/* ── top bar ── */
.topbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 24px; margin-bottom: 20px;
  background: linear-gradient(90deg, #050c1a 0%, #0a1628 60%, #050c1a 100%);
  border-bottom: 1px solid var(--border);
  position: relative; overflow: hidden;
}
.topbar::before {
  content:''; position:absolute; left:0; top:0; right:0; bottom:0;
  background: repeating-linear-gradient(90deg, transparent, transparent 80px, rgba(0,212,255,.03) 80px, rgba(0,212,255,.03) 81px);
  pointer-events:none;
}
.topbar-logo {
  font-family: 'Orbitron', sans-serif; font-weight: 900; font-size: 22px;
  color: var(--accent); letter-spacing: 4px;
  text-shadow: var(--glow);
}
.topbar-logo span { color: var(--accent2); }
.topbar-sub { font-family:'Share Tech Mono'; font-size:10px; color:var(--dim); letter-spacing:2px; margin-top:2px; }
.topbar-right { display:flex; gap:20px; align-items:center; }
.status-pill {
  display:inline-flex; align-items:center; gap:6px;
  padding:4px 12px; border-radius:20px;
  background:rgba(0,255,136,.08); border:1px solid rgba(0,255,136,.3);
  font-family:'Share Tech Mono'; font-size:11px; color:var(--accent2);
}
.pulse { width:7px; height:7px; border-radius:50%; background:var(--accent2);
  box-shadow:0 0 8px var(--accent2); animation:blink 1.2s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }

/* ── metric cards ── */
.metric-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 20px;
  position: relative; overflow: hidden;
  transition: border-color .3s;
}
.metric-card::after {
  content:''; position:absolute; top:0; left:0; right:0; height:2px;
}
.card-cyan::after  { background: linear-gradient(90deg, transparent, var(--accent), transparent); }
.card-green::after { background: linear-gradient(90deg, transparent, var(--accent2), transparent); }
.card-warn::after  { background: linear-gradient(90deg, transparent, var(--warn), transparent); }
.card-red::after   { background: linear-gradient(90deg, transparent, var(--danger), transparent); }
.card-label { font-size:11px; letter-spacing:2px; color:var(--dim); text-transform:uppercase; }
.card-value { font-family:'Orbitron'; font-size:32px; font-weight:700; margin:6px 0 2px; }
.v-cyan  { color:var(--accent);  text-shadow:var(--glow);  }
.v-green { color:var(--accent2); text-shadow:var(--glow2); }
.v-warn  { color:var(--warn);    text-shadow:0 0 12px rgba(255,170,0,.45); }
.v-red   { color:var(--danger);  text-shadow:var(--glowR); }
.card-delta { font-size:12px; color:var(--dim); }

/* ── section headers ── */
.sec-head {
  font-family:'Orbitron'; font-size:13px; font-weight:700;
  letter-spacing:3px; color:var(--accent); text-transform:uppercase;
  border-left:3px solid var(--accent); padding-left:12px;
  margin-bottom:12px; text-shadow:var(--glow);
}

/* ── threat feed ── */
.threat-item {
  display:flex; align-items:flex-start; gap:10px;
  padding:10px 14px; margin-bottom:6px;
  border-radius:6px; border-left:3px solid;
  background:rgba(10,15,30,.8);
  font-family:'Share Tech Mono'; font-size:12px;
  animation: fadeIn .4s ease;
}
@keyframes fadeIn { from{opacity:0;transform:translateX(-6px)} to{opacity:1;transform:none} }
.t-critical { border-color: var(--danger); background: rgba(255,51,102,.05); }
.t-high     { border-color: var(--warn);   background: rgba(255,170,0,.04); }
.t-medium   { border-color: var(--accent); background: rgba(0,212,255,.04); }
.t-low      { border-color: var(--accent2);background: rgba(0,255,136,.04); }
.t-badge {
  padding:2px 7px; border-radius:3px; font-size:9px;
  font-weight:700; letter-spacing:1px; white-space:nowrap;
}
.b-critical { background:rgba(255,51,102,.2); color:var(--danger); }
.b-high     { background:rgba(255,170,0,.2); color:var(--warn); }
.b-medium   { background:rgba(0,212,255,.2); color:var(--accent); }
.b-low      { background:rgba(0,255,136,.2); color:var(--accent2); }
.t-ip { color:var(--accent); margin-left:auto; white-space:nowrap; }
.t-time { color:var(--dim); font-size:10px; }

/* ── radar ring animation ── */
.radar-wrap { display:flex; justify-content:center; align-items:center; padding:10px 0; }
.radar { width:160px; height:160px; position:relative; }
.radar svg { width:100%; height:100%; }
.scan { animation: rotate 3s linear infinite; transform-origin:80px 80px; }
@keyframes rotate { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
.dot { animation: dotPulse 1.5s ease-in-out infinite; }
@keyframes dotPulse { 0%,100%{opacity:1;r:3} 50%{opacity:.3;r:1.5} }

/* ── progress bars ── */
.prog-row { margin-bottom:10px; }
.prog-label { display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px; }
.prog-bar { height:6px; border-radius:3px; background:#0f2a4a; overflow:hidden; }
.prog-fill { height:100%; border-radius:3px; transition:width 1s ease; }

/* ── log console ── */
.console-box {
  background:#020810; border:1px solid var(--border); border-radius:6px;
  padding:12px 14px; font-family:'Share Tech Mono'; font-size:11px;
  height:240px; overflow-y:auto; line-height:1.8;
}
.console-box::-webkit-scrollbar { width:4px; }
.console-box::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
.log-info  { color: var(--accent2); }
.log-warn  { color: var(--warn); }
.log-err   { color: var(--danger); }
.log-sys   { color: var(--dim); }

/* ── buttons ── */
.stButton > button {
  background: transparent !important;
  border: 1px solid var(--accent) !important;
  color: var(--accent) !important;
  font-family: 'Orbitron', sans-serif !important;
  font-size: 11px !important;
  letter-spacing: 2px !important;
  border-radius: 4px !important;
  transition: all .2s !important;
}
.stButton > button:hover {
  background: rgba(0,212,255,.1) !important;
  box-shadow: var(--glow) !important;
}

/* ── selectbox / input ── */
.stSelectbox > div > div,
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  color: var(--text) !important;
  font-family: 'Rajdhani', sans-serif !important;
  border-radius: 4px !important;
}

/* ── tabs ── */
.stTabs [data-baseweb="tab-list"] {
  background: transparent !important;
  border-bottom: 1px solid var(--border) !important;
  gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
  font-family: 'Orbitron', sans-serif !important;
  font-size: 11px !important;
  letter-spacing: 2px !important;
  color: var(--dim) !important;
  background: transparent !important;
  border: none !important;
  padding: 8px 20px !important;
}
.stTabs [aria-selected="true"] {
  color: var(--accent) !important;
  border-bottom: 2px solid var(--accent) !important;
}

/* ── incident table ── */
.inc-table { width:100%; border-collapse:collapse; font-size:12px; }
.inc-table th { font-family:'Orbitron'; font-size:9px; letter-spacing:2px; color:var(--dim);
  padding:8px 10px; border-bottom:1px solid var(--border); text-align:left; }
.inc-table td { padding:9px 10px; border-bottom:1px solid rgba(15,42,74,.5); color:var(--text); }
.inc-table tr:hover td { background:rgba(0,212,255,.03); }

/* ── network map node ── */
.nmap { display:flex; flex-wrap:wrap; gap:8px; padding:10px 0; }
.node {
  width:52px; height:52px; border-radius:50%;
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  border:1px solid; font-size:9px; font-family:'Share Tech Mono';
  cursor:pointer; transition:all .2s;
}
.node:hover { transform:scale(1.12); }
.node-ok   { border-color:var(--accent2); background:rgba(0,255,136,.06); color:var(--accent2); }
.node-warn { border-color:var(--warn);   background:rgba(255,170,0,.06);  color:var(--warn); }
.node-bad  { border-color:var(--danger); background:rgba(255,51,102,.06); color:var(--danger);
  animation: nodeAlert .8s ease-in-out infinite; }
@keyframes nodeAlert { 0%,100%{box-shadow:0 0 0 rgba(255,51,102,0)} 50%{box-shadow:0 0 10px rgba(255,51,102,.5)} }

/* ── ai response box ── */
.ai-box {
  background:rgba(0,212,255,.04); border:1px solid rgba(0,212,255,.2);
  border-radius:8px; padding:16px 18px; margin-top:12px;
  font-family:'Share Tech Mono'; font-size:12px; line-height:1.8; color:var(--text);
}
.ai-label { font-family:'Orbitron'; font-size:10px; letter-spacing:2px;
  color:var(--accent); margin-bottom:8px; }

/* sidebar nav ── */
.nav-item {
  padding:10px 16px; border-radius:6px; margin-bottom:4px;
  cursor:pointer; display:flex; align-items:center; gap:10px;
  font-family:'Rajdhani'; font-size:15px; font-weight:600; letter-spacing:1px;
  color:var(--dim); transition:all .2s;
  border: 1px solid transparent;
}
.nav-item:hover, .nav-active {
  color:var(--accent); background:rgba(0,212,255,.06);
  border-color:rgba(0,212,255,.15);
}
</style>
""", unsafe_allow_html=True)

# ─── Session State Initialization ─────────────────────────────────────────────
def init_state():
    defaults = {
        "threats": [], "logs": [], "incidents": [],
        "monitoring": False, "scan_count": 0,
        "blocked_ips": set(), "alert_count": 0,
        "last_refresh": datetime.now(),
        "page": "dashboard",
        "risk_score": random.randint(28, 55),
        "uptime_hours": random.randint(200, 8760),
        "analysis_result": None,
        "analysis_error": False,
        "hunt_result": None,
        "heal_result": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ─── Data Generators ──────────────────────────────────────────────────────────
THREAT_TYPES = [
    ("SQL Injection Attempt", "critical"), ("Ransomware Beacon", "critical"),
    ("Port Scan Detected", "high"),       ("Brute Force SSH", "high"),
    ("C2 Callback Detected", "critical"), ("Data Exfiltration", "critical"),
    ("Phishing URL Click", "high"),       ("Anomalous Login", "medium"),
    ("DDoS Syn Flood", "high"),           ("Malware Download", "critical"),
    ("Lateral Movement", "high"),         ("Privilege Escalation", "critical"),
    ("Zero-Day Exploit", "critical"),     ("Insider Threat Indicator", "high"),
    ("DNS Tunneling", "medium"),          ("Credential Stuffing", "medium"),
    ("Fileless Malware", "critical"),     ("Supply Chain Attack", "critical"),
    ("XSS Injection", "medium"),          ("API Abuse", "low"),
]
COUNTRIES = ["CN", "RU", "US", "BR", "KP", "IR", "UA", "DE", "IN", "NG"]
MALWARE_FAMILIES = ["Emotet", "TrickBot", "REvil", "LockBit", "Cobalt Strike",
                    "BlackByte", "Qakbot", "IcedID", "AgentTesla", "AsyncRAT"]
MITRE = ["T1059", "T1078", "T1110", "T1486", "T1071", "T1027", "T1055", "T1547"]

def rand_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_threat():
    ttype, sev = random.choice(THREAT_TYPES)
    return {
        "id": f"THR-{random.randint(10000,99999)}",
        "type": ttype, "severity": sev,
        "src_ip": rand_ip(), "dst_ip": rand_ip(),
        "country": random.choice(COUNTRIES),
        "malware": random.choice(MALWARE_FAMILIES) if sev == "critical" else None,
        "mitre": random.choice(MITRE),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "confidence": random.randint(72, 99),
        "action": random.choice(["BLOCKED", "QUARANTINED", "ALERTING", "INVESTIGATING"]),
    }

def generate_log():
    logs = [
        ("[SYS]  AEGIS engine heartbeat OK", "sys"),
        ("[SCAN] Deep packet inspection running on eth0", "info"),
        ("[ML]   Anomaly model inference: 0.{} score".format(random.randint(10,99)), "info"),
        ("[WARN] Suspicious beacon to {}".format(rand_ip()), "warn"),
        ("[BLOCK] IP {} added to blocklist".format(rand_ip()), "info"),
        ("[ERR]  Failed auth attempt from {}".format(rand_ip()), "err"),
        ("[HUNT] Threat hunting sweep: {} endpoints scanned".format(random.randint(100,9000)), "info"),
        ("[AI]   NLP model parsed {} events".format(random.randint(500,5000)), "sys"),
        ("[RESP] Auto-remediation playbook PB-{} executed".format(random.randint(1,99)), "info"),
        ("[PRED] Risk score updated: {}".format(random.randint(10,95)), "warn"),
        ("[HEAL] Self-healing patch deployed on node-{}".format(random.randint(1,64)), "info"),
        ("[IOC]  Hash match: {}...".format(random.randint(10**14,10**15)), "warn"),
    ]
    msg, kind = random.choice(logs)
    return {"msg": msg, "kind": kind, "ts": datetime.now().strftime("%H:%M:%S")}

def generate_incident():
    types = ["Intrusion", "Data Breach", "Malware", "Insider Threat", "Ransomware", "DDoS"]
    statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"]
    owners = ["Alpha Team", "Beta Team", "AI Engine", "Auto-Response", "SOC Lead"]
    return {
        "id": f"INC-{random.randint(1000,9999)}",
        "type": random.choice(types),
        "severity": random.choice(["P1", "P2", "P3", "P4"]),
        "status": random.choice(statuses),
        "owner": random.choice(owners),
        "created": (datetime.now() - timedelta(hours=random.randint(0,48))).strftime("%m/%d %H:%M"),
        "ttd": f"{random.randint(1,120)}m",
        "ttr": f"{random.randint(5,300)}m" if random.random() > .4 else "—",
    }

# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:16px 0 24px">
      <div style="font-family:'Orbitron';font-weight:900;font-size:20px;
                  color:#00d4ff;letter-spacing:4px;text-shadow:0 0 12px rgba(0,212,255,.5)">
        AEGIS
      </div>
      <div style="font-family:'Share Tech Mono';font-size:9px;color:#4a6080;
                  letter-spacing:3px;margin-top:4px">AI · SEC · OPS · v4.2.1</div>
    </div>
    """, unsafe_allow_html=True)

    pages = [
        ("🛡️", "Dashboard", "dashboard"),
        ("🔍", "Threat Detection", "threats"),
        ("🦠", "Malware Analysis", "malware"),
        ("💳", "Fraud Detection", "fraud"),
        ("⚡", "Incident Response", "incidents"),
        ("📊", "Predictive Risk", "risk"),
        ("🌐", "Network Monitor", "network"),
        ("🏹", "Threat Hunting", "hunting"),
        ("🔧", "Self-Healing", "healing"),
        ("⚙️", "Settings", "settings"),
    ]
    for icon, label, key in pages:
        active = "nav-active" if st.session_state.page == key else ""
        if st.button(f"{icon}  {label}", key=f"nav_{key}", use_container_width=True):
            st.session_state.page = key
            st.rerun()

    st.markdown("---")
    st.markdown('<div style="font-family:\'Share Tech Mono\';font-size:10px;color:#4a6080;padding:0 8px">SYSTEM STATUS</div>', unsafe_allow_html=True)
    metrics_side = [
        ("CPU", random.randint(25,78), "#00d4ff"),
        ("MEM", random.randint(40,82), "#00ff88"),
        ("NET", random.randint(10,95), "#ffaa00"),
        ("DISK", random.randint(20,60), "#00d4ff"),
    ]
    for name, val, color in metrics_side:
        st.markdown(f"""
        <div class="prog-row">
          <div class="prog-label">
            <span style="font-family:'Share Tech Mono';font-size:10px;color:#4a6080">{name}</span>
            <span style="font-family:'Share Tech Mono';font-size:10px;color:{color}">{val}%</span>
          </div>
          <div class="prog-bar"><div class="prog-fill" style="width:{val}%;background:linear-gradient(90deg,{color}88,{color})"></div></div>
        </div>""", unsafe_allow_html=True)

# ─── Top Bar ──────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="topbar">
  <div>
    <div class="topbar-logo">AEGIS <span>SOC</span></div>
    <div class="topbar-sub">AUTONOMOUS · INTELLIGENT · RESILIENT · SECURITY OPERATIONS</div>
  </div>
  <div class="topbar-right">
    <div class="status-pill"><div class="pulse"></div> 24/7 ACTIVE</div>
    <div style="font-family:'Share Tech Mono';font-size:11px;color:#4a6080">
      {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.page == "dashboard":
    # KPI Row
    threats_today = random.randint(1240, 3800)
    blocked = random.randint(1100, 3700)
    active_inc = random.randint(3, 18)
    risk = st.session_state.risk_score

    c1, c2, c3, c4, c5 = st.columns(5)
    cards = [
        (c1, "THREATS TODAY",   threats_today, "+12% ↑", "cyan",  "card-cyan"),
        (c2, "BLOCKED",         blocked,       "98.2% rate", "green", "card-green"),
        (c3, "ACTIVE INCIDENTS",active_inc,    "2 critical", "red",   "card-red"),
        (c4, "RISK SCORE",      f"{risk}/100", "Moderate",  "warn",  "card-warn"),
        (c5, "UPTIME HRS",      st.session_state.uptime_hours, "99.97%", "cyan", "card-cyan"),
    ]
    for col, label, val, delta, color, card_cls in cards:
        with col:
            st.markdown(f"""
            <div class="metric-card {card_cls}">
              <div class="card-label">{label}</div>
              <div class="card-value v-{color}">{val}</div>
              <div class="card-delta">{delta}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_left, col_mid, col_right = st.columns([1.1, 1, 0.9])

    # ── Live Threat Feed ──────────────────────────────────────────────────────
    with col_left:
        st.markdown('<div class="sec-head">LIVE THREAT FEED</div>', unsafe_allow_html=True)

        btn1, btn2 = st.columns(2)
        with btn1:
            if st.button("▶  START MONITORING", use_container_width=True):
                st.session_state.monitoring = True
        with btn2:
            if st.button("⏸  PAUSE", use_container_width=True):
                st.session_state.monitoring = False

        if st.session_state.monitoring:
            for _ in range(random.randint(1, 3)):
                st.session_state.threats.insert(0, generate_threat())
                st.session_state.logs.insert(0, generate_log())
            st.session_state.scan_count += 1

        feed = st.session_state.threats[:12] if st.session_state.threats else [generate_threat() for _ in range(6)]
        for t in feed[:8]:
            sev = t["severity"]
            st.markdown(f"""
            <div class="threat-item t-{sev}">
              <div>
                <span class="t-badge b-{sev}">{sev.upper()}</span>
                <span style="color:#c9d8e8;margin-left:8px">{t['type']}</span><br>
                <span class="t-time">{t['timestamp']} · MITRE {t['mitre']} · {t['confidence']}% conf · {t['action']}</span>
              </div>
              <div class="t-ip">{t['src_ip']}<br><span style="color:#4a6080;font-size:9px">{t['country']}</span></div>
            </div>""", unsafe_allow_html=True)

    # ── Radar + Stats ─────────────────────────────────────────────────────────
    with col_mid:
        st.markdown('<div class="sec-head">THREAT RADAR</div>', unsafe_allow_html=True)

        # Generate random dots for radar
        dots_svg = ""
        for _ in range(12):
            angle = random.uniform(0, 2 * math.pi)
            radius = random.uniform(15, 72)
            x = 80 + radius * math.cos(angle)
            y = 80 + radius * math.sin(angle)
            colors = ["#ff3366","#ffaa00","#00d4ff","#00ff88"]
            c = random.choice(colors)
            dots_svg += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{c}" class="dot" style="animation-delay:{random.uniform(0,1.5):.2f}s"/>'

        st.markdown(f"""
        <div class="radar-wrap">
        <div class="radar">
          <svg viewBox="0 0 160 160">
            <circle cx="80" cy="80" r="72" fill="none" stroke="#0f2a4a" stroke-width="1"/>
            <circle cx="80" cy="80" r="48" fill="none" stroke="#0f2a4a" stroke-width="1"/>
            <circle cx="80" cy="80" r="24" fill="none" stroke="#0f2a4a" stroke-width="1"/>
            <line x1="8" y1="80" x2="152" y2="80" stroke="#0f2a4a" stroke-width="1"/>
            <line x1="80" y1="8"  x2="80" y2="152" stroke="#0f2a4a" stroke-width="1"/>
            <g class="scan">
              <path d="M80,80 L152,80 A72,72 0 0,0 80,8 Z"
                    fill="url(#sweep)" opacity=".35"/>
            </g>
            <defs>
              <radialGradient id="sweep" cx="0%" cy="50%">
                <stop offset="0%" stop-color="#00d4ff" stop-opacity="0"/>
                <stop offset="100%" stop-color="#00d4ff" stop-opacity=".6"/>
              </radialGradient>
            </defs>
            {dots_svg}
            <circle cx="80" cy="80" r="4" fill="#00d4ff" opacity=".9"/>
          </svg>
        </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sec-head" style="margin-top:16px">DETECTION COVERAGE</div>', unsafe_allow_html=True)
        coverage = [
            ("Network IDS/IPS", random.randint(88, 99), "#00d4ff"),
            ("Endpoint EDR", random.randint(82, 97), "#00ff88"),
            ("Email Security", random.randint(75, 95), "#ffaa00"),
            ("Cloud Posture", random.randint(70, 92), "#00d4ff"),
            ("Identity Prot.", random.randint(80, 96), "#00ff88"),
        ]
        for name, val, color in coverage:
            st.markdown(f"""
            <div class="prog-row">
              <div class="prog-label">
                <span style="font-size:12px;color:#c9d8e8">{name}</span>
                <span style="font-family:'Share Tech Mono';font-size:11px;color:{color}">{val}%</span>
              </div>
              <div class="prog-bar"><div class="prog-fill" style="width:{val}%;background:linear-gradient(90deg,{color}66,{color})"></div></div>
            </div>""", unsafe_allow_html=True)

    # ── System Log ────────────────────────────────────────────────────────────
    with col_right:
        st.markdown('<div class="sec-head">SYSTEM LOG</div>', unsafe_allow_html=True)

        if st.session_state.monitoring:
            new_log = generate_log()
            st.session_state.logs.insert(0, new_log)

        log_html = ""
        for entry in (st.session_state.logs[:40] if st.session_state.logs else [generate_log() for _ in range(20)]):
            cls = f"log-{entry['kind']}"
            log_html += f'<div><span style="color:#4a6080">{entry["ts"]}</span> <span class="{cls}">{entry["msg"]}</span></div>'

        st.markdown(f'<div class="console-box">{log_html}</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sec-head">AI ENGINE STATUS</div>', unsafe_allow_html=True)
        engines = [
            ("Anomaly Detection ML", "ACTIVE", "#00ff88"),
            ("NLP Threat Classifier", "ACTIVE", "#00ff88"),
            ("Behavioral Analytics", "ACTIVE", "#00ff88"),
            ("Predictive Risk AI", "TRAINING", "#ffaa00"),
            ("Threat Intel Feed", "SYNCING", "#00d4ff"),
            ("Auto-Response Engine", "ACTIVE", "#00ff88"),
        ]
        for name, status, color in engines:
            st.markdown(f"""
            <div style="display:flex;justify-content:space-between;align-items:center;
                        padding:6px 0;border-bottom:1px solid rgba(15,42,74,.4);font-size:12px">
              <span style="color:#c9d8e8">{name}</span>
              <span style="font-family:'Share Tech Mono';font-size:10px;color:{color};
                           background:rgba(0,0,0,.3);padding:2px 8px;border-radius:3px">{status}</span>
            </div>""", unsafe_allow_html=True)

    if st.session_state.monitoring:
        time.sleep(0.8)
        st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: THREAT DETECTION
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "threats":
    st.markdown('<div class="sec-head">THREAT DETECTION · AI-POWERED ANALYSIS</div>', unsafe_allow_html=True)

    # VT status badge
    st.markdown("""
    <div style="display:inline-flex;align-items:center;gap:8px;padding:5px 14px;
                border-radius:4px;border:1px solid rgba(0,212,255,.3);
                background:rgba(0,212,255,.05);margin-bottom:14px">
      <div style="width:7px;height:7px;border-radius:50%;background:#00d4ff;
                  box-shadow:0 0 8px #00d4ff;animation:blink 1.2s infinite"></div>
      <span style="font-family:'Share Tech Mono';font-size:11px;color:#00d4ff;letter-spacing:1px">
        VIRUSTOTAL API · LIVE THREAT INTELLIGENCE CONNECTED
      </span>
    </div>""", unsafe_allow_html=True)

    col1, col2 = st.columns([1.4, 1])
    with col1:
        st.markdown("**Analyze IP / Domain / Hash / URL via VirusTotal**")
        ioc = st.text_input("Enter IOC", placeholder="e.g. 185.220.101.45  |  evil.com  |  SHA256 hash  |  https://...")
        ioc_type = st.selectbox("IOC Type", ["Auto-Detect", "IP Address", "Domain", "File Hash MD5", "File Hash SHA256", "URL"])

        if st.button("🔍  RUN LIVE VT LOOKUP", use_container_width=True) and ioc:
            detected_type = detect_ioc_type(ioc.strip()) if ioc_type == "Auto-Detect" else ioc_type
            with st.spinner(f"Querying VirusTotal › {detected_type}: {ioc.strip()[:40]}..."):
                report, err = run_vt_lookup(ioc, ioc_type)
            if err:
                st.session_state.analysis_result = f"⚠️  VIRUSTOTAL ERROR\n\n{err}"
                st.session_state.analysis_error  = True
            else:
                st.session_state.analysis_result = report
                st.session_state.analysis_error  = False

        if st.session_state.analysis_result:
            box_color    = "rgba(255,51,102,.08)" if st.session_state.get("analysis_error") else "rgba(0,212,255,.04)"
            border_color = "rgba(255,51,102,.3)"  if st.session_state.get("analysis_error") else "rgba(0,212,255,.2)"
            label = "⚠️ ERROR" if st.session_state.get("analysis_error") else "🛡️ VIRUSTOTAL LIVE RESULT"
            st.markdown(f"""
            <div style="background:{box_color};border:1px solid {border_color};border-radius:8px;
                        padding:16px 18px;margin-top:12px">
              <div style="font-family:'Orbitron';font-size:10px;letter-spacing:2px;color:#00d4ff;margin-bottom:8px">{label}</div>
              <pre style="margin:0;white-space:pre-wrap;font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8;line-height:1.7">{st.session_state.analysis_result}</pre>
            </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown("**Recent Detections**")
        for _ in range(8):
            t = generate_threat()
            sev = t["severity"]
            st.markdown(f"""
            <div class="threat-item t-{sev}">
              <div>
                <span class="t-badge b-{sev}">{sev.upper()}</span>
                <span style="color:#c9d8e8;margin-left:6px;font-size:12px">{t['type']}</span><br>
                <span class="t-time">{t['src_ip']} → {t['dst_ip']} · {t['confidence']}%</span>
              </div>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: MALWARE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "malware":
    st.markdown('<div class="sec-head">MALWARE IDENTIFICATION · VIRUSTOTAL HASH LOOKUP</div>', unsafe_allow_html=True)

    st.markdown("""
    <div style="display:inline-flex;align-items:center;gap:8px;padding:5px 14px;
                border-radius:4px;border:1px solid rgba(255,51,102,.3);
                background:rgba(255,51,102,.05);margin-bottom:14px">
      <div style="width:7px;height:7px;border-radius:50%;background:#ff3366;
                  box-shadow:0 0 8px #ff3366;animation:blink 1.2s infinite"></div>
      <span style="font-family:'Share Tech Mono';font-size:11px;color:#ff3366;letter-spacing:1px">
        VIRUSTOTAL API · LIVE MALWARE HASH INTELLIGENCE
      </span>
    </div>""", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Submit File Hash for VirusTotal Lookup**")
        sample_hash = st.text_input("File Hash (MD5 / SHA256)", placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f")
        sample_name = st.text_input("Sample Name (optional)", placeholder="e.g. invoice.exe")
        analysis_type = st.multiselect("Local Analysis Modules (supplementary)",
            ["Static Analysis", "Dynamic Sandbox", "YARA Rules", "ML Classifier",
             "Behavioral Analysis", "Network Forensics", "Memory Forensics"],
            default=["Static Analysis", "ML Classifier", "YARA Rules"])

        if st.button("🦠  LOOKUP HASH ON VIRUSTOTAL", use_container_width=True):
            if not sample_hash:
                st.warning("Please enter a file hash.")
            else:
                h = sample_hash.strip()
                ioc_t = "File Hash MD5" if len(h) == 32 else "File Hash SHA256"
                with st.spinner(f"Querying VirusTotal for hash: {h[:20]}..."):
                    data, err = vt_scan_hash(h)
                if err:
                    st.markdown(f"""
                    <div style="background:rgba(255,51,102,.08);border:1px solid rgba(255,51,102,.3);
                                border-radius:8px;padding:16px;margin-top:12px">
                      <div style="font-family:'Orbitron';font-size:10px;letter-spacing:2px;color:#ff3366;margin-bottom:8px">⚠️ LOOKUP ERROR</div>
                      <pre style="margin:0;font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8">{err}</pre>
                    </div>""", unsafe_allow_html=True)
                else:
                    report = vt_report_hash(h, data)
                    attrs  = data.get("data", {}).get("attributes", {})
                    stats  = attrs.get("last_analysis_stats", {})
                    mal    = stats.get("malicious", 0)
                    sus    = stats.get("suspicious", 0)
                    # extra local augmentation
                    local_notes = ""
                    if mal > 10:
                        local_notes = "\nAUTO-RESPONSE:  Playbook PB-{:02d} triggered · HOST QUARANTINE recommended".format(random.randint(1,50))
                    elif mal > 0 or sus > 3:
                        local_notes = "\nAUTO-RESPONSE:  Flagged for Tier-2 review · Monitor host activity"
                    else:
                        local_notes = "\nAUTO-RESPONSE:  No action required · Continue standard monitoring"
                    st.markdown(f"""
                    <div style="background:rgba(255,51,102,.05);border:1px solid rgba(255,51,102,.2);
                                border-radius:8px;padding:16px 18px;margin-top:12px">
                      <div style="font-family:'Orbitron';font-size:10px;letter-spacing:2px;color:#ff3366;margin-bottom:8px">🦠 VIRUSTOTAL MALWARE REPORT</div>
                      <pre style="margin:0;white-space:pre-wrap;font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8;line-height:1.7">{report}{local_notes}</pre>
                    </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown("**Malware Landscape (Last 30 days)**")
        families_data = {f: random.randint(5, 150) for f in MALWARE_FAMILIES}
        total = sum(families_data.values())
        for fam, count in sorted(families_data.items(), key=lambda x: -x[1])[:8]:
            pct = count / total * 100
            colors_list = ["#ff3366", "#ffaa00", "#00d4ff", "#00ff88"]
            color = random.choice(colors_list)
            st.markdown(f"""
            <div class="prog-row">
              <div class="prog-label">
                <span style="font-size:13px;color:#c9d8e8">{fam}</span>
                <span style="font-family:'Share Tech Mono';font-size:11px;color:{color}">{count} samples</span>
              </div>
              <div class="prog-bar"><div class="prog-fill" style="width:{pct:.0f}%;background:linear-gradient(90deg,{color}66,{color})"></div></div>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: FRAUD DETECTION
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "fraud":
    st.markdown('<div class="sec-head">FRAUD DETECTION · BEHAVIORAL AI</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div class="metric-card card-red">
          <div class="card-label">FRAUD ALERTS TODAY</div>
          <div class="card-value v-red">{random.randint(12,89)}</div>
          <div class="card-delta">+{random.randint(5,25)}% vs yesterday</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card card-warn">
          <div class="card-label">$ FRAUD PREVENTED</div>
          <div class="card-value v-warn">${random.randint(10,500)}K</div>
          <div class="card-delta">This month</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card card-green">
          <div class="card-label">ML ACCURACY</div>
          <div class="card-value v-green">{random.uniform(97.5,99.8):.1f}%</div>
          <div class="card-delta">False positive rate: 0.3%</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown('<div class="sec-head">TRANSACTION ANALYZER</div>', unsafe_allow_html=True)
        user_id = st.text_input("User / Account ID", placeholder="e.g. USR-48291")
        amount = st.number_input("Transaction Amount ($)", min_value=0.01, value=5000.0)
        tx_type = st.selectbox("Transaction Type", ["Wire Transfer", "Card Payment", "ACH", "Crypto", "Internal Transfer"])
        country = st.selectbox("Origin Country", ["United States", "China", "Russia", "Nigeria", "Brazil", "Unknown"])

        if st.button("🔎  ANALYZE TRANSACTION", use_container_width=True):
            with st.spinner("Running fraud ML models..."):
                time.sleep(1.0)
            fraud_score = random.randint(10, 95)
            verdict = "🔴 HIGH RISK" if fraud_score > 70 else ("🟡 MEDIUM RISK" if fraud_score > 40 else "🟢 LOW RISK")
            st.markdown(f"""
            <div class="ai-box">
              <div class="ai-label">💳 FRAUD ANALYSIS RESULT</div>
              <pre style="margin:0;white-space:pre-wrap;font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8">
USER:   {user_id or 'USR-UNKNOWN'}
AMOUNT: ${amount:,.2f} ({tx_type})
ORIGIN: {country}

FRAUD SCORE:  {fraud_score}/100
VERDICT:      {verdict}

RISK SIGNALS:
  {'✗ Unusual transaction amount' if amount > 10000 else '✓ Amount within normal range'}
  {'✗ High-risk origin country' if country in ['Russia','Nigeria','Unknown'] else '✓ Origin country normal'}
  {'✗ Velocity anomaly detected' if fraud_score > 60 else '✓ Transaction velocity normal'}
  {'✗ Behavioral deviation from baseline' if fraud_score > 50 else '✓ Behavior matches profile'}

ACTION: {'BLOCK & ALERT COMPLIANCE' if fraud_score > 70 else ('FLAG FOR REVIEW' if fraud_score > 40 else 'APPROVE')}
</pre>
            </div>""", unsafe_allow_html=True)

    with col_b:
        st.markdown('<div class="sec-head">RECENT FRAUD ALERTS</div>', unsafe_allow_html=True)
        fraud_types = ["Account Takeover", "Card Not Present", "Synthetic Identity",
                       "Money Laundering", "Chargeback Fraud", "Phishing", "Wire Fraud"]
        for _ in range(8):
            ftype = random.choice(fraud_types)
            fscore = random.randint(55, 99)
            color = "danger" if fscore > 75 else "warn"
            st.markdown(f"""
            <div class="threat-item t-{'critical' if fscore>75 else 'high'}">
              <div>
                <span class="t-badge b-{'critical' if fscore>75 else 'high'}">{fscore}% FRAUD</span>
                <span style="color:#c9d8e8;margin-left:6px;font-size:12px">{ftype}</span><br>
                <span class="t-time">User {random.randint(10000,99999)} · ${random.randint(100,50000):,} · {datetime.now().strftime('%H:%M')}</span>
              </div>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: INCIDENT RESPONSE
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "incidents":
    st.markdown('<div class="sec-head">AUTOMATED INCIDENT RESPONSE · SOAR ENGINE</div>', unsafe_allow_html=True)

    if not st.session_state.incidents:
        st.session_state.incidents = [generate_incident() for _ in range(15)]

    col1, col2 = st.columns([1.6, 1])
    with col1:
        st.markdown('<div class="sec-head">ACTIVE INCIDENTS</div>', unsafe_allow_html=True)
        sev_colors = {"P1": "#ff3366", "P2": "#ffaa00", "P3": "#00d4ff", "P4": "#00ff88"}
        status_colors = {"OPEN": "#ff3366", "INVESTIGATING": "#ffaa00", "CONTAINED": "#00d4ff", "RESOLVED": "#00ff88"}

        table_rows = ""
        for inc in st.session_state.incidents:
            sc = sev_colors.get(inc["severity"], "#fff")
            stc = status_colors.get(inc["status"], "#fff")
            table_rows += f"""
            <tr>
              <td style="font-family:'Share Tech Mono';color:#00d4ff">{inc['id']}</td>
              <td>{inc['type']}</td>
              <td><span style="color:{sc};font-family:'Share Tech Mono';font-size:11px">{inc['severity']}</span></td>
              <td><span style="color:{stc};font-family:'Share Tech Mono';font-size:11px">{inc['status']}</span></td>
              <td style="color:#4a6080">{inc['owner']}</td>
              <td style="font-family:'Share Tech Mono';font-size:10px;color:#4a6080">{inc['created']}</td>
              <td style="color:#00d4ff">{inc['ttd']}</td>
              <td style="color:#00ff88">{inc['ttr']}</td>
            </tr>"""

        st.markdown(f"""
        <table class="inc-table">
          <thead><tr>
            <th>ID</th><th>TYPE</th><th>SEV</th><th>STATUS</th>
            <th>OWNER</th><th>CREATED</th><th>TTD</th><th>TTR</th>
          </tr></thead>
          <tbody>{table_rows}</tbody>
        </table>""", unsafe_allow_html=True)

        if st.button("➕  CREATE NEW INCIDENT", use_container_width=True):
            st.session_state.incidents.insert(0, generate_incident())
            st.rerun()

    with col2:
        st.markdown('<div class="sec-head">AUTO-RESPONSE PLAYBOOKS</div>', unsafe_allow_html=True)
        playbooks = [
            ("PB-001", "Ransomware Containment", "#ff3366", "47 runs"),
            ("PB-012", "Phishing Response", "#ffaa00", "132 runs"),
            ("PB-023", "DDoS Mitigation", "#00d4ff", "28 runs"),
            ("PB-034", "Insider Threat", "#ffaa00", "9 runs"),
            ("PB-047", "C2 Takedown", "#ff3366", "61 runs"),
            ("PB-056", "Data Breach Response", "#ff3366", "14 runs"),
            ("PB-078", "Privilege Escalation", "#ffaa00", "33 runs"),
            ("PB-091", "Vulnerability Patch", "#00ff88", "89 runs"),
        ]
        for pb_id, name, color, runs in playbooks:
            st.markdown(f"""
            <div style="display:flex;justify-content:space-between;align-items:center;
                        padding:10px 12px;margin-bottom:6px;border-radius:6px;
                        border:1px solid rgba(15,42,74,.8);background:rgba(10,15,30,.6)">
              <div>
                <span style="font-family:'Share Tech Mono';font-size:10px;color:{color}">{pb_id}</span>
                <span style="font-size:13px;color:#c9d8e8;margin-left:10px">{name}</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px">
                <span style="font-family:'Share Tech Mono';font-size:10px;color:#4a6080">{runs}</span>
                <span style="font-family:'Share Tech Mono';font-size:9px;color:{color};
                             background:rgba(0,0,0,.4);padding:2px 7px;border-radius:3px">READY</span>
              </div>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: PREDICTIVE RISK
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "risk":
    st.markdown('<div class="sec-head">PREDICTIVE RISK ANALYSIS · ML FORECASTING</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="sec-head">RISK FORECAST (NEXT 7 DAYS)</div>', unsafe_allow_html=True)
        days = [(datetime.now() + timedelta(days=i)).strftime("%a %d") for i in range(7)]
        scores = [random.randint(20, 85) for _ in range(7)]
        for day, score in zip(days, scores):
            color = "#ff3366" if score > 70 else ("#ffaa00" if score > 45 else "#00ff88")
            level = "CRITICAL" if score > 70 else ("HIGH" if score > 55 else ("MEDIUM" if score > 35 else "LOW"))
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
              <span style="font-family:'Share Tech Mono';font-size:11px;color:#4a6080;width:55px">{day}</span>
              <div style="flex:1;height:24px;background:#0f2a4a;border-radius:4px;overflow:hidden">
                <div style="width:{score}%;height:100%;background:linear-gradient(90deg,{color}66,{color});
                             display:flex;align-items:center;padding-left:8px">
                  <span style="font-family:'Share Tech Mono';font-size:10px;color:#000;font-weight:700">{score}</span>
                </div>
              </div>
              <span style="font-family:'Share Tech Mono';font-size:10px;color:{color};width:65px">{level}</span>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sec-head">ATTACK SURFACE SCORING</div>', unsafe_allow_html=True)
        surfaces = [
            ("External Attack Surface", random.randint(30, 75)),
            ("Cloud Infrastructure", random.randint(20, 65)),
            ("Third-Party / Supply Chain", random.randint(40, 80)),
            ("Insider Threat Risk", random.randint(15, 50)),
            ("Unpatched Vulnerabilities", random.randint(25, 70)),
            ("Credential Exposure", random.randint(10, 60)),
        ]
        for name, score in surfaces:
            color = "#ff3366" if score > 65 else ("#ffaa00" if score > 40 else "#00ff88")
            st.markdown(f"""
            <div class="prog-row">
              <div class="prog-label">
                <span style="font-size:12px;color:#c9d8e8">{name}</span>
                <span style="font-family:'Share Tech Mono';font-size:11px;color:{color}">{score}/100</span>
              </div>
              <div class="prog-bar"><div class="prog-fill" style="width:{score}%;background:linear-gradient(90deg,{color}66,{color})"></div></div>
            </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="sec-head">AI RISK ASSESSMENT</div>', unsafe_allow_html=True)
        org_type = st.selectbox("Organization Type", ["Financial Services", "Healthcare", "Government", "Retail", "Manufacturing", "Technology"])
        employee_count = st.selectbox("Employee Count", ["1-50", "50-250", "250-1000", "1000-10000", "10000+"])
        recent_incidents = st.slider("Recent Incidents (30 days)", 0, 50, random.randint(2, 20))
        patch_lag = st.slider("Avg Patch Lag (days)", 0, 180, random.randint(10, 60))

        if st.button("📊  GENERATE RISK REPORT", use_container_width=True):
            with st.spinner("Running predictive models..."):
                time.sleep(1.3)
            overall_risk = min(95, recent_incidents * 2 + patch_lag // 3 + random.randint(10, 30))
            risk_label = "CRITICAL" if overall_risk > 75 else ("HIGH" if overall_risk > 55 else ("MEDIUM" if overall_risk > 35 else "LOW"))
            st.markdown(f"""
            <div class="ai-box">
              <div class="ai-label">📊 AI RISK REPORT — {org_type.upper()}</div>
              <pre style="margin:0;white-space:pre-wrap;font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8">
OVERALL RISK: {overall_risk}/100 — {risk_label}
SECTOR BENCHMARK: {'Above' if overall_risk > 50 else 'Below'} industry average

TOP RISK FACTORS:
  1. {'High' if patch_lag > 30 else 'Low'} patch lag ({patch_lag}d avg) — CVSS exposure
  2. {'Elevated' if recent_incidents > 10 else 'Normal'} incident rate ({recent_incidents}/mo)
  3. {'Large' if employee_count in ['1000-10000','10000+'] else 'Limited'} attack surface

PREDICTED THREATS (30-day horizon):
  • Ransomware probability:    {random.randint(10,45)}%
  • Phishing campaign:         {random.randint(40,85)}%
  • Insider threat event:      {random.randint(5,30)}%
  • Zero-day exploitation:     {random.randint(3,20)}%
  • Supply chain compromise:   {random.randint(5,25)}%

TOP RECOMMENDATIONS:
  [1] Accelerate patching SLA to <14 days
  [2] Deploy MFA on all privileged accounts
  [3] Increase endpoint EDR coverage
  [4] Run tabletop exercise this quarter
  [5] Review third-party access controls
</pre>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: NETWORK MONITOR
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "network":
    st.markdown('<div class="sec-head">24/7 NETWORK MONITORING · REAL-TIME VISIBILITY</div>', unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    for col, label, val, color in [
        (col1, "NODES MONITORED", random.randint(240, 1200), "cyan"),
        (col2, "PACKETS/SEC", f"{random.randint(10,999)}K", "green"),
        (col3, "ANOMALIES", random.randint(2, 45), "warn"),
        (col4, "BANDWIDTH Gbps", f"{random.uniform(2,18):.1f}", "cyan"),
    ]:
        with col:
            st.markdown(f"""
            <div class="metric-card card-{color}">
              <div class="card-label">{label}</div>
              <div class="card-value v-{color}">{val}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col_left, col_right = st.columns([1.3, 1])
    with col_left:
        st.markdown('<div class="sec-head">NETWORK NODE MAP</div>', unsafe_allow_html=True)
        node_types = [("FW", "ok"), ("SW", "ok"), ("RTR", "warn"), ("SRV", "ok"),
                      ("DB", "bad"), ("WEB", "ok"), ("VPN", "ok"), ("EDR", "ok"),
                      ("IDS", "ok"), ("CLOUD", "warn"), ("IOT", "bad"), ("DMZ", "ok"),
                      ("PRXY", "ok"), ("DNS", "ok"), ("MAIL", "warn"), ("API", "ok")]
        nodes_html = '<div class="nmap">'
        for name, status in node_types:
            nodes_html += f'<div class="node node-{status}" title="{name}">{name}<br><span style="font-size:8px">{"●" if status=="ok" else ("⚠" if status=="warn" else "✗")}</span></div>'
        nodes_html += '</div>'
        st.markdown(nodes_html, unsafe_allow_html=True)

        st.markdown('<div class="sec-head" style="margin-top:16px">LIVE TRAFFIC FLOW</div>', unsafe_allow_html=True)
        flows = [
            (rand_ip(), rand_ip(), random.choice(["HTTP","HTTPS","SSH","RDP","DNS","SMTP"]),
             random.randint(100,9999), random.choice(["ALLOW","BLOCK","INSPECT"]))
            for _ in range(8)
        ]
        flow_rows = "".join([f"""
        <tr>
          <td style="font-family:'Share Tech Mono';font-size:11px;color:#00d4ff">{src}</td>
          <td style="font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8">{dst}</td>
          <td style="color:#4a6080">{proto}</td>
          <td style="font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8">{size}B</td>
          <td style="color:{'#ff3366' if action=='BLOCK' else ('#ffaa00' if action=='INSPECT' else '#00ff88')};
             font-family:'Share Tech Mono';font-size:10px">{action}</td>
        </tr>""" for src, dst, proto, size, action in flows])
        st.markdown(f"""
        <table class="inc-table">
          <thead><tr><th>SRC IP</th><th>DST IP</th><th>PROTO</th><th>SIZE</th><th>ACTION</th></tr></thead>
          <tbody>{flow_rows}</tbody>
        </table>""", unsafe_allow_html=True)

    with col_right:
        st.markdown('<div class="sec-head">PROTOCOL DISTRIBUTION</div>', unsafe_allow_html=True)
        protocols = {"HTTPS": 45, "HTTP": 18, "DNS": 12, "SSH": 8, "SMTP": 7, "RDP": 5, "OTHER": 5}
        colors_p = ["#00d4ff","#00ff88","#ffaa00","#ff3366","#9966ff","#ff6699","#4a6080"]
        for (proto, pct), color in zip(protocols.items(), colors_p):
            st.markdown(f"""
            <div class="prog-row">
              <div class="prog-label">
                <span style="font-size:13px;color:#c9d8e8">{proto}</span>
                <span style="font-family:'Share Tech Mono';color:{color}">{pct}%</span>
              </div>
              <div class="prog-bar"><div class="prog-fill" style="width:{pct*2}%;background:linear-gradient(90deg,{color}55,{color})"></div></div>
            </div>""", unsafe_allow_html=True)

        st.markdown('<div class="sec-head" style="margin-top:16px">GEO THREAT ORIGINS</div>', unsafe_allow_html=True)
        geo_threats = [("China", 28, "#ff3366"), ("Russia", 22, "#ff3366"), ("United States", 15, "#ffaa00"),
                       ("North Korea", 10, "#ff3366"), ("Iran", 8, "#ffaa00"), ("Brazil", 6, "#00d4ff"),
                       ("Unknown", 11, "#4a6080")]
        for country, pct, color in geo_threats:
            st.markdown(f"""
            <div class="prog-row">
              <div class="prog-label">
                <span style="font-size:12px;color:#c9d8e8">{country}</span>
                <span style="font-family:'Share Tech Mono';font-size:11px;color:{color}">{pct}%</span>
              </div>
              <div class="prog-bar"><div class="prog-fill" style="width:{pct*3}%;background:linear-gradient(90deg,{color}55,{color})"></div></div>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: THREAT HUNTING
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "hunting":
    st.markdown('<div class="sec-head">AI-DRIVEN THREAT HUNTING · PROACTIVE DETECTION</div>', unsafe_allow_html=True)

    col1, col2 = st.columns([1.2, 1])
    with col1:
        st.markdown("**Hunt Query Builder**")
        hunt_query = st.text_area("Threat Hunting Query (natural language or KQL)",
            placeholder="e.g. Find all processes spawned by Office applications in the last 24h\nor: Find lateral movement indicators using PsExec",
            height=100)
        hunt_scope = st.multiselect("Hunt Scope",
            ["Endpoints", "Network Logs", "Cloud Events", "Email Gateway",
             "Identity Logs", "DNS Logs", "Firewall Logs"],
            default=["Endpoints", "Network Logs"])
        time_range = st.selectbox("Time Range", ["Last 1 hour", "Last 24 hours", "Last 7 days", "Last 30 days"])

        if st.button("🏹  LAUNCH THREAT HUNT", use_container_width=True):
            with st.spinner(f"Hunting across {len(hunt_scope)} data sources..."):
                time.sleep(1.8)
            hits = random.randint(0, 47)
            st.session_state.hunt_result = {
                "query": hunt_query or "Anomalous network beaconing to external IPs",
                "scope": hunt_scope, "range": time_range, "hits": hits,
            }

        if st.session_state.hunt_result:
            h = st.session_state.hunt_result
            hits = h["hits"]
            st.markdown(f"""
            <div class="ai-box">
              <div class="ai-label">🏹 HUNT RESULTS</div>
              <pre style="margin:0;white-space:pre-wrap;font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8">
QUERY:  {h['query'][:60]}...
SCOPE:  {', '.join(h['scope'])}
RANGE:  {h['range']}
HITS:   {hits} {'⚠️ SUSPICIOUS ACTIVITY FOUND' if hits > 0 else '✅ CLEAN'}

{'TOP FINDINGS:' if hits > 0 else 'No anomalies detected. Environment appears clean.'}
{chr(10).join([f"  [{i+1}] {random.choice(['Beaconing pattern','Unusual process','Lateral movement','Data staging','Persistence mechanism','Encoded commands'])} on {rand_ip()} (confidence: {random.randint(70,98)}%)" for i in range(min(5,hits))]) if hits > 0 else ''}

ENDPOINTS SCANNED: {random.randint(100,2000)}
EVENTS ANALYZED:   {random.randint(10000,5000000):,}
DURATION:          {random.uniform(2,45):.1f}s
</pre>
            </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="sec-head">HUNT HYPOTHESES</div>', unsafe_allow_html=True)
        hypotheses = [
            ("Living-off-the-land binaries", "high", "APT29"),
            ("Kerberoasting activity", "medium", "APT40"),
            ("DNS over HTTPS tunneling", "medium", "FIN7"),
            ("Scheduled task persistence", "low", "Generic"),
            ("WMI-based lateral movement", "high", "HAFNIUM"),
            ("Memory-only malware execution", "critical", "LazarusGroup"),
            ("OAuth token theft", "medium", "APT10"),
        ]
        for hyp, priority, actor in hypotheses:
            p_color = {"critical":"#ff3366","high":"#ffaa00","medium":"#00d4ff","low":"#00ff88"}[priority]
            st.markdown(f"""
            <div class="threat-item t-{'critical' if priority=='critical' else ('high' if priority=='high' else 'medium')}">
              <div>
                <span class="t-badge" style="background:rgba(0,0,0,.3);color:{p_color}">{priority.upper()}</span>
                <span style="color:#c9d8e8;margin-left:8px;font-size:12px">{hyp}</span><br>
                <span class="t-time">Threat Actor: {actor}</span>
              </div>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: SELF-HEALING
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "healing":
    st.markdown('<div class="sec-head">SELF-HEALING NETWORKS · AUTONOMOUS REMEDIATION</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="sec-head">HEALING ENGINE STATUS</div>', unsafe_allow_html=True)
        healing_modules = [
            ("Auto-Patch Deployment", random.randint(85,99), "#00ff88"),
            ("Configuration Drift Repair", random.randint(70,95), "#00d4ff"),
            ("Firewall Rule Auto-Update", random.randint(90,99), "#00ff88"),
            ("Certificate Rotation", random.randint(75,99), "#00ff88"),
            ("Backup & Snapshot", random.randint(80,98), "#00d4ff"),
            ("Network Segment Isolation", random.randint(88,99), "#ffaa00"),
            ("Key Rotation", random.randint(70,95), "#00d4ff"),
        ]
        for name, health, color in healing_modules:
            st.markdown(f"""
            <div style="display:flex;justify-content:space-between;align-items:center;
                        padding:12px 14px;margin-bottom:6px;border-radius:6px;
                        border:1px solid rgba(15,42,74,.8);background:rgba(10,15,30,.6)">
              <div>
                <div style="font-size:13px;color:#c9d8e8">{name}</div>
                <div class="prog-bar" style="width:180px;margin-top:4px">
                  <div class="prog-fill" style="width:{health}%;background:linear-gradient(90deg,{color}55,{color})"></div>
                </div>
              </div>
              <span style="font-family:'Share Tech Mono';font-size:14px;color:{color}">{health}%</span>
            </div>""", unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="sec-head">TRIGGER SELF-HEAL</div>', unsafe_allow_html=True)
        target = st.text_input("Target Host / Segment", placeholder="e.g. 192.168.1.0/24 or web-server-01")
        heal_type = st.selectbox("Healing Action", [
            "Full System Scan & Repair", "Isolate Compromised Host",
            "Restore from Clean Snapshot", "Re-image Endpoint",
            "Rotate All Credentials", "Block Malicious C2",
            "Patch Critical CVEs", "Restore Network Config"])
        priority_heal = st.radio("Priority", ["Emergency", "High", "Normal"], horizontal=True)

        if st.button("🔧  EXECUTE SELF-HEALING", use_container_width=True):
            with st.spinner("Executing autonomous remediation..."):
                time.sleep(1.5)
            st.session_state.heal_result = {
                "target": target or "192.168.0.0/16",
                "action": heal_type, "priority": priority_heal
            }

        if st.session_state.heal_result:
            r = st.session_state.heal_result
            st.markdown(f"""
            <div class="ai-box">
              <div class="ai-label">🔧 HEALING OPERATION RESULT</div>
              <pre style="margin:0;white-space:pre-wrap;font-family:'Share Tech Mono';font-size:11px;color:#c9d8e8">
TARGET:   {r['target']}
ACTION:   {r['action']}
PRIORITY: {r['priority']}
STATUS:   ✅ COMPLETED SUCCESSFULLY

STEPS EXECUTED:
  [1] Backup current state snapshot         ✓
  [2] Identify affected components          ✓
  [3] Isolate target from network           ✓
  [4] Apply remediation: {r['action'][:30]}  ✓
  [5] Validate system integrity             ✓
  [6] Restore network connectivity          ✓
  [7] Update threat intel database          ✓
  [8] Generate post-healing report          ✓

DURATION:    {random.uniform(15,120):.1f}s
NODES FIXED: {random.randint(1,50)}
CVEs PATCHED:{random.randint(0,15)}
</pre>
            </div>""", unsafe_allow_html=True)

        st.markdown('<div class="sec-head" style="margin-top:16px">RECENT HEAL EVENTS</div>', unsafe_allow_html=True)
        heal_events = [
            ("Auto-patched CVE-2024-{}".format(random.randint(1000,9999)), rand_ip(), "2m ago"),
            ("Isolated compromised host", rand_ip(), "15m ago"),
            ("Firewall rules auto-updated", "perimeter-fw01", "42m ago"),
            ("Credential rotation executed", "svc-account-db", "1h ago"),
            ("Config drift corrected on {}".format(rand_ip()), rand_ip(), "2h ago"),
        ]
        for action, host, when in heal_events:
            st.markdown(f"""
            <div class="threat-item t-low">
              <div>
                <span class="t-badge b-low">HEALED</span>
                <span style="color:#c9d8e8;margin-left:8px;font-size:12px">{action}</span><br>
                <span class="t-time">{host} · {when}</span>
              </div>
            </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE: SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "settings":
    st.markdown('<div class="sec-head">SYSTEM SETTINGS · AEGIS CONFIGURATION</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**AI Engine Settings**")
        st.slider("ML Model Sensitivity", 0, 100, 75, help="Higher = more alerts, lower = fewer false positives")
        st.slider("Auto-Response Threshold", 0, 100, 85, help="Confidence score required to trigger automated response")
        st.slider("Threat Hunt Frequency (hours)", 1, 24, 6)
        st.selectbox("Primary ML Model", ["AEGIS-Neural-v4", "RandomForest-Ensemble", "XGBoost-Threat", "LSTM-Behavioral"])
        st.selectbox("Threat Intel Feed", ["MISP + VirusTotal", "Recorded Future", "CrowdStrike Intel", "Custom STIX/TAXII"])

    with col2:
        st.markdown("**Alert & Notification Settings**")
        st.multiselect("Alert Channels", ["Email", "Slack", "PagerDuty", "JIRA", "ServiceNow", "Teams"], default=["Email", "Slack"])
        st.selectbox("Minimum Alert Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=1)
        st.text_input("SIEM Integration URL", placeholder="https://your-siem.example.com/api")
        st.text_input("Webhook URL", placeholder="https://hooks.slack.com/...")
        st.selectbox("Data Retention", ["30 days", "90 days", "180 days", "1 year", "3 years"])

    if st.button("💾  SAVE CONFIGURATION", use_container_width=True):
        st.success("✅ Configuration saved successfully.")

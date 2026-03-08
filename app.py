from flask import Flask, render_template, request, send_file
import os
import subprocess
import time
import requests
from fpdf import FPDF
import re

# External modules
from modules.abuseipdb import check_ip
from modules.virustotal import check_file


app = Flask(__name__)

# =================================
# ATTACKMATRIX API CONFIG
# =================================

ATTACK_API = "http://127.0.0.1:8008/api"


def start_attackmatrix():
    try:
        requests.get(f"{ATTACK_API}/explore/Tactics", timeout=2)
        print("[+] AttackMatrix API already running")
    except:
        print("[+] Starting AttackMatrix API...")
        subprocess.Popen(
            ["python3", "attackmatrix/attackmatrix.py", "-d"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(4)
        print("[+] AttackMatrix API started")


start_attackmatrix()


# =================================
# LOAD MALWARE CATALOG FROM API
# =================================

malware_catalog = []

def load_catalog():
    global malware_catalog

    try:
        data = requests.get(f"{ATTACK_API}/search?params=rat").json()

        names = []

        if "Malwares" in data:
            for mid, m in data["Malwares"].items():
                names.extend(m["Metadata"]["name"])

        malware_catalog = sorted(list(set(names)))

        print(f"[+] Loaded catalog with {len(malware_catalog)} entries")

    except:
        print("[-] Failed to load catalog")


load_catalog()


# =================================
# GLOSSARY
# =================================

glossary_defs = {
    "APT": "Advanced Persistent Threat",
    "C2": "Command and Control server",
    "Exfiltration": "Stealing data from a network",
    "Lateral Movement": "Moving through a network",
    "MITRE ATT&CK": "Knowledge base of adversary techniques",
    "Phishing": "Tricking users to open malicious files",
    "Ransomware": "Malware encrypting files for ransom",
    "STIX": "Structured Threat Information Expression",
    "TTPs": "Tactics Techniques Procedures",
    "Zero-Day": "Unknown vulnerability exploited"
}


# =================================
# CLEAN TEXT
# =================================

def clean_text(text):

    if not text:
        return ""

    # Replace markdown links [text](url) -> text
    text = re.sub(r'\[([^\]]+)\]\((.*?)\)', r'\1', text)

    # Remove citation tags
    text = re.sub(r'\(Citation:.*?\)', '', text)

    # Fix unicode characters
    replacements = {
        '\u2018': "'",
        '\u2019': "'",
        '\u201c': '"',
        '\u201d': '"',
        '\u2013': '-',
        '\u2014': '-',
        '\u2026': '...'
    }

    for k, v in replacements.items():
        text = text.replace(k, v)

    return text


# =================================
# MAIN ROUTE
# =================================

@app.route('/', methods=['GET', 'POST'])
def index():

    results = None
    error = None
    search_term = ""

    ip_result = None
    vt_result = None
    file_hash = None

    if request.method == 'POST':

        search_term = request.form.get('malware', '').strip()
        ip = request.form.get("ip")
        file = request.files.get("file")

        # =========================
        # ABUSEIPDB
        # =========================

        if ip:
            ip_data = check_ip(ip)
            if ip_data:
                ip_result = ip_data["data"]

        # =========================
        # VIRUSTOTAL
        # =========================

        if file and file.filename != "":
            vt_data, file_hash = check_file(file)
            if vt_data:
                vt_result = vt_data["data"]["attributes"]["last_analysis_stats"]

        # =========================
        # MITRE SEARCH (API)
        # =========================

        if search_term:

            try:

                search = requests.get(
                    f"{ATTACK_API}/search?params={search_term}"
                ).json()

                if "Malwares" not in search:

                    error = f"No results found for '{search_term}'."

                else:

                    malware_id = list(search["Malwares"].keys())[0]

                    data = requests.get(
                        f"{ATTACK_API}/explore/Malwares/{malware_id}"
                    ).json()

                    metadata = data.get("Metadata", {})

                    malware_name = metadata.get("name", ["Unknown"])[0]
                    malware_desc = clean_text(metadata.get("description", ["No description"])[0])
                    malware_url = metadata.get("url", [""])[0]

                    techniques = data.get("Techniques", {})
                    mitigations = data.get("Mitigations", {})
                    actors_data = data.get("Actors", {})
                    tools_data = data.get("Tools", {})

                    clean_techs = []
                    phase_counts = {}

                    # SAFE ATTACK SURFACE COLLECTION
                    platforms_set = set()

                    for tid, t in techniques.items():

                        name = t["name"][0]
                        desc = clean_text(t["description"][0])

                        platforms = t.get("platforms", [])
                        for p in platforms:
                            platforms_set.add(p)

                        base = tid.split(".")[0]

                        # DO NOT TOUCH THIS LOGIC (avoids "other bug")

                        if base.startswith("T10"):
                            phase = "execution"
                        elif base.startswith("T11"):
                            phase = "credential-access"
                        elif base.startswith("T12"):
                            phase = "initial-access"
                        elif base.startswith("T15"):
                            phase = "defense-evasion"
                        else:
                            phase = "other"

                        phase_counts[phase] = phase_counts.get(phase, 0) + 1

                        clean_techs.append({
                            "id": tid,
                            "name": name,
                            "description": desc[:300] + "...",
                            "full_desc": desc,
                            "phase": phase,
                            "platforms": "Unknown"
                        })

                    defenses_list = []

                    for mid, m in mitigations.items():

                        mname = m["name"][0]
                        mdesc = m["description"][0][:200] + "..."

                        defenses_list.append(f"{mname}: {mdesc}")

                    actors = []

                    for aid, a in actors_data.items():

                        actors.append({
                            "name": a["name"][0],
                            "description": clean_text(a["description"][0])[:200] + "..."
                        })

                    tools = []

                    for tid, t in tools_data.items():

                        tools.append({
                            "name": t["name"][0],
                            "description": clean_text(t["description"][0])[:200] + "..."
                        })

                    count = len(clean_techs)

                    if count <= 5:
                        risk_level = "LOW"
                        risk_score = 25
                    elif count <= 10:
                        risk_level = "MEDIUM"
                        risk_score = 50
                    elif count <= 20:
                        risk_level = "HIGH"
                        risk_score = 75
                    else:
                        risk_level = "CRITICAL"
                        risk_score = 100

                    results = {
                        "name": malware_name,
                        "description": malware_desc,
                        "url": malware_url,
                        "actors": actors,
                        "tools": tools,
                        "platforms": list(platforms_set),  # ATTACK SURFACE
                        "id": malware_id,
                        "count": count,
                        "risk": risk_level,
                        "risk_score": risk_score,
                        "techniques": clean_techs,
                        "chart_data": phase_counts,
                        "defenses": defenses_list
                    }

                    generate_pdf_report(malware_name, clean_techs, defenses_list)

            except Exception as e:
                error = str(e)

    return render_template(
        'index.html',
        results=results,
        error=error,
        search_term=search_term,
        catalog=malware_catalog,
        glossary=glossary_defs,
        ip_result=ip_result,
        vt_result=vt_result,
        file_hash=file_hash
    )


# =================================
# PDF DOWNLOAD
# =================================

@app.route('/download_playbook/<name>')
def download_playbook(name):

    filename = f"{name}_Playbook.pdf"

    if os.path.exists(filename):
        return send_file(filename, as_attachment=True)

    return "Error: File not found"


# =================================
# PDF GENERATION
# =================================

def generate_pdf_report(name, techniques, defenses):

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 10, f"Threat Report: {clean_text(name)}", ln=True)

    pdf.ln(10)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Adversary Playbook", ln=True)

    for i, t in enumerate(techniques, 1):

        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, f"{i}. {clean_text(t['name'])} ({t['id']})", ln=True)

        pdf.set_font("Arial", "", 10)
        pdf.multi_cell(0, 6, clean_text(t["description"]))

        pdf.ln(2)

    pdf.add_page()

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Defense Blueprint", ln=True)

    for d in defenses[:20]:

        pdf.set_font("Arial", "", 10)
        pdf.multi_cell(0, 6, clean_text(d))

        pdf.ln(1)

    filename = f"{name}_Playbook.pdf"

    pdf.output(filename)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
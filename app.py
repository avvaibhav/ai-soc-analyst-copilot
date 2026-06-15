import os
import re
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

st.set_page_config(page_title="AI SOC Analyst Copilot", layout="wide")

st.title("AI-Powered SOC Analyst Copilot")
st.write(
    "Upload any CSV file. The app detects security-relevant fields, normalizes logs, "
    "maps activity to MITRE ATT&CK, and generates an AI-assisted SOC report."
)

def get_groq_api_key():
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        try:
            api_key = st.secrets["GROQ_API_KEY"]
        except Exception:
            api_key = None
    return api_key

api_key = get_groq_api_key()
client = Groq(api_key=api_key) if api_key else None

uploaded_file = st.file_uploader("Upload Any CSV File", type=["csv"])

def find_column(df, possible_names):
    columns_lower = {col.lower(): col for col in df.columns}
    for name in possible_names:
        if name.lower() in columns_lower:
            return columns_lower[name.lower()]
    return None

def extract_field(raw_text, field_name):
    if pd.isna(raw_text):
        return None

    pattern = rf"{field_name}=([^\n\r]+)"
    match = re.search(pattern, str(raw_text), re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return None

def detect_event_type(row):
    combined = " ".join([str(value) for value in row.values]).lower()

    if "failed login" in combined or "failed logon" in combined or "authentication failed" in combined:
        return "Failed Login"

    if "powershell" in combined:
        return "PowerShell Execution"

    if "encodedcommand" in combined or "encoded command" in combined:
        return "Encoded Command"

    if "rundll32" in combined or "regsvr32" in combined or "wmic" in combined:
        return "Suspicious Process"

    if "administrator" in combined and ("created" in combined or "added" in combined):
        return "New Admin User"

    if "privilege" in combined or "elevated" in combined:
        return "Privilege Escalation"

    if "ransomware" in combined or "encrypted" in combined or "mass file" in combined:
        return "Ransomware Activity"

    if "malware" in combined or "trojan" in combined or "backdoor" in combined:
        return "Malware Alert"

    if "error" in combined or "warning" in combined:
        return "System Warning/Error"

    if "information" in combined or "successfully" in combined:
        return "Informational Event"

    return "Generic Security/Event Log"

def estimate_severity(row):
    combined = " ".join([str(value) for value in row.values]).lower()

    if any(word in combined for word in ["critical", "ransomware", "malware", "trojan", "privilege escalation"]):
        return "Critical"

    if any(word in combined for word in ["failed login", "failed logon", "powershell", "encodedcommand", "administrator", "suspicious"]):
        return "High"

    if any(word in combined for word in ["warning", "error", "denied", "blocked"]):
        return "Medium"

    return "Low"

def map_mitre(row):
    combined = " ".join([str(value) for value in row.values]).lower()

    if "failed login" in combined or "failed logon" in combined or "authentication failed" in combined:
        return "T1110 - Brute Force"

    if "powershell" in combined:
        return "T1059.001 - PowerShell"

    if "encodedcommand" in combined or "encoded command" in combined or "obfuscated" in combined:
        return "T1027 - Obfuscated Files or Information"

    if "rundll32" in combined or "regsvr32" in combined or "wmic" in combined:
        return "T1218 - System Binary Proxy Execution"

    if "administrator" in combined and ("created" in combined or "added" in combined):
        return "T1098 - Account Manipulation"

    if "privilege" in combined or "elevated" in combined:
        return "T1068 - Exploitation for Privilege Escalation"

    if "ransomware" in combined or "encrypted" in combined or "mass file" in combined:
        return "T1486 - Data Encrypted for Impact"

    if "malware" in combined or "trojan" in combined:
        return "T1204 - User Execution"

    if "scheduled task" in combined:
        return "T1053 - Scheduled Task/Job"

    if "service installed" in combined or "new service" in combined:
        return "T1543.003 - Windows Service"

    if "registry" in combined:
        return "T1112 - Modify Registry"

    if "network connection" in combined or "connection allowed" in combined:
        return "T1049 - System Network Connections Discovery"

    return "Needs Analyst Review"

def normalize_csv(df):
    timestamp_col = find_column(df, ["timestamp", "time", "TimeGenerated", "TimeCreated", "_time", "date"])
    source_ip_col = find_column(df, ["source_ip", "src_ip", "SourceIP", "ClientIP", "IpAddress", "ip"])
    user_col = find_column(df, ["user", "username", "Account", "AccountName", "UserName", "SubjectUserName"])
    host_col = find_column(df, ["host", "hostname", "Computer", "ComputerName", "DeviceName", "machine"])
    event_col = find_column(df, ["event_type", "AlertName", "EventType", "EventID", "EventCode", "ProcessName", "Activity", "Operation"])
    severity_col = find_column(df, ["severity", "Severity", "level", "risk", "priority", "Type"])
    description_col = find_column(df, ["description", "Message", "event", "CommandLine", "Details", "AlertDescription", "_raw"])
    raw_col = find_column(df, ["_raw", "raw", "message", "Message"])

    normalized_df = pd.DataFrame()

    normalized_df["timestamp"] = df[timestamp_col] if timestamp_col else "Unknown"
    normalized_df["source_ip"] = df[source_ip_col] if source_ip_col else "Unknown"
    normalized_df["host"] = df[host_col] if host_col else "Unknown"

    if user_col:
        normalized_df["user"] = df[user_col]
    elif raw_col:
        normalized_df["user"] = df[raw_col].apply(lambda x: extract_field(x, "User") or "Unknown")
    else:
        normalized_df["user"] = "Unknown"

    if event_col:
        normalized_df["event_type"] = df[event_col].astype(str)
    elif raw_col:
        normalized_df["event_type"] = df[raw_col].apply(
            lambda x: extract_field(x, "SourceName") or extract_field(x, "EventCode") or "Windows Event Log"
        )
    else:
        normalized_df["event_type"] = df.apply(detect_event_type, axis=1)

    if severity_col:
        normalized_df["severity"] = df[severity_col].astype(str)
    elif raw_col:
        normalized_df["severity"] = df[raw_col].apply(lambda x: extract_field(x, "Type") or "Low")
    else:
        normalized_df["severity"] = df.apply(estimate_severity, axis=1)

    if description_col:
        normalized_df["description"] = df[description_col].astype(str).str.slice(0, 500)
    else:
        normalized_df["description"] = df.astype(str).agg(" | ".join, axis=1).str.slice(0, 500)

    if raw_col:
        normalized_df["event_code"] = df[raw_col].apply(lambda x: extract_field(x, "EventCode") or "Unknown")
        normalized_df["source_name"] = df[raw_col].apply(lambda x: extract_field(x, "SourceName") or "Unknown")
    else:
        normalized_df["event_code"] = "Unknown"
        normalized_df["source_name"] = "Unknown"

    normalized_df["Detected Event Category"] = normalized_df.apply(detect_event_type, axis=1)
    normalized_df["MITRE Technique"] = normalized_df.apply(map_mitre, axis=1)

    return normalized_df

def generate_ai_report(original_data, normalized_data):
    prompt = f"""
You are a senior SOC analyst and incident responder.

Analyze the following security log data. It may come from Splunk, Microsoft Sentinel, Sysmon, Windows Event Logs, EDR, firewall, IAM, or cloud logs.

Produce a professional SOC investigation report.

Important:
- If logs are mostly informational, state that clearly.
- Do not exaggerate risk.
- Identify what requires analyst review.
- Mention whether there is enough evidence for compromise.

Include:
1. Executive Summary
2. Data Source Understanding
3. Key Observations
4. Suspicious or High-Risk Events
5. MITRE ATT&CK Mapping
6. Severity Assessment
7. Possible Attack Chain
8. Threat Hunting Recommendations
9. Containment Recommendations
10. Remediation Recommendations
11. Analyst Notes
12. Final Conclusion

Original CSV Preview:
{original_data}

Normalized SOC View:
{normalized_data}
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": "You are an expert SOC analyst specializing in SIEM alert triage, Windows Event Logs, Splunk logs, threat hunting, incident response, and MITRE ATT&CK mapping.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content

if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Could not read CSV file: {e}")
        st.stop()

    if df.empty:
        st.error("Uploaded CSV is empty.")
        st.stop()

    st.subheader("Original Uploaded CSV")
    st.dataframe(df.head(100))

    normalized_df = normalize_csv(df)

    st.subheader("Normalized SOC Alert View")
    st.dataframe(normalized_df.head(100))

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Rows", len(df))
    col2.metric("Detected Hosts", normalized_df["host"].nunique())
    col3.metric("Detected Users", normalized_df["user"].nunique())
    col4.metric(
        "Items Needing Review",
        len(normalized_df[normalized_df["MITRE Technique"] == "Needs Analyst Review"]),
    )

    st.subheader("Severity Distribution")
    st.bar_chart(normalized_df["severity"].astype(str).value_counts())

    st.subheader("Detected Event Categories")
    st.bar_chart(normalized_df["Detected Event Category"].astype(str).value_counts())

    st.subheader("MITRE ATT&CK Mapping")
    st.dataframe(
        normalized_df[
            [
                "timestamp",
                "host",
                "user",
                "event_type",
                "event_code",
                "source_name",
                "severity",
                "Detected Event Category",
                "MITRE Technique",
            ]
        ].head(100)
    )

    st.subheader("AI Incident Investigation")

    if st.button("Generate AI Incident Report"):
        if not client:
            st.error("Groq API key is missing. Add it in .env locally or Streamlit Secrets online.")
        else:
            try:
                with st.spinner("Generating AI incident report..."):
                    safe_df = df.head(10).copy()
                    safe_normalized_df = normalized_df.head(10).copy()

                    for col in safe_df.columns:
                        safe_df[col] = safe_df[col].astype(str).str.slice(0, 300)

                    for col in safe_normalized_df.columns:
                        safe_normalized_df[col] = safe_normalized_df[col].astype(str).str.slice(0, 300)

                    original_preview = safe_df.to_string(index=False)
                    normalized_preview = safe_normalized_df.to_string(index=False)

                    report = generate_ai_report(original_preview, normalized_preview)

                st.success("AI incident report generated successfully.")
                st.markdown(report)

                st.download_button(
                    label="Download Incident Report",
                    data=report,
                    file_name="ai_incident_report.txt",
                    mime="text/plain",
                )

            except Exception as e:
                st.error(
                    "AI report generation failed. This may be due to API limits, model availability, or large input size."
                )
                st.write(str(e))

else:
    st.info("Upload any CSV file to begin investigation.")